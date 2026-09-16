"""No-auth Google TLS positive control and OS egress denial checks."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import argparse
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.storage_guard import namespace, seal, STORAGE_CHECK
from harness.resource_guard import limited_execute, command_for, bus_prefix
from harness.network_guard import guarded_command, DEPS
from backend.app.runners.process import RunnerError

PAYLOAD = r'''
import concurrent.futures, json, socket, ssl, subprocess, os, sys
checks = {}
first, second, blocked = sys.argv[1:]
ip = socket.gethostbyname(first)
for label, host in [('primary_tls_verified', first), ('secondary_tls_verified', second)]:
    with socket.create_connection((host,443),timeout=5) as conn:
        with ssl.create_default_context().wrap_socket(conn,server_hostname=host) as tls:
            checks[label] = tls.version() is not None
try:
    socket.gethostbyname(blocked)
    checks['unapproved_service_hostname_denied'] = False
except OSError:
    checks['unapproved_service_hostname_denied'] = True
# Private loopback remains available for CLI <-> language server IPC.
with socket.socket() as listener:
    listener.bind(('127.0.0.1',0)); listener.listen()
    with socket.create_connection(listener.getsockname(),timeout=1):
        checks['private_loopback_works'] = True
def denied(pair):
    name, addr = pair
    try:
        with socket.create_connection(addr, timeout=1): return name, False
    except OSError: return name, True
targets = [('other_public_ip_denied',('1.1.1.1',443)),
           ('google_http_denied',(ip,80)), ('google_other_port_denied',(ip,8443)),
           ('host_gateway_denied',('10.0.2.2',5173)),
           ('lan_denied',('192.168.1.1',443)), ('metadata_denied',('169.254.169.254',80)),
           ('ipv6_denied',('2606:4700:4700::1111',443))]
with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
    checks.update(pool.map(denied,targets))
for name, addr in [('dns_udp_denied',('10.0.2.3',53)),('google_quic_denied',(ip,443))]:
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(0.5)
        try:
            udp.sendto(b'UNION_NETWORK_CANARY',addr)
            udp.recv(1); checks[name]=False
        except OSError: checks[name]=True
try:
    socket.gethostbyname('example.com')
    checks['unlisted_hostname_denied']=False
except OSError: checks['unlisted_hostname_denied']=True
tamper = subprocess.run(['/network/nft','flush','ruleset'],
    env={'LD_LIBRARY_PATH':'/network/lib','PATH':'/usr/bin:/bin'},capture_output=True,timeout=3)
checks['firewall_tamper_denied'] = tamper.returncode != 0 and b'Operation not permitted' in tamper.stderr
checks['tamper_did_not_open_egress'] = denied(('check',('1.1.1.1',443)))[1]
try:
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW):
        checks['raw_packet_bypass_denied'] = False
except PermissionError: checks['raw_packet_bypass_denied'] = True
route = subprocess.run(['/usr/sbin/ip','route','add','1.1.1.1/32','via','10.0.2.2'],
                       capture_output=True,timeout=2)
checks['route_tamper_denied'] = route.returncode != 0 and b'Operation not permitted' in route.stderr
checks['host_network_namespace_unreachable'] = not os.path.exists('/run/netns')
print(json.dumps(checks))
'''


async def probe(provider='agy'):
    with tempfile.TemporaryDirectory(prefix='union-network-') as tmp:
        root = Path(tmp)
        for name in ('home', 'work', 'etc/ssl/certs'):
            (root / name).mkdir(parents=True)
        (root / 'etc/hosts').write_text('127.0.0.1 localhost\n')
        (root / 'etc/nsswitch.conf').write_text('hosts: files\n')
        command = namespace(root, os.environ['HOME'])
        command += ['--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
                    '--ro-bind', str(DEPS / 'usr/sbin/nft'), '/network/nft',
                    '--ro-bind', str(DEPS / 'usr/lib/x86_64-linux-gnu'), '/network/lib']
        destinations = (['chatgpt.com', 'auth.openai.com', 'api.openai.com'] if provider == 'codex'
                        else ['oauth2.googleapis.com', 'daily-cloudcode-pa.googleapis.com', 'play.googleapis.com'])
        command += seal() + ['/usr/bin/python3', '-I', '-c', STORAGE_CHECK + PAYLOAD, *destinations]
        raw = await limited_execute(guarded_command(command, root, provider=provider), '', timeout=35, limit=16384)
        checks = json.loads(raw)
        boundary = json.loads((root / 'network-boundary.json').read_text())
        checks['kernel_counted_drops'] = boundary['dropped_packets']['output'] >= 8
        return {'scope': 'No-auth provider TLS and private network firewall', 'provider': provider,
                'credential_mounts': 0, 'model_calls': 0, 'http_requests': 0,
                'checks': checks, 'boundary': boundary,
                'status': 'PASS' if checks and all(v is True for v in checks.values()) else 'BLOCKED'}


async def transport_probe():
    """Synthetic stdin/stderr through the exact network launch chain; no auth."""
    from backend.app.runners.codex import classify_failure
    with tempfile.TemporaryDirectory(prefix='union-network-transport-') as tmp:
        root = Path(tmp)
        for name in ('home', 'work', 'etc'):
            (root / name).mkdir()
        (root / 'etc/hosts').touch()
        payload = ("import sys; data=sys.stdin.read(); "
                   "sys.stderr.write('401 Unauthorized SYNTHETIC' if data=='UNION_STDIN_CANARY' else 'wrong input'); "
                   "sys.exit(1)")
        command = namespace(root, os.environ['HOME']) + seal() + ['/usr/bin/python3', '-I', '-c', payload]
        code = None
        try:
            await limited_execute(guarded_command(command, root, provider='codex'), 'UNION_STDIN_CANARY',
                                  timeout=15, limit=8192, classify_failure=classify_failure)
        except RunnerError as exc:
            code = exc.code
        return {'scope': 'Synthetic network transport; no authentication or model',
                'model_calls': 0, 'credential_mounts': 0,
                'stdin_and_stderr_reached_bounded_caller': code == 'auth_required',
                'observed_error_code': code,
                'status': 'PASS' if code == 'auth_required' else 'BLOCKED'}


async def cleanup_probe():
    """Stop only this owned cgroup after the sandbox and a descendant are ready."""
    unit = 'union-probe-' + uuid.uuid4().hex + '.service'
    process = None
    group = None
    ready = False
    with tempfile.TemporaryDirectory(prefix='union-network-stop-') as tmp:
        root = Path(tmp)
        for name in ('home', 'work', 'etc'):
            (root / name).mkdir()
        (root / 'etc/hosts').touch()
        payload = "import subprocess,time; subprocess.Popen(['/usr/bin/sleep','40']); print('READY',flush=True); time.sleep(40)"
        command = namespace(root, os.environ['HOME']) + seal() + ['/usr/bin/python3', '-I', '-c', STORAGE_CHECK + payload]
        try:
            process = await asyncio.create_subprocess_exec(*command_for(unit, guarded_command(command, root)),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            ready = await asyncio.wait_for(process.stdout.readline(), 15) == b'READY\n'
            observed = subprocess.run([*bus_prefix(), '/usr/bin/systemctl', '--user', 'show',
                unit, '--property=ControlGroup', '--value'], capture_output=True, check=True, timeout=3)
            relative = observed.stdout.decode().strip()
            if relative.startswith('/user.slice/') and unit in relative and '..' not in relative:
                group = Path('/sys/fs/cgroup') / relative.lstrip('/')
        finally:
            subprocess.run([*bus_prefix(), '/usr/bin/systemctl', '--user', '--no-ask-password', 'stop', unit],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
            if process is not None:
                await asyncio.wait_for(process.wait(), 5)
        cleared = group is not None and (not (group / 'cgroup.procs').exists() or not (group / 'cgroup.procs').read_text().strip())
        return {'scope': 'Owned network cgroup cancellation with running descendant',
                'sandbox_ready_before_stop': ready, 'owned_cgroup_empty_or_removed': cleared,
                'model_calls': 0, 'credential_mounts': 0,
                'status': 'PASS' if ready and cleared else 'BLOCKED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cleanup', action='store_true')
    parser.add_argument('--provider', choices=['agy', 'codex'], default='agy')
    parser.add_argument('--transport', action='store_true')
    args = parser.parse_args()
    try:
        result = asyncio.run(transport_probe() if args.transport else cleanup_probe() if args.cleanup else probe(args.provider))
    except (OSError, ValueError, RunnerError, TimeoutError, subprocess.SubprocessError):
        result = {'status': 'BLOCKED', 'error': 'network_probe_failed', 'model_calls': 0}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result.get('status') == 'PASS' else 2)

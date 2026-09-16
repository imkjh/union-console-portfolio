"""Private rootless netns lifecycle; run beneath resource_guard, not directly."""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness.network_guard import (DEPS, WORKER, dependencies_verified, resolve_hosts,
                                   rules_for, public_ipv4, hosts_for)

ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'LD_LIBRARY_PATH': str(DEPS / 'usr/lib/x86_64-linux-gnu')}


def wait_byte(fd, expected):
    if not select.select([fd], [], [], 5)[0] or os.read(fd, 1) != expected:
        raise ValueError('network_setup_handshake_failed')


def stop(process):
    if process is not None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait(timeout=1)


def child(args, provider='agy'):
    hosts_for(provider)
    host_net, ready, proceed, destinations, report_path = args[:5]
    command = args[6:]
    if (os.readlink('/proc/self/ns/net') == host_net or args[5] != '--'
            or not command or command[0] != '/usr/bin/bwrap'
            or '--unshare-all' not in command or '--share-net' in command
            or '--netns' in command):
        raise ValueError('private_network_required')
    rules = rules_for(json.loads(destinations))
    # No flush: this newly-created netns has its own table. Rules precede TAP
    # connectivity and the payload. The payload's nested userns cannot edit them.
    subprocess.run([str(DEPS / 'usr/sbin/nft'), '-f', '-'], input=rules.encode(),
                   env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=4, check=True)
    os.write(int(ready), b'F')
    os.close(int(ready))
    wait_byte(int(proceed), b'G')
    os.close(int(proceed))
    # Here --share-net refers only to the filtered private parent, not host net.
    command.insert(command.index('--unshare-all') + 1, '--share-net')
    result = subprocess.run(command, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                            timeout=80)
    observed = subprocess.run([str(DEPS / 'usr/sbin/nft'), '-j', 'list', 'table', 'inet',
                               'union_egress'], env=ENV, capture_output=True, timeout=3, check=True)
    entries = json.loads(observed.stdout)['nftables']
    counts = {chain: sum(expr['counter']['packets'] for entry in entries
                        if entry.get('rule', {}).get('chain') == chain
                        for expr in entry['rule']['expr'] if 'counter' in expr)
              for chain in ('input', 'output')}
    Path(report_path).write_text(json.dumps({'private_namespace': True,
        'policy': ('google-profile-review' if provider == 'agy-profile-review' else
                   'google' if provider == 'agy' else 'codex') + '-public-ipv4-tcp443',
        'dropped_packets': counts}))
    return result.returncode


def parent(args, provider='agy'):
    fixture, host_net = Path(args[0]), args[1]
    command = args[3:]
    if args[2] != '--' or not dependencies_verified():
        raise ValueError('network_preflight_failed')
    mapping = resolve_hosts(provider)
    addresses = public_ipv4(sorted({ip for ips in mapping.values() for ip in ips}))
    (fixture / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n' +
        ''.join(f'{ip} {name}\n' for name, ips in mapping.items() for ip in ips))
    (fixture / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
    # An empty resolver file also makes native resolvers fail closed, without
    # exposing the host's DNS service or using slirp's DNS forwarder.
    (fixture / 'etc/resolv.conf').write_text('')
    ready_r, ready_w = os.pipe()
    proceed_r, proceed_w = os.pipe()
    slirp_r, slirp_w = os.pipe()
    process = slirp = None
    try:
        process = subprocess.Popen(['/usr/bin/unshare', '--user', '--map-root-user', '--net',
            '/usr/bin/python3', '-I', str(WORKER), '--provider', provider, '--child', host_net,
            str(ready_w), str(proceed_r), json.dumps(addresses),
            str(fixture / 'network-boundary.json'), '--', *command],
            # Inherit the outer limited_execute stderr pipe. Discarding here
            # erased native CLI errors before safe classification could run.
            env=ENV, pass_fds=(ready_w, proceed_r))
        os.close(ready_w); ready_w = -1
        os.close(proceed_r); proceed_r = -1
        wait_byte(ready_r, b'F')
        slirp = subprocess.Popen([str(DEPS / 'usr/bin/slirp4netns'), '--configure',
            '--disable-host-loopback', '--disable-dns', '--enable-sandbox', '--enable-seccomp',
            '--ready-fd=' + str(slirp_w), str(process.pid), 'tap0'], env=ENV,
            pass_fds=(slirp_w,), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(slirp_w); slirp_w = -1
        wait_byte(slirp_r, b'1')
        os.write(proceed_w, b'G')
        while process.poll() is None:
            if slirp.poll() is not None:
                raise ValueError('network_transport_stopped')
            time.sleep(0.05)
        return process.returncode
    finally:
        stop(process)
        stop(slirp)
        for fd in (ready_r, ready_w, proceed_r, proceed_w, slirp_r, slirp_w):
            if fd >= 0:
                os.close(fd)


if __name__ == '__main__':
    try:
        args, provider = sys.argv[1:], 'agy'
        if args[:1] == ['--provider']:
            provider, args = args[1], args[2:]
        hosts_for(provider)
        result = child(args[1:], provider) if args[:1] == ['--child'] else parent(args, provider)
    except (OSError, ValueError, subprocess.SubprocessError):
        # Setup contains no credentials; still never echo paths or raw stderr.
        print(json.dumps({'error': 'network_guard_failed', 'model_calls': 0}))
        result = 2
    raise SystemExit(result)

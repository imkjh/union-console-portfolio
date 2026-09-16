"""Test the installed Codex tool dispatcher against a fully offline fixture.

No credentials, external API endpoints, API keys, or live model calls are used.
The positive control reads only a newly created fake canary. Not live approval.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import base64
import subprocess
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.offline_cli_probe import CODEX, CHECK, namespace
from backend.app.runners.process import execute, RunnerError
from harness import storage_guard


async def probe(*, synthetic_oauth=False, smoke=False, bounded_runtime=False):
    report = {'scope': 'Installed CLI dispatcher + synthetic offline server, not live provider PASS',
              'real_model_calls': 0, 'existing_credentials_mounted': False, 'live_ready': False}
    report['synthetic_oauth'] = synthetic_oauth
    report['smoke_only'] = smoke
    report['bounded_runtime'] = bounded_runtime
    host_home = os.environ.get('HOME', '')
    if not host_home.startswith('/home/') or not CODEX.is_file():
        return {**report, 'error': 'unsupported_environment'}
    with tempfile.TemporaryDirectory(prefix='union-protocol-') as temp:
        root = Path(temp)
        for folder in ('home', 'work', 'etc'):
            (root / folder).mkdir()
        (root / 'home/union-fake-home').write_text('FAKE')
        outside = root / 'outside-canary'
        outside.write_text('FAKE')
        (root / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
        (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
        (root / 'etc/passwd').write_text(f'union-probe:x:{os.getuid()}:{os.getgid()}:Offline probe:{host_home}:/bin/bash\n')
        (root / 'etc/group').write_text(f'union-probe:x:{os.getgid()}:\n')
        base = (storage_guard.namespace(root, host_home, sandbox_uid_maps=True)
                if bounded_runtime else namespace(root, host_home))
        base_length = len(base)
        try:
            check = (storage_guard.storage_check(sandbox_uid_maps=True) if bounded_runtime else '') + CHECK
            sealing = storage_guard.seal(sandbox_uid_maps=True) if bounded_runtime else []
            raw = await execute(base + sealing + ['/usr/bin/python3', '-I', '-c', check,
                                        str(outside), os.readlink('/proc/self/ns/net'), host_home],
                                '', '/tmp', timeout=10, limit=32768)
            checks = json.loads(raw)
            expected = {'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
                        'host_preview_unreachable', 'windows_mount_hidden'}
            if not isinstance(checks, dict) or set(checks) != expected or any(v is not True for v in checks.values()):
                return {**report, 'error': 'namespace_checks_failed'}
            report['isolation'] = checks
            (root / 'work/namespace-verified').touch()
            (root / 'empty-init.py').touch()
            if synthetic_oauth:
                (root / 'etc/ssl/certs').mkdir(parents=True)
                now = datetime.now(timezone.utc)
                def segment(value):
                    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()
                # Entirely fabricated OAuth-shaped data. Never a real login/key.
                identity = segment({'alg': 'RS256', 'typ': 'JWT'}) + '.' + segment({
                    'sub': 'union-offline-fixture', 'exp': int((now + timedelta(hours=1)).timestamp()),
                    'email': 'offline@invalid.test',
                    'https://api.openai.com/auth': {'chatgpt_account_id': 'union-fake-account',
                                                   'chatgpt_plan_type': 'plus'},
                }) + '.' + base64.urlsafe_b64encode(b'UNION_FAKE_SIGNATURE').rstrip(b'=').decode()
                (root / 'fake-oauth.json').write_text(json.dumps({
                    'auth_mode': 'chatgpt', 'tokens': {'id_token': identity,
                    'access_token': 'UNION_FAKE_ACCESS', 'refresh_token': 'UNION_FAKE_REFRESH',
                    'account_id': 'union-fake-account'}, 'last_refresh': now.isoformat(),
                }))
                # A disposable fixture CA, trusted only by this isolated child.
                work = root / 'work'
                (work / 'leaf.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
                certificate_commands = [
                    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'fixture-ca-key.pem',
                     '-out', 'fixture-ca.pem', '-days', '1', '-subj', '/CN=Union offline CA',
                     '-addext', 'basicConstraints=critical,CA:TRUE'],
                    ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'fixture-key.pem',
                     '-out', 'fixture.csr', '-subj', '/CN=union-offline.test'],
                    ['x509', '-req', '-in', 'fixture.csr', '-CA', 'fixture-ca.pem', '-CAkey', 'fixture-ca-key.pem',
                     '-CAcreateserial', '-out', 'fixture-cert.pem', '-days', '1', '-extfile', 'leaf.ext'],
                ]
                for command in certificate_commands:
                    subprocess.run(['/usr/bin/openssl', *command], cwd=work,
                                   check=True, capture_output=True, timeout=10)
                auth_home = storage_guard.RUNTIME_HOME if bounded_runtime else host_home
                base += ['--ro-bind', str(root / 'fake-oauth.json'), auth_home + '/.codex/auth.json',
                         '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
                         '--setenv', 'UNION_PROBE_SYNTHETIC_OAUTH', '1']
            if smoke:
                base += ['--setenv', 'UNION_PROBE_SMOKE', '1']
            if bounded_runtime:
                # Include synthetic files created after the initial isolation check.
                base = storage_guard.namespace(root, host_home, sandbox_uid_maps=True) + base[base_length:]
            args = base + ['--ro-bind', str(CODEX), '/cli/codex',
                           '--ro-bind', str(ROOT / 'harness/codex_policy.py'), '/probe/codex_policy.py',
                           '--ro-bind', str(ROOT / 'harness/codex_protocol_worker.py'), '/probe/worker.py',
                           '--ro-bind', str(root / 'empty-init.py'), '/probe/runner/__init__.py',
                           '--ro-bind', str(ROOT / 'backend/app/runners/process.py'), '/probe/runner/process.py',
                           '--ro-bind', str(ROOT / 'backend/app/runners/parsers.py'), '/probe/runner/parsers.py',
                           *sealing, '/usr/bin/python3', '/probe/worker.py']
            raw = await execute(args, '', '/tmp', timeout=90, limit=131072)
            result = json.loads(raw)
            if result.get('error'):
                return {**report, 'error': result['error'], 'auth_fixture': result.get('auth_fixture')}
            if not isinstance(result.get('cases'), list) or len(result['cases']) != (1 if smoke else 31):
                return {**report, 'error': 'invalid_worker_report'}
            report['cases'] = result['cases']
            report['auth_fixture'] = result['auth_fixture']
            residue = result.get('synthetic_residue')
            if (not isinstance(residue, dict) or residue.get('status') not in {'PASS', 'BLOCKED'}
                    or not isinstance(residue.get('matches'), list)
                    or not isinstance(residue.get('incomplete'), list)):
                return {**report, 'error': 'invalid_residue_report'}
            report['synthetic_residue'] = residue
        except (RunnerError, OSError, ValueError, subprocess.SubprocessError) as exc:
            report['error'] = exc.code if isinstance(exc, RunnerError) else 'probe_failed'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional new sanitized evidence path')
    parser.add_argument('--synthetic-oauth', action='store_true', help='Use fabricated OAuth data inside the offline fixture only')
    parser.add_argument('--smoke', action='store_true', help='Only the root-deny text response; not the security suite')
    parser.add_argument('--bounded-runtime', action='store_true', help='Use candidate volatile storage and protected private procfs')
    args = parser.parse_args()
    report = asyncio.run(probe(synthetic_oauth=args.synthetic_oauth, smoke=args.smoke, bounded_runtime=args.bounded_runtime))
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        with args.output.open('x') as target:
            target.write(serialized)
    print(serialized, end='')
    return 2 if (report.get('error') or report.get('synthetic_residue', {}).get('status') != 'PASS'
                 or (args.synthetic_oauth and not report.get('auth_fixture', {}).get('untrusted_tls_rejected_before_http'))
                 or any(c['status'] != 'PASS' for c in report.get('cases', []))) else 0


if __name__ == '__main__':
    raise SystemExit(main())

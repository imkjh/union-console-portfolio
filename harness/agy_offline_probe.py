"""Installed agy against a synthetic OAuth fixture; no external connectivity.

This never mounts existing credentials or forwards requests to a real service.
No API key is used. A fixture CA is trusted only inside the disposable child.
Startup evidence alone never establishes tool permission enforcement.
"""
import argparse
import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.agy_cache_probe import TESTED_SHA256
from harness.agy_policy import candidate_settings
from harness.offline_cli_probe import AGY, AGENT, CHECK
from harness.storage_guard import namespace, seal, STORAGE_CHECK
from harness.resource_guard import limited_execute
from backend.app.runners.process import RunnerError

HOSTS = ('accounts.google.com', 'oauth2.googleapis.com', 'www.googleapis.com',
         'antigravity.google', 'daily-cloudcode-pa.googleapis.com',
         'lh3.googleusercontent.com', 'play.googleapis.com')
DIAGNOSTIC = {}


def classify(stdout, stderr):
    DIAGNOSTIC['terms'] = sorted(set(re.findall(r'[a-z]+', (stdout + stderr).decode(errors='replace').lower())) & {
        'denied', 'permission', 'missing', 'mount', 'directory', 'file', 'socket', 'address',
        'space', 'memory', 'readonly', 'argument', 'invalid', 'syntaxerror', 'importerror',
        'traceback', 'exist', 'symbolic', 'link', 'bind', 'bwrap', 'systemd', 'failed'})
    for marker, code in ((b'ModuleNotFoundError', 'fixture_import_failed'),
                         (b'PermissionError', 'fixture_permission_denied'),
                         (b'FileNotFoundError', 'fixture_file_missing'),
                         (b'SSLError', 'fixture_tls_failed'),
                         (b'Address already in use', 'fixture_bind_failed'),
                         (b'bwrap:', 'fixture_mount_failed'),
                         (b'resource_limits_unconfirmed', 'fixture_resources_failed')):
        if marker in stdout + stderr:
            DIAGNOSTIC['category'] = code
            return 'cli_failed'
    DIAGNOSTIC['category'] = 'fixture_worker_failed'
    return 'cli_failed'


async def probe(*, dispatch=False):
    DIAGNOSTIC.clear()
    with AGY.open('rb') as binary:
        if hashlib.file_digest(binary, 'sha256').hexdigest() != TESTED_SHA256:
            return {'error': 'installation_changed'}
    with tempfile.TemporaryDirectory(prefix='union-agy-offline-') as temporary:
        root = Path(temporary)
        for folder in ('home/.gemini/antigravity-cli', 'home/.gemini/config/agents/union-settings', 'work', 'etc'):
            (root / folder).mkdir(parents=True)
        (root / 'home/union-fake-home').write_text('FAKE')
        (root / 'outside').write_text('FAKE')
        (root / 'etc/hosts').write_text('127.0.0.1 localhost ' + ' '.join(HOSTS) + '\n')
        (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
        (root / 'etc/resolv.conf').write_text('')
        home = '/home/union'
        (root / 'etc/passwd').write_text(f'union:x:{os.getuid()}:{os.getgid()}:Union:{home}:/bin/bash\n')
        (root / 'etc/group').write_text(f'union:x:{os.getgid()}:\n')
        settings = root / 'home/.gemini/antigravity-cli/settings.json'
        settings.write_text(json.dumps(candidate_settings()))
        (root / 'home/.gemini/config/agents/union-settings/agent.md').write_text(
            AGENT.replace('union-offline', 'union-settings').replace('tools: []', 'tools: [ask_permission]'))
        # Invented fixture values only; never populated from any actual login.
        fake = {'auth_method': 'consumer', 'token': {
            'access_token': 'UNION_FAKE_ACCESS', 'refresh_token': 'UNION_FAKE_REFRESH',
            'token_type': 'Bearer', 'expiry': '2099-01-01T00:00:00Z'}}
        cache = root / 'home/.gemini/antigravity-cli/antigravity-oauth-token'
        cache.write_text(json.dumps(fake))
        cache.chmod(0o600)
        work = root / 'work'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(work / 'fixture-key.pem'), '-out', str(work / 'fixture-cert.pem'),
                        '-days', '1', '-subj', '/CN=Union synthetic offline fixture',
                        '-addext', 'subjectAltName=' + ','.join('DNS:' + host for host in HOSTS)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        checks = json.loads(await limited_execute(namespace(root, home) + seal() + [
            '/usr/bin/python3', '-I', '-c', STORAGE_CHECK + CHECK,
            str(root / 'outside'), os.readlink('/proc/self/ns/net'), home], '', timeout=10, classify_failure=classify))
        expected = {'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
                    'host_preview_unreachable', 'windows_mount_hidden'}
        if set(checks) != expected or not all(v is True for v in checks.values()):
            return {'error': 'isolation_failed'}
        (work / 'namespace-verified').touch()
        cmd = namespace(root, home) + ['--ro-bind', str(AGY), '/cli/agy',
            '--ro-bind', str(ROOT / 'harness/agy_offline_worker.py'), '/probe/worker.py',
            '--ro-bind', str(ROOT / 'harness/agy_bootstrap_worker.py'), '/probe/agy_bootstrap_worker.py'] + seal() + [
            '/usr/bin/python3', '/probe/worker.py'] + (['--dispatch'] if dispatch else [])
        raw = await limited_execute(cmd, '', timeout=18, limit=32768, classify_failure=classify)
        reports = [json.loads(line) for line in raw.splitlines()]
        return {'scope': 'Offline synthetic OAuth fixture, not live tool proof',
                'existing_credentials_mounted': False, 'external_network': False,
                'mode': 'dispatch_attempt' if dispatch else 'startup_only',
                'isolation': checks, 'reports': reports, 'security_gate': 'BLOCKED'}


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--dispatch', action='store_true')
    options = parser.parse_args(args)
    if not options.execute:
        print(json.dumps({'execution': False, 'scope': 'offline_synthetic_only',
            'existing_credentials_mounted': False, 'external_network': False,
            'real_model_calls': 0, 'security_gate': 'BLOCKED'}))
        return 0
    try:
        result = asyncio.run(probe(dispatch=options.dispatch))
    except RunnerError as exc:
        result = {'error': 'offline_fixture_failed', 'code': exc.code, 'diagnostic': DIAGNOSTIC, 'real_model_calls': 0}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {'error': 'offline_fixture_failed', 'type': type(exc).__name__, 'real_model_calls': 0}
    print(json.dumps(result, indent=2))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

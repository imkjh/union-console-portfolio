"""Observe offline agy startup metadata; never submit a model question."""
import argparse
import re
import asyncio
import ctypes
import json
import os
import stat
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.offline_cli_probe import AGY, AGENT, CHECK
from harness.storage_guard import namespace, seal, RUNTIME_HOME, STORAGE_BYTES, STORAGE_CHECK
from harness.resource_guard import limited_execute
from harness.agy_policy import candidate_settings, validated_settings
from harness.network_guard import guarded_command, AGY_HOSTS, AGY_PROFILE_HOSTS
from backend.app.runners.process import RunnerError


def cache_binding(cache, *, writable=False):
    """Mount one regular file, never its parent directory or a credential copy."""
    cache = Path(cache)
    if type(writable) is not bool or any(p.is_symlink() for p in (cache, *cache.parents)):
        raise ValueError('invalid_cache_binding')
    info = cache.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('invalid_cache_binding')
    if writable and (info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077
                     or not 0 < info.st_size <= 262144):
        raise ValueError('unsafe_writable_cache')
    return ['--bind' if writable else '--ro-bind', str(cache),
            RUNTIME_HOME + '/.gemini/antigravity-cli/antigravity-oauth-token']


async def probe(*, inspect_help=False, inspect_bootstrap=False, fake_login=None, existing_cache=None, native_network=False, allow_cache_write=False, allow_profile_host=False):
    if type(allow_profile_host) is not bool or (allow_profile_host and not native_network):
        raise ValueError('profile_host_requires_native_review')
    if type(native_network) is not bool or (native_network and
            (not inspect_bootstrap or inspect_help or fake_login or existing_cache is None)):
        raise ValueError('unsupported_network_probe')
    if type(allow_cache_write) is not bool or (allow_cache_write and not native_network):
        raise ValueError('cache_write_requires_native_review')
    report = {'scope': 'agy startup discovery; not permission enforcement',
              'real_model_calls': 0, 'external_network': native_network, 'live_ready': False,
              'volatile_storage_limit_bytes': STORAGE_BYTES,
              'existing_credentials_mounted': False, 'cases': []}
    home = os.environ.get('HOME', '')
    if not home.startswith('/home/') or not AGY.is_file():
        return {**report, 'error': 'unsupported_environment'}
    with tempfile.TemporaryDirectory(prefix='union-agy-settings-') as tmp:
        root = Path(tmp)
        for folder in ('home', 'work', 'etc'):
            (root / folder).mkdir()
        (root / 'home/union-fake-home').write_text('FAKE')
        (root / 'outside').write_text('FAKE')
        (root / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
        (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
        if native_network:
            (root / 'etc/ssl/certs').mkdir(parents=True)
            (root / 'etc/resolv.conf').touch()
        (root / 'etc/passwd').write_text(f'union:x:{os.getuid()}:{os.getgid()}:Union:{home}:/bin/bash\n')
        (root / 'etc/group').write_text(f'union:x:{os.getgid()}:\n')
        base = namespace(root, home)
        checks = json.loads(await limited_execute(base + seal() + ['/usr/bin/python3', '-I', '-c', STORAGE_CHECK + CHECK,
                                    str(root / 'outside'), os.readlink('/proc/self/ns/net'), home], '', timeout=10))
        expected = {'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
                    'host_preview_unreachable', 'windows_mount_hidden'}
        if set(checks) != expected or any(v is not True for v in checks.values()):
            return {**report, 'error': 'isolation_failed'}
        report['isolation'] = checks
        if inspect_help:
            diagnostic = "import subprocess,json,os; r=subprocess.run(['/cli/agy','--help'],env={'HOME':os.environ['HOME'],'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},capture_output=True,timeout=8); print(json.dumps({'exit_code':r.returncode,'help_lines':[line for line in (r.stdout+r.stderr).decode(errors='replace').splitlines() if line.strip()]}))"
            raw = await limited_execute(base + ['--ro-bind', str(AGY), '/cli/agy'] + seal() +
                                        ['/usr/bin/python3', '-I', '-c', diagnostic], '', timeout=15, limit=32768)
            help_data = json.loads(raw)
            lines = help_data['help_lines']
            report['help'] = {'exit_code': help_data['exit_code'],
                              'flags': sorted(set(re.findall(r'--[a-z][a-z-]*', '\n'.join(lines)))),
                              'scope': 'Advertised flags only; no security enforcement proof'}
            return report
        settings = root / 'home/.gemini/antigravity-cli/settings.json'
        settings.parent.mkdir(parents=True)
        definition = root / 'home/.gemini/config/agents/union-settings/agent.md'
        definition.parent.mkdir(parents=True)
        # An empty tools list did not narrow the installed primary-agent registry.
        # Use one already-observed permission prompt tool as a bounded candidate.
        # This remains startup-only: no user prompt or provider registration.
        definition.write_text(AGENT.replace('union-offline', 'union-settings')
                             .replace('tools: []', 'tools: [ask_permission]'))
        report['candidate_agent_tools'] = ['ask_permission']
        safe_settings = validated_settings(json.dumps(candidate_settings()))
        if inspect_bootstrap:
            settings.write_text(safe_settings)
            base = namespace(root, home)
            if existing_cache is not None:
                expected_cache = Path(home) / '.gemini/antigravity-cli/antigravity-oauth-token'
                if fake_login or existing_cache != expected_cache or existing_cache.is_symlink() or not existing_cache.is_file():
                    raise ValueError('invalid_existing_cache')
                if '--unshare-all' not in base or '--share-net' in base:
                    raise ValueError('offline_required')
                base += cache_binding(existing_cache, writable=allow_cache_write)
                report['existing_credentials_mounted'] = True
                report['credential_access'] = 'Official CLI only, one read-only file, offline namespace'
                if native_network:
                    base += ['--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs']
                    report['credential_access'] = ('Official CLI only, one writable file, filtered native HTTPS' if allow_cache_write
                                                   else 'Official CLI only, one read-only file, filtered native HTTPS')
                    report['network_policy'] = {'hosts': list(AGY_PROFILE_HOSTS if allow_profile_host else AGY_HOSTS), 'port': 443,
                                               'public_ipv4_only': True, 'dns_inside_cli': False}
            watch = None
            if fake_login:
                cache = root / 'home/.gemini/antigravity-cli/antigravity-oauth-token'
                if fake_login == 'malformed':
                    cache.write_text('UNION_INVALID_SYNTHETIC_CACHE')
                elif fake_login in {'oauth-shaped', 'oauth-expired'}:
                    cache.write_text(json.dumps({'access_token': 'fake-access', 'refresh_token': 'fake-refresh',
                                                'token_type': 'Bearer',
                                                'expiry': ('2000' if fake_login == 'oauth-expired' else '2099') + '-01-01T00:00:00Z'}))
                else:
                    raise ValueError('unsupported_fixture')
                cache.chmod(0o600)
                libc = ctypes.CDLL(None, use_errno=True)
                watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
                if watch < 0 or libc.inotify_add_watch(watch, os.fsencode(cache), 0x21) < 0:
                    if watch >= 0:
                        os.close(watch)
                    raise OSError('watch_failed')
                base += ['--ro-bind', str(cache), RUNTIME_HOME + '/.gemini/antigravity-cli/antigravity-oauth-token']
                report['fake_cache'] = {'shape': fake_login, 'read_only_mount': True, 'open_or_access': False}
            before = existing_cache.stat() if allow_cache_write else None
            try:
                command = (base + ['--ro-bind', str(AGY), '/cli/agy',
                    '--ro-bind', str(ROOT / 'harness/agy_bootstrap_worker.py'), '/probe/bootstrap.py'] + seal() +
                    ['/usr/bin/python3', '-I', '/probe/bootstrap.py']
                    + (['--native-startup'] if native_network else [])
                    + (['--cache-write'] if allow_cache_write else []))
                if native_network:
                    command = (guarded_command(command, root, provider='agy-profile-review')
                               if allow_profile_host else guarded_command(command, root))
                raw = await limited_execute(command, '', timeout=25 if native_network else 12, limit=32768)
                report['bootstrap'] = json.loads(raw)
                if native_network:
                    report['network_boundary'] = json.loads((root / 'network-boundary.json').read_text())
            finally:
                if before is not None:
                    after = existing_cache.stat()
                    report['cache_update'] = {
                        'metadata_changed': (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size),
                        'same_file': (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                        'private_permissions': after.st_mode & 0o077 == 0,
                        'contents_inspected': False}
                if watch is not None:
                    try:
                        report['fake_cache']['open_or_access'] = bool(os.read(watch, 4096))
                    except BlockingIOError:
                        pass
                    os.close(watch)
            report['security_gate'] = 'BLOCKED'  # No dispatcher/canary proof from startup metadata.
            return report
        libc = ctypes.CDLL(None, use_errno=True)
        for label, body in [('valid_settings', safe_settings), ('malformed_settings', '{invalid')]:
            settings.write_text(body)
            base = namespace(root, home)
            watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            if watch < 0 or libc.inotify_add_watch(watch, os.fsencode(settings), 0x21) < 0:
                if watch >= 0:
                    os.close(watch)
                raise OSError('watch_failed')
            case = {'case': label, 'settings_open_or_access': False, 'policy_enforcement_verified': False}
            try:
                raw = await limited_execute(base + ['--ro-bind', str(AGY), '/cli/agy'] + seal() +
                                            ['/cli/agy', 'agent'], '', timeout=15, limit=32768)
                case['synthetic_agent_found'] = 'union-settings' in raw.decode().splitlines()
                case['cli_exit_zero'] = True
            except RunnerError as exc:
                case.update(cli_exit_zero=False, error=exc.code)
            finally:
                try:
                    case['settings_open_or_access'] = bool(os.read(watch, 4096))
                except BlockingIOError:
                    pass
                os.close(watch)
            report['cases'].append(case)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--inspect-help', action='store_true')
    modes.add_argument('--inspect-bootstrap', action='store_true')
    parser.add_argument('--fake-login', choices=['malformed', 'oauth-shaped', 'oauth-expired'])
    args = parser.parse_args()
    if args.fake_login and not args.inspect_bootstrap:
        parser.error('--fake-login requires --inspect-bootstrap')
    try:
        result = asyncio.run(probe(inspect_help=args.inspect_help, inspect_bootstrap=args.inspect_bootstrap, fake_login=args.fake_login))
    except (OSError, ValueError, RunnerError):
        result = {'scope': 'Synthetic agy settings only', 'error': 'probe_failed', 'real_model_calls': 0}
    print(json.dumps(result, indent=2))
    raise SystemExit(2 if result.get('error') or result.get('security_gate') == 'BLOCKED' else 0)

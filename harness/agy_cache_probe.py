"""Review by default; --execute observes agy startup with one cache (RO by default).

Offline by default. --native-network requires separate OAuth-refresh risk approval.
No questions, keyring/bus exposure, credential inspection/copy, model inference,
user settings, or UI enablement. Native CLI alone reads its cache.
"""
import argparse
import asyncio
import hashlib
import json
import os
import fcntl
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.offline_cli_probe import AGY
from harness.agy_settings_probe import probe, cache_binding
from harness.network_guard import AGY_HOSTS, AGY_PROFILE_HOSTS, dependencies_verified
from backend.app.runners.process import RunnerError

TESTED_SHA256 = 'e8f90ef67943b56c1148d73bc0e102d0b44d18935ffb11d49a2d870a095f416b'
CACHE_RELATIVE = '.gemini/antigravity-cli/antigravity-oauth-token'


def review(*, native_network=False, allow_cache_write=False, allow_profile_host=False):
    if type(allow_profile_host) is not bool or (allow_profile_host and not native_network):
        raise ValueError('profile_host_requires_native_review')
    if type(allow_cache_write) is not bool or (allow_cache_write and not native_network):
        raise ValueError("cache_write_requires_native_review")
    home = Path(os.environ.get('HOME', '/nonexistent'))
    cache = home / CACHE_RELATIVE
    regular = (str(home).startswith('/home/') and cache.is_file()
               and not any(p.is_symlink() for p in (home, home / '.gemini', cache.parent, cache)))
    writable_safe = False
    if allow_cache_write and regular:
        try:
            cache_binding(cache, writable=True)
            writable_safe = True
        except (OSError, ValueError):
            pass
    digest = None
    if AGY.is_file():
        with AGY.open('rb') as binary:
            digest = hashlib.file_digest(binary, 'sha256').hexdigest()
    return {'mode': 'native_auth_review' if native_network else 'offline_cache_review', 'tested_cli_matches': digest == TESTED_SHA256,
            'cache_regular_file': regular, 'credential_contents_inspected': False,
            'question_bytes': 0, 'model_calls': 0, 'external_network': native_network,
            'cache_access': ('One writable file; official CLI only' if allow_cache_write else 'One read-only file; official CLI only'),
            'allow_cache_write': allow_cache_write, 'writable_cache_safe': writable_safe, 'live_ready': False,
            'allow_profile_host': allow_profile_host,
            'browser_preparation': 'Fixed absent driver path under read-only root; checked before CLI launch',
            'requires_separate_network_approval': native_network,
            'network_policy': {'hosts': list(AGY_PROFILE_HOSTS if allow_profile_host else AGY_HOSTS), 'port': 443, 'dns_inside_cli': False,
                               'dependencies_verified': dependencies_verified()} if native_network else None,
            'network_risks': ['Native OAuth refresh; a failed credential save may require login again',
                              'Public IPv4 from exact Google DNS names only, TCP/443; shared IPs are not an HTTP content boundary',
                              'Required but unlisted CLI endpoints fail closed; native compatibility not yet verified'] if native_network else []}


async def run_once(plan, *, native_network=False, allow_cache_write=False, allow_profile_host=False):
    if type(allow_profile_host) is not bool or (allow_profile_host and
            (not native_network or plan.get('allow_profile_host') is not True or
             plan.get('network_policy', {}).get('hosts') != list(AGY_PROFILE_HOSTS))):
        return {'error': 'profile_host_review_required', 'model_calls': 0}
    if type(allow_cache_write) is not bool or (allow_cache_write and
            (not native_network or plan.get("allow_cache_write") is not True or plan.get("writable_cache_safe") is not True)):
        return {"error": "cache_write_review_required", "model_calls": 0}
    if type(native_network) is not bool or (native_network and
            (plan.get('mode') != 'native_auth_review' or plan.get('external_network') is not True)):
        return {'error': 'network_review_required', 'model_calls': 0}
    if plan.get('tested_cli_matches') is not True or plan.get('cache_regular_file') is not True:
        return {'error': 'preflight_blocked', 'model_calls': 0}
    lock = None
    stage = 'preflight'
    try:
        if allow_cache_write:
            # Only this harness shares the lock; a manually started CLI can still race.
            lock_dir = ROOT / '.runs'
            if lock_dir.is_symlink():
                raise ValueError('invalid_lock_directory')
            lock_dir.mkdir(mode=0o700, exist_ok=True)
            fd = os.open(lock_dir / 'agy-refresh.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            lock = os.fdopen(fd, 'w')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stage = 'process_metadata_check'
            if active_agy():
                return {'error': 'agy_already_running', 'model_calls': 0}
        stage = 'cli_probe'
        return await probe(inspect_bootstrap=True, existing_cache=Path(os.environ['HOME']) / CACHE_RELATIVE,
                           native_network=native_network, allow_cache_write=allow_cache_write,
                           **({'allow_profile_host': True} if allow_profile_host else {}))
    except (RunnerError, OSError, ValueError):
        return {'error': 'cache_probe_failed', 'stage': stage, 'model_calls': 0}
    finally:
        if lock is not None:
            lock.close()


def active_agy(proc_root=Path('/proc')):
    # Process executable metadata only; never inspect argv/environment.
    target = AGY.resolve()
    for process in proc_root.iterdir():
        if process.name.isdigit():
            try:
                if process.stat().st_uid == os.getuid():
                    try:
                        executable = os.readlink(process / 'exe')
                    except PermissionError:
                        # Some unrelated desktop processes protect exe metadata.
                        # This is a best-effort concurrency check, not isolation.
                        if (process / 'comm').read_text().strip() == 'agy':
                            return True
                        continue
                    if executable == str(target) or executable == '/cli/agy':
                        return True
            except FileNotFoundError:
                continue
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', help='Run reviewed startup, never submit a question')
    parser.add_argument('--native-network', action='store_true', help='Review native OAuth startup; execution needs separate risk approval')
    parser.add_argument('--allow-cache-write', action='store_true', help='Approved single-file native refresh only; never model questions')
    parser.add_argument('--allow-profile-host', action='store_true', help='Separately approved lh3.googleusercontent.com startup only')
    args = parser.parse_args()
    if args.allow_cache_write and not args.native_network:
        parser.error('--allow-cache-write requires --native-network')
    if args.allow_profile_host and not args.native_network:
        parser.error('--allow-profile-host requires --native-network')
    plan = (review(native_network=True, allow_cache_write=args.allow_cache_write, allow_profile_host=True) if args.allow_profile_host
            else review(native_network=True, allow_cache_write=True) if args.allow_cache_write
            else review(native_network=True) if args.native_network else review())
    result = asyncio.run(run_once(plan, native_network=args.native_network, allow_cache_write=args.allow_cache_write,
                                 **({'allow_profile_host': True} if args.allow_profile_host else {}))) if args.execute else plan
    print(json.dumps(result, indent=2))
    return 2 if result.get('error') or result.get('security_gate') == 'BLOCKED' else 0


if __name__ == '__main__':
    raise SystemExit(main())

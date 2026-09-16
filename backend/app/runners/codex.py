"""Concrete Codex adapter registered only after the fixed installation preflight.

The reviewed CLI probe and production web calls share this fixed runtime.
Existing harness guards remain shared to avoid duplicating security policy.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from harness.offline_cli_probe import CODEX, CHECK
from harness.storage_guard import namespace, seal, RUNTIME_HOME, storage_check
from harness.codex_policy import locked_options
from harness.resource_guard import limited_execute
from harness.network_guard import guarded_command, dependencies_verified
from .process import execute, RunnerError
from .parsers import codex_jsonl

TESTED_SHA256 = '6970ad6a5b7615d2f5838879e19c1369e5527cb1544f1515f76900267740a403'
ISOLATION_CHECK = storage_check(sandbox_uid_maps=True) + CHECK
STATUS_CHECK = '''import json,os,subprocess
r=subprocess.run(['/cli/codex','login','status'],env={'HOME':os.environ['HOME'],'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},capture_output=True,timeout=8)
output=(r.stdout+r.stderr).decode(errors='replace').lower()
print(json.dumps({'chatgpt':r.returncode==0 and 'logged in using chatgpt' in output and 'api key' not in output}))
'''


def classify_failure(stdout, stderr):
    """Fixed error codes only; raw output never leaves this in-memory check."""
    text = (stdout + b'\n' + stderr).decode(errors='replace').lower()
    if any(marker in text for marker in ('401 unauthorized', 'refresh_token_reused',
                                         'refresh_token_expired', 'not logged in', 'authentication required')):
        return 'auth_required'
    if any(marker in text for marker in ('429 too many requests', 'usage_limit_reached', 'rate_limit_exceeded')):
        return 'rate_limited'
    if any(marker in text for marker in ('dns error', 'failed to lookup address', 'name or service not known',
                                         'network is unreachable', 'error sending request for url')):
        return 'network_unavailable'
    return 'cli_failed'


async def in_phase(phase, executor, *args, **kwargs):
    try:
        return await executor(*args, **kwargs)
    except RunnerError as exc:
        exc.stage = phase
        raise


def preflight():
    """Metadata only for credentials; read bytes only from the public executable."""
    home = Path(os.environ.get('HOME', '/nonexistent'))
    auth = home / '.codex/auth.json'
    safe = False
    matches = False
    try:
        info = auth.lstat()
        safe = (home.parts == ('/', 'home', home.name)
                and not any(p.is_symlink() for p in (home, auth.parent, auth))
                and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077 and info.st_nlink == 1
                and 0 < info.st_size <= 262144)
        with CODEX.open('rb') as binary:
            matches = hashlib.file_digest(binary, 'sha256').hexdigest() == TESTED_SHA256
    except OSError:
        pass
    return {'tested_cli_matches': matches, 'auth_cache_regular_file': safe,
            'network_dependencies_verified': dependencies_verified()}


class CodexAdapter:
    async def __call__(self, prompt):
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 4000:
            raise RunnerError('invalid_input')
        try:
            prompt.encode('utf-8')
        except UnicodeError:
            raise RunnerError('invalid_input') from None
        # A total deadline includes isolation, catalog, auth status and inference.
        try:
            async with asyncio.timeout(85):
                return await self._run(prompt)
        except TimeoutError:
            raise RunnerError('timeout') from None
        except (OSError, ValueError):
            raise RunnerError('provider_unavailable') from None

    async def _run(self, prompt):
        checks = await asyncio.to_thread(preflight)
        if not checks or any(value is not True for value in checks.values()):
            raise RunnerError('provider_unavailable')
        home = os.environ['HOME']
        auth = Path(home) / '.codex/auth.json'
        with tempfile.TemporaryDirectory(prefix='union-codex-') as temporary:
            root = Path(temporary)
            for folder in ('home', 'work', 'etc/ssl/certs'):
                (root / folder).mkdir(parents=True)
            (root / 'home/union-fake-home').write_text('FAKE')
            outside = root / 'outside-canary'
            outside.write_text('FAKE')
            (root / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
            (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
            (root / 'etc/passwd').write_text(f'union:x:{os.getuid()}:{os.getgid()}:Union:{home}:/bin/bash\n')
            (root / 'etc/group').write_text(f'union:x:{os.getgid()}:\n')
            base = namespace(root, home, sandbox_uid_maps=True)
            # No auth/network until the namespace and storage contract is checked.
            isolated = json.loads(await in_phase('isolation', execute, base + seal(sandbox_uid_maps=True) + [
                '/usr/bin/python3', '-I', '-c', ISOLATION_CHECK, str(outside),
                os.readlink('/proc/self/ns/net'), home], '', '/tmp', timeout=10, limit=8192))
            expected = {'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
                        'host_preview_unreachable', 'windows_mount_hidden'}
            if not isinstance(isolated, dict) or set(isolated) != expected or any(v is not True for v in isolated.values()):
                raise RunnerError('provider_unavailable')
            base += ['--ro-bind', str(CODEX), '/cli/codex']
            catalog = await in_phase('catalog', limited_execute, base + seal(sandbox_uid_maps=True) + ['/cli/codex', 'debug', 'models', '--bundled'],
                                            '', timeout=10, limit=4194304)
            (root / 'work/catalog.json').write_bytes(catalog)
            base = namespace(root, home, sandbox_uid_maps=True) + ['--ro-bind', str(CODEX), '/cli/codex',
                    '--ro-bind', str(auth), RUNTIME_HOME + '/.codex/auth.json']
            status = json.loads(await in_phase('auth_status', limited_execute, base + seal(sandbox_uid_maps=True) + [
                '/usr/bin/python3', '-I', '-c', STATUS_CHECK], '', timeout=10, limit=8192))
            if not isinstance(status, dict) or status.get('chatgpt') is not True:
                raise RunnerError('auth_required')
            command = base + ['--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs'] + seal(sandbox_uid_maps=True) + [
                '/cli/codex', 'exec', *locked_options(), '-c', 'model_provider="openai"', '-']
            # Only the fixed Codex hosts. Never fall back to host network sharing.
            command = guarded_command(command, root, provider='codex')
            raw = await in_phase('inference', limited_execute, command, prompt, timeout=70, limit=262144,
                                 classify_failure=classify_failure)
            return codex_jsonl(raw)

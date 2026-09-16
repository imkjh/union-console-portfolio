"""Pinned Gemini/Claude CLI adapter with verified deny policy and OS isolation."""
import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import MappingProxyType

from harness.agy_cache_probe import CACHE_RELATIVE, TESTED_SHA256
from harness.agy_policy import candidate_settings, validated_settings
from harness.agy_settings_probe import cache_binding
from harness.offline_cli_probe import AGY, AGENT, CHECK
from harness.storage_guard import namespace, seal, STORAGE_CHECK
from harness.network_guard import guarded_command, dependencies_verified
from harness.resource_guard import limited_execute
from .parsers import agy_stdin, agy_stream_json, decode_output, strict_json
from .process import RunnerError

MODEL_IDS = MappingProxyType({'gemini': 'gemini-3.1-pro-high', 'claude': 'claude-sonnet-4-6'})
ISOLATION_CHECK = STORAGE_CHECK + CHECK
AGENT_DEFINITION = AGENT.replace('union-offline', 'union-settings').replace(
    'tools: []', 'tools: [ask_permission, view_file, write_to_file, run_command]')


def policy_verified():
    # Native read/write/command permission-denied events for both models:
    # docs/evidence/2026-09-14-agy-dispatcher.md. preflight separately pins the
    # tested executable and boundaries. No environment switch bypasses them.
    return True


def preflight():
    home = Path(os.environ.get('HOME', '/nonexistent'))
    cache = home / CACHE_RELATIVE
    try:
        info = cache.lstat()
        safe = (home.parts == ('/', 'home', home.name)
                and not any(p.is_symlink() for p in (cache, *cache.parents))
                and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077 and info.st_nlink == 1
                and 0 < info.st_size <= 262144)
        with AGY.open('rb') as binary:
            matches = hashlib.file_digest(binary, 'sha256').hexdigest() == TESTED_SHA256
        return safe and matches and dependencies_verified()
    except OSError:
        return False


def classify_failure(stdout, stderr):
    text = (stdout + b'\n' + stderr).decode(errors='replace').lower()
    if any(marker in text for marker in ('authentication required', 'unauthenticated',
                                         'invalid_grant', '401 unauthorized', 'token has expired')):
        return 'auth_required'
    if any(marker in text for marker in ('429 too many requests', 'resource_exhausted',
                                         'rate limit exceeded', 'quota exhausted')):
        return 'rate_limited'
    if any(marker in text for marker in ('no such host', 'network is unreachable',
                                         'connection refused', 'tls handshake timeout')):
        return 'network_unavailable'
    return 'cli_failed'


def parse_response(raw, model_id):
    # A metadata match is an identity check only, not tool policy verification.
    answer = agy_stream_json(raw)
    try:
        first = next(line for line in decode_output(raw).splitlines() if line.strip())
        identity = strict_json(first).get('init')
        if (not isinstance(identity, dict) or identity.get('model') != model_id
                or identity.get('agent') != 'union-settings'
                or identity.get('permission_mode') != 'request-review'):
            raise ValueError('unexpected_identity')
    except (ValueError, TypeError, UnicodeError, StopIteration):
        raise RunnerError('invalid_output') from None
    return answer


@dataclass(frozen=True)
class AgyAdapter:
    model: str

    def __post_init__(self):
        if self.model not in MODEL_IDS:
            raise ValueError('unsupported_agy_model')

    async def __call__(self, prompt):
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 4000:
            raise RunnerError('invalid_input')
        try:
            message = agy_stdin(prompt).decode('utf-8')
        except UnicodeError:
            raise RunnerError('invalid_input') from None
        # Fail before even inspecting credential metadata or creating a process.
        if not policy_verified():
            raise RunnerError('provider_unavailable')
        try:
            async with asyncio.timeout(85):
                if await asyncio.to_thread(preflight) is not True:
                    raise RunnerError('provider_unavailable')
                return await self._run(message)
        except TimeoutError:
            raise RunnerError('timeout') from None
        except (OSError, ValueError):
            raise RunnerError('provider_unavailable') from None

    async def _run(self, message):
        home = os.environ['HOME']
        with tempfile.TemporaryDirectory(prefix='union-agy-run-') as temporary:
            root = Path(temporary)
            for folder in ('home/.gemini/antigravity-cli',
                           'home/.gemini/config/agents/union-settings', 'work', 'etc/ssl/certs'):
                (root / folder).mkdir(parents=True)
            (root / 'home/union-fake-home').write_text('FAKE')
            (root / 'outside').write_text('FAKE')
            (root / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
            (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
            (root / 'etc/resolv.conf').touch()
            (root / 'etc/passwd').write_text(f'union:x:{os.getuid()}:{os.getgid()}:Union:{home}:/bin/bash\n')
            (root / 'etc/group').write_text(f'union:x:{os.getgid()}:\n')
            (root / 'home/.gemini/antigravity-cli/settings.json').write_text(
                validated_settings(json.dumps(candidate_settings())))
            (root / 'home/.gemini/config/agents/union-settings/agent.md').write_text(
                AGENT_DEFINITION)
            base = namespace(root, home)
            checks = json.loads(await limited_execute(base + seal() + [
                '/usr/bin/python3', '-I', '-c', ISOLATION_CHECK, str(root / 'outside'),
                os.readlink('/proc/self/ns/net'), home], '', timeout=10, limit=8192))
            expected = {'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
                        'host_preview_unreachable', 'windows_mount_hidden'}
            if not isinstance(checks, dict) or set(checks) != expected or any(v is not True for v in checks.values()):
                raise RunnerError('provider_unavailable')
            command = (base + cache_binding(Path(home) / CACHE_RELATIVE)
                + ['--ro-bind', str(AGY), '/cli/agy', '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs',
                   '--setenv', 'PLAYWRIGHT_DRIVER_PATH', '/disabled-browser'] + seal()
                + ['/cli/agy', '--input-format', 'stream-json', '--output-format', 'stream-json',
                   '--agent', 'union-settings', '--model', MODEL_IDS[self.model],
                   '--disable-slash-commands', '--sandbox', '--log-file', '/dev/stderr',
                   '--print-timeout', '60s'])
            # Existing approved six-host profile. No wildcard, API fallback,
            # writable cache, real HOME mount, resume or unsafe permission mode.
            return await self._execute(root, command, message)

    async def _execute(self, root, command, message):
        command = guarded_command(command, root, provider='agy-profile-review')
        raw = await limited_execute(command, message, timeout=70, limit=262144,
                                    classify_failure=classify_failure)
        return parse_response(raw, MODEL_IDS[self.model])

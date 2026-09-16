"""Capture fixed execution plans; no real credential, CLI or network access."""
import asyncio
import json
from pathlib import Path
import pytest
from backend.app.runners import codex
from backend.app.runners.process import RunnerError


@pytest.mark.parametrize('failure', [None, 'preflight', 'isolation', 'auth', 'network', 'parser', 'cancel'])
async def test_adapter_orders_gates_and_always_cleans_its_fixture(monkeypatch, failure):
    monkeypatch.setenv('HOME', '/home/union')
    monkeypatch.setattr(codex, 'preflight', lambda: {'tested_cli_matches': failure != 'preflight',
        'auth_cache_regular_file': True, 'network_dependencies_verified': True})
    calls, roots = [], set()
    private_prompt = '--help\nSYNTHETIC_PRIVATE_QUESTION'
    def guard(argv, root, *, provider):
        assert provider == 'codex'
        assert '--share-net' not in argv and '/etc/resolv.conf' not in argv
        assert private_prompt not in argv
        if failure == 'network':
            raise ValueError('network_setup_failed')
        return ['FILTERED', *argv]
    async def execute(argv, prompt, *args, **kwargs):
        calls.append((argv, prompt))
        assert '--bind' not in argv and '--share-net' not in argv
        # Google sign-in does not authorize passing Google/agy credentials to
        # this runner. Only its own cache may enter from the real user home.
        sources = [argv[i + 1] for i, value in enumerate(argv) if value == '--ro-bind']
        assert all('.gemini' not in value for value in argv)
        expected_sources = {'/usr', str(codex.CODEX), '/etc/ssl/certs',
                            '/home/union/.codex/auth.json', '/proc/sys',
                            '/proc/sysrq-trigger', '/proc/irq', '/proc/bus'}
        assert all(source in expected_sources or source.startswith('/tmp/union-codex-')
                   for source in sources)
        caches = [source for source in sources if source == '/home/union/.codex/auth.json']
        assert len(caches) == (0 if codex.ISOLATION_CHECK in argv or '--bundled' in argv else 1)
        assert ['--size', '134217728', '--tmpfs', '/runtime'] == argv[argv.index('--size'):argv.index('--size')+4]
        assert '--clearenv' in argv and '--remount-ro' in argv
        for path in ('/proc/sys', '/proc/sysrq-trigger', '/proc/irq', '/proc/bus'):
            assert ['--ro-bind', path, path] in [argv[i:i+3] for i in range(len(argv)-2)]
        for item in argv:
            if item.startswith('/tmp/union-codex-'):
                roots.add(Path('/tmp') / Path(item).parts[2])
        if codex.ISOLATION_CHECK in argv:
            assert not any('.codex/auth.json' in item for item in argv)
            return json.dumps({key: failure != 'isolation' for key in (
                'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
                'host_preview_unreachable', 'windows_mount_hidden')}).encode()
        if '--bundled' in argv:
            assert not any('.codex/auth.json' in item for item in argv)
            return b'{}'
        if codex.STATUS_CHECK in argv:
            assert argv[argv.index('/home/union/.codex/auth.json')-1] == '--ro-bind'
            return json.dumps({'chatgpt': failure != 'auth'}).encode()
        assert argv[0] == 'FILTERED'
        assert prompt == private_prompt and argv[-1] == '-'
        assert '--ignore-user-config' in argv and '--ephemeral' in argv
        assert 'permissions.union_probe={extends=":read-only",filesystem={"/"="deny"}}' in argv
        assert kwargs == {'timeout': 70, 'limit': 262144, 'classify_failure': codex.classify_failure}
        if failure == 'cancel':
            raise asyncio.CancelledError()
        if failure == 'parser':
            return b'{"type":"turn.failed"}'
        return b'{"type":"item.completed","item":{"type":"agent_message","text":"synthetic"}}\n{"type":"turn.completed"}'
    monkeypatch.setattr(codex, 'guarded_command', guard)
    monkeypatch.setattr(codex, 'execute', execute)
    monkeypatch.setattr(codex, 'limited_execute', execute)
    if failure is None:
        assert await codex.CodexAdapter()(private_prompt) == 'synthetic'
    elif failure == 'cancel':
        with pytest.raises(asyncio.CancelledError):
            await codex.CodexAdapter()(private_prompt)
    else:
        with pytest.raises(RunnerError, match={'auth': 'auth_required', 'parser': 'cli_failed'}.get(failure, 'provider_unavailable')):
            await codex.CodexAdapter()(private_prompt)
    assert all(not root.exists() for root in roots)
    assert sum(argv[0] == 'FILTERED' for argv, _ in calls) == int(failure in (None, 'parser', 'cancel'))
    assert sum(bool(prompt) for _, prompt in calls) == int(failure in (None, 'parser', 'cancel'))


@pytest.mark.parametrize('prompt', ['', ' ', 'x'*4001, '\ud800', None])
async def test_invalid_prompt_cannot_reach_preflight(monkeypatch, prompt):
    def forbidden():
        raise AssertionError('no credential metadata or CLI before input validation')
    monkeypatch.setattr(codex, 'preflight', forbidden)
    with pytest.raises(RunnerError, match='invalid_input'):
        await codex.CodexAdapter()(prompt)


@pytest.mark.parametrize('message,expected', [
    ('401 Unauthorized PRIVATE', 'auth_required'),
    ('429 Too Many Requests PRIVATE', 'rate_limited'),
    ('error sending request for url PRIVATE', 'network_unavailable'),
    ('unclassified PRIVATE', 'cli_failed'),
])
def test_failure_classification_never_exports_raw_output(message, expected):
    assert codex.classify_failure(b'', message.encode()) == expected

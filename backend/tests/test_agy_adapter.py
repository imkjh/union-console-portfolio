"""Candidate adapter transport tests; no existing credential or CLI is used."""
import asyncio
import copy
import json
from pathlib import Path

import pytest
from backend.app.runners import agy
from backend.app.runners.process import RunnerError
from backend.app.runners.providers import LiveRunner
from backend.app.service import Store


def response(model, *, conversation='synthetic'):
    return ('\n'.join(json.dumps(event) for event in [
        {'event': 'init', 'conversation_id': conversation, 'init': {
            'model': agy.MODEL_IDS[model], 'agent': 'union-settings', 'permission_mode': 'request-review'}},
        {'event': 'result', 'result': {'conversation_id': conversation, 'status': 'SUCCESS',
            'num_turns': 1, 'response': 'synthetic ' + model}}])).encode()


@pytest.mark.parametrize('model', ['gemini', 'claude'])
async def test_unverified_policy_blocks_before_any_credential_or_process(monkeypatch, model):
    def forbidden(*args, **kwargs):
        raise AssertionError('must not touch credential or start process')
    monkeypatch.setattr(agy, 'preflight', forbidden)
    monkeypatch.setattr(agy, 'limited_execute', forbidden)
    monkeypatch.setattr(agy, 'policy_verified', lambda: False)
    monkeypatch.setenv('UNION_AGY_ENABLED', 'true')
    monkeypatch.setenv('UNION_LIVE_READY', 'true')
    with pytest.raises(RunnerError, match='provider_unavailable'):
        await agy.AgyAdapter(model)('hello')


@pytest.mark.parametrize('model', ['gpt', '--help', 'gemini;whoami', ''])
def test_unknown_model_rejected(model):
    with pytest.raises(ValueError):
        agy.AgyAdapter(model)


@pytest.mark.parametrize('prompt', ['', ' ', 'x' * 4001, '\ud800', None])
async def test_invalid_input_stops_before_policy_or_preflight(monkeypatch, prompt):
    def forbidden():
        raise AssertionError('invalid input must stop first')
    monkeypatch.setattr(agy, 'policy_verified', forbidden)
    with pytest.raises(RunnerError, match='invalid_input'):
        await agy.AgyAdapter('gemini')(prompt)


def synthetic_runtime(monkeypatch, failure=None):
    monkeypatch.setenv('HOME', '/home/union')
    monkeypatch.setattr(agy, 'policy_verified', lambda: True)
    monkeypatch.setattr(agy, 'preflight', lambda: failure != 'preflight')
    monkeypatch.setattr(agy, 'cache_binding', lambda path: ['--ro-bind', str(path), '/runtime/home/' + agy.CACHE_RELATIVE])
    roots, calls = set(), []

    def guard(argv, root, *, provider):
        assert provider == 'agy-profile-review'
        if failure == 'network':
            raise ValueError('fixture_failure')
        return ['FILTERED', *argv]

    async def execute(argv, message, **kwargs):
        assert '--clearenv' in argv and '--unshare-all' in argv and '--share-net' not in argv
        assert '--bind' not in argv
        # Both agy models share Google auth, never Codex auth or browser cookies.
        sources = [argv[i + 1] for i, value in enumerate(argv) if value == '--ro-bind']
        assert all('.codex' not in value for value in argv)
        cache = '/home/union/' + agy.CACHE_RELATIVE
        expected_sources = {'/usr', str(agy.AGY), '/etc/ssl/certs', cache}
        assert all(source in expected_sources or source.startswith('/tmp/union-agy-run-')
                   for source in sources)
        assert sources.count(cache) == (0 if agy.ISOLATION_CHECK in argv else 1)
        for value in argv:
            if value.startswith('/tmp/union-agy-run-'):
                roots.add(Path('/tmp') / Path(value).parts[2])
        if agy.ISOLATION_CHECK in argv:
            root = Path('/tmp') / Path(next(v for v in argv if v.startswith('/tmp/union-agy-run-'))).parts[2]
            settings = json.loads((root / 'home/.gemini/antigravity-cli/settings.json').read_text())
            assert settings['permissions']['allow'] == [] and settings['permissions']['ask'] == []
            assert set(settings['permissions']['deny']) == {
                f'{name}(*)' for name in ('read_file', 'write_file', 'read_url',
                                        'execute_url', 'command', 'unsandboxed', 'mcp')}
            definition = (root / 'home/.gemini/config/agents/union-settings/agent.md').read_text()
            assert 'tools: [ask_permission, view_file, write_to_file, run_command]' in definition
            assert 'mcpServers: []' in definition and 'plugins: []' in definition and 'skills: []' in definition
            assert message == '' and not any(agy.CACHE_RELATIVE in value for value in argv)
            return json.dumps(dict.fromkeys(('host_canary_hidden', 'synthetic_home_visible',
                'network_namespace_changed', 'host_preview_unreachable', 'windows_mount_hidden'),
                failure != 'isolation')).encode()
        assert argv[0] == 'FILTERED'
        model_id = argv[argv.index('--model') + 1]
        model = next(model for model, ident in agy.MODEL_IDS.items() if ident == model_id)
        payload = json.loads(message)
        prompt = payload['message']['content']
        assert payload['event'] == 'user' and all(prompt not in value for value in argv)
        assert kwargs == {'timeout': 70, 'limit': 262144, 'classify_failure': agy.classify_failure}
        calls.append((model, prompt))
        if failure == 'cancel':
            raise asyncio.CancelledError()
        if failure in ('timeout', 'auth_required', 'rate_limited', 'output_limit'):
            raise RunnerError(failure)
        if failure == 'parser':
            return b'broken synthetic envelope'
        return response(model)

    monkeypatch.setattr(agy, 'guarded_command', guard)
    monkeypatch.setattr(agy, 'limited_execute', execute)
    return roots, calls


@pytest.mark.parametrize('model', ['gemini', 'claude'])
@pytest.mark.parametrize('failure', [None, 'preflight', 'isolation', 'network', 'parser',
                                     'timeout', 'auth_required', 'rate_limited', 'output_limit', 'cancel'])
async def test_call_contract_failures_and_cleanup(monkeypatch, model, failure):
    roots, calls = synthetic_runtime(monkeypatch, failure)
    prompt = '--help\n한글 질문 $(touch /not-run); `whoami`'
    if failure is None:
        assert await agy.AgyAdapter(model)(prompt) == 'synthetic ' + model
    elif failure == 'cancel':
        with pytest.raises(asyncio.CancelledError):
            await agy.AgyAdapter(model)(prompt)
    else:
        error = {'preflight': 'provider_unavailable', 'isolation': 'provider_unavailable',
                 'network': 'provider_unavailable', 'parser': 'invalid_output'}.get(failure, failure)
        with pytest.raises(RunnerError, match=error):
            await agy.AgyAdapter(model)(prompt)
    assert all(not root.exists() for root in roots)
    assert len(calls) == (0 if failure in {'preflight', 'isolation', 'network'} else 1)


@pytest.mark.parametrize('key,value', [('model', 'other'), ('agent', 'other'),
                                      ('permission_mode', 'other')])
def test_wrong_identity_is_never_displayed_as_requested_model(key, value):
    lines = response('gemini').decode().splitlines()
    first = json.loads(lines[0])
    first['init'][key] = value
    lines[0] = json.dumps(first)
    with pytest.raises(RunnerError, match='invalid_output'):
        agy.parse_response('\n'.join(lines).encode(), agy.MODEL_IDS['gemini'])


@pytest.mark.parametrize('message,code', [
    ('Authentication required private-value', 'auth_required'),
    ('RESOURCE_EXHAUSTED private-value', 'rate_limited'),
    ('lookup service: no such host private-value', 'network_unavailable'),
    ('Unexpected private-value', 'cli_failed')])
def test_error_never_returns_raw_diagnostic(message, code):
    assert agy.classify_failure(b'', message.encode()) == code


async def test_candidate_adapters_serialize_agy_and_retry_without_touching_gpt(monkeypatch):
    roots, calls = synthetic_runtime(monkeypatch)
    execute = agy.limited_execute
    entered, release = asyncio.Event(), asyncio.Event()
    attempts = []
    active = maximum = 0

    async def transport(argv, message, **kwargs):
        nonlocal active, maximum
        if argv[0] != 'FILTERED':
            return await execute(argv, message, **kwargs)
        model_id = argv[argv.index('--model') + 1]
        model = next(key for key, ident in agy.MODEL_IDS.items() if ident == model_id)
        active += 1
        maximum = max(maximum, active)
        attempts.append((model, json.loads(message)['message']['content']))
        try:
            if model == 'gemini' and sum(m == model for m, _ in attempts) == 1:
                entered.set()
                await release.wait()
                raise RunnerError('timeout')
            return await execute(argv, message, **kwargs)
        finally:
            active -= 1

    gpt_calls = []
    async def gpt(prompt):
        gpt_calls.append(prompt)
        return 'synthetic GPT'

    monkeypatch.setattr(agy, 'limited_execute', transport)
    store = Store(LiveRunner({'gpt': gpt, 'gemini': agy.AgyAdapter('gemini'),
                              'claude': agy.AgyAdapter('claude')}), mode='live')
    try:
        async with asyncio.timeout(3):
            key = (await store.create('same synthetic question', ['gpt', 'gemini', 'claude']))['run_id']
            await entered.wait()
            during = store.get(key)['models']
            assert during['gpt']['status'] == 'complete'
            assert during['gemini']['status'] == 'running'
            assert during['claude']['status'] == 'waiting'
            release.set()
            await asyncio.gather(*list(store.tasks))
            before = store.get(key)['models']
            assert before['gemini']['status'] == 'timeout'
            assert before['claude']['status'] == 'complete'
            saved = copy.deepcopy(before)
            await store.retry(key, 'gemini')
            await asyncio.gather(*list(store.tasks))
            after = store.get(key)['models']
            assert after['gpt'] == saved['gpt'] and after['claude'] == saved['claude']
            assert after['gemini']['attempt_id'] == 2 and after['gemini']['status'] == 'complete'
            assert attempts == [('gemini', 'same synthetic question'),
                                ('claude', 'same synthetic question'), ('gemini', 'same synthetic question')]
            assert maximum == 1 and gpt_calls == ['same synthetic question']
            assert len(roots) == 3 and all(not root.exists() for root in roots)
    finally:
        release.set()
        await store.close()

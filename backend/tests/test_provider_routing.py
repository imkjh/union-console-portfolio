"""Synthetic adapters only: never register or invoke an actual provider here."""
import asyncio
import copy
import httpx
import pytest
from backend.app.main import create_app
from backend.app.runners.providers import LiveRunner
from backend.app.runners.process import RunnerError


async def test_registry_is_fixed_and_unknown_models_never_dispatch():
    calls = []
    async def gpt(prompt):
        calls.append(prompt)
        return 'synthetic response'
    entries = {'gpt': gpt}
    runner = LiveRunner(entries)
    entries['gemini'] = gpt
    del entries['gpt']
    assert runner.available('gpt') and not runner.available('gemini')
    for model in ('gemini', 'claude', '--help'):
        with pytest.raises(RunnerError, match='provider_unavailable'):
            await runner(model, 'never execute', 1)
    assert calls == []
    assert await runner('gpt', '--help\n$(touch /not-run)', 2) == 'synthetic response'
    assert calls == ['--help\n$(touch /not-run)']
    with pytest.raises(ValueError, match='invalid_provider_registration'):
        LiveRunner({'unknown': gpt})


async def test_partial_live_selection_is_atomic_and_retry_preserves_success():
    calls = []
    async def gpt(prompt):
        calls.append(('gpt', prompt))
        return 'synthetic GPT'
    async def gemini(prompt):
        calls.append(('gemini', prompt))
        if sum(model == 'gemini' for model, _ in calls) == 1:
            raise RunnerError('timeout')
        return 'synthetic Gemini retry'
    app = create_app('live', LiveRunner({'gpt': gpt, 'gemini': gemini}))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://127.0.0.1:8000') as client:
            health = (await client.get('/api/health')).json()
            assert health['live_ready'] is False  # All three required for full readiness.
            client.headers['X-Union-Token'] = health['csrf_token']
            catalog = (await client.get('/api/models')).json()
            assert [m['id'] for m in catalog if m['available']] == ['gpt', 'gemini']
            assert catalog[-1]['model_verified'] is False
            mixed = await client.post('/api/runs', json={'prompt': 'never execute', 'models': ['gpt', 'claude']})
            assert mixed.status_code == 503
            assert calls == [] and app.state.store.runs == {} and not app.state.store.tasks
            response = await client.post('/api/runs', json={'prompt': 'same question', 'models': ['gpt', 'gemini']})
            assert response.status_code == 201
            key = response.json()['run_id']
            await asyncio.gather(*list(app.state.store.tasks))
            before = (await client.get('/api/runs/' + key)).json()
            saved_gpt = copy.deepcopy(before['models']['gpt'])
            assert before['mode'] == 'live' and saved_gpt['status'] == 'complete'
            assert before['models']['gemini']['status'] == 'timeout'
            assert (await client.post(f'/api/runs/{key}/models/claude/retry', json={})).status_code == 503
            assert (await client.post(f'/api/runs/{key}/models/gpt/retry', json={})).status_code == 409
            assert (await client.post(f'/api/runs/{key}/models/gemini/retry', json={})).status_code == 200
            await asyncio.gather(*list(app.state.store.tasks))
            after = (await client.get('/api/runs/' + key)).json()
            assert after['models']['gpt'] == saved_gpt
            assert after['models']['gemini']['attempt_id'] == 2
            assert after['models']['gemini']['response'] == 'synthetic Gemini retry'
            assert calls == [('gpt', 'same question'), ('gemini', 'same question'), ('gemini', 'same question')]
    finally:
        await app.state.store.close()


async def test_environment_and_plain_callback_cannot_open_live(monkeypatch):
    from backend.app.runners import codex, agy
    monkeypatch.setattr(codex, 'preflight', lambda: {'tested_cli_matches': False})
    monkeypatch.setattr(agy, 'preflight', lambda: False)
    monkeypatch.setenv('UNION_MODE', 'live')
    monkeypatch.setenv('UNION_LIVE_READY', 'true')
    monkeypatch.setenv('UNION_ENABLED_MODELS', 'gpt,gemini,claude')
    async def forbidden(*args):
        raise AssertionError('unregistered callback must not run')
    for runner in (None, forbidden):
        app = create_app(runner=runner)
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url='http://127.0.0.1:8000') as client:
                health = (await client.get('/api/health')).json()
                client.headers['X-Union-Token'] = health['csrf_token']
                assert health['live_ready'] is False
                assert not any(m['available'] for m in (await client.get('/api/models')).json())
                assert (await client.post('/api/runs', json={'prompt': 'never execute', 'models': ['gpt']})).status_code == 503
                assert not app.state.store.tasks
        finally:
            await app.state.store.close()


@pytest.mark.parametrize('gpt_ok,agy_ok', [(True, True), (True, False), (False, True), (False, False)])
async def test_native_registration_requires_each_provider_preflight(monkeypatch, gpt_ok, agy_ok):
    from backend.app.runners import codex, agy
    monkeypatch.setattr(codex, 'preflight', lambda: {'tested_cli_matches': gpt_ok})
    monkeypatch.setattr(agy, 'preflight', lambda: agy_ok)
    monkeypatch.setattr(agy, 'policy_verified', lambda: True)
    app = create_app('live')
    try:
        assert {m for m in ('gpt', 'gemini', 'claude') if app.state.store.runner.available(m)} == (
            ({'gpt'} if gpt_ok else set()) | ({'gemini', 'claude'} if agy_ok else set()))
    finally:
        await app.state.store.close()

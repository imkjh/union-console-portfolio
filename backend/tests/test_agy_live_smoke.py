"""Synthetic execution only; no CLI, network, or real credentials."""
import asyncio
import json

import pytest

from harness import agy_live_smoke as smoke
from backend.app.runners import agy
from backend.app.runners.process import RunnerError


@pytest.mark.parametrize('args', [[], ['--execute'], ['--accept-unverified-tool-access']])
def test_review_or_missing_consent_never_runs(monkeypatch, capsys, args):
    def forbidden(*args, **kwargs):
        raise AssertionError('no credential or process access')
    monkeypatch.setattr(smoke, 'preflight', forbidden)
    monkeypatch.setattr(smoke, 'experiment', forbidden)
    assert smoke.main(args) == (2 if '--execute' in args else 0)
    assert json.loads(capsys.readouterr().out)['execution'] is False


@pytest.mark.parametrize('failure', [None, 'preflight', 'auth_required', 'timeout', 'mismatch', 'unknown'])
async def test_fixed_scope_stops_on_failure_and_redacts(monkeypatch, failure):
    calls = []
    policy_before = agy.policy_verified()
    monkeypatch.setattr(smoke, 'preflight', lambda: failure != 'preflight')
    async def run(self, message):
        assert json.loads(message)['message']['content'] == smoke.QUESTION
        calls.append(self.model)
        if failure == 'auth_required':
            raise RunnerError('auth_required')
        if failure == 'timeout':
            raise TimeoutError('PRIVATE_DIAGNOSTIC')
        if failure == 'unknown':
            raise ValueError('PRIVATE_DIAGNOSTIC')
        return 'PRIVATE_DIAGNOSTIC' if failure == 'mismatch' else 'UNION_SMOKE_OK'
    monkeypatch.setattr(smoke.AgyAdapter, '_run', run)
    result = await smoke.experiment()
    assert calls == ([] if failure == 'preflight' else ['gemini', 'claude'] if failure is None else ['gemini'])
    assert result['response_compatibility_passed'] is (failure is None)
    assert result['tool_policy_verified'] is False and result['app_enabled'] is False
    assert 'PRIVATE_DIAGNOSTIC' not in json.dumps(result)
    assert agy.policy_verified() is policy_before


async def test_cancellation_propagates_without_next_model(monkeypatch):
    calls = []
    monkeypatch.setattr(smoke, 'preflight', lambda: True)
    async def cancel(self, message):
        calls.append(self.model)
        raise asyncio.CancelledError()
    monkeypatch.setattr(smoke.AgyAdapter, '_run', cancel)
    with pytest.raises(asyncio.CancelledError):
        await smoke.experiment()
    assert calls == ['gemini']

"""A review command must never silently become an authenticated model request."""
import json
from pathlib import Path
import pytest
from harness import codex_live_probe as probe


def test_default_probe_only_displays_review(monkeypatch, capsys):
    plan = {'mode': 'review_only', 'model_invocations': 0}
    monkeypatch.setattr(probe, 'review', lambda: plan)
    monkeypatch.setattr(probe.sys, 'argv', ['codex_live_probe.py'])
    def forbidden(*args):
        raise AssertionError('review must not start a live coroutine')
    monkeypatch.setattr(probe, 'run_once', forbidden)
    assert probe.main() == 0
    assert json.loads(capsys.readouterr().out) == plan


@pytest.mark.parametrize('plan', [
    {}, {'tested_cli_matches': False, 'auth_cache_regular_file': True},
    {'tested_cli_matches': True, 'auth_cache_regular_file': False},
    {'tested_cli_matches': 'true', 'auth_cache_regular_file': True},
])
async def test_incomplete_preflight_never_invokes_cli(monkeypatch, plan):
    async def forbidden(*args, **kwargs):
        raise AssertionError('preflight failure must not invoke a process')
    monkeypatch.setattr(probe, 'CodexAdapter', forbidden)
    result = await probe.run_once(plan)
    assert result['error'] == 'preflight_blocked'
    assert result['model_invocations'] == 0


async def test_reviewed_probe_uses_same_adapter_as_web_candidate(monkeypatch):
    calls = []
    class FakeAdapter:
        async def __call__(self, prompt):
            calls.append(prompt)
            return 'SYNTHETIC_ANSWER'
    monkeypatch.setattr(probe, 'CodexAdapter', FakeAdapter)
    result = await probe.run_once({'tested_cli_matches': True, 'auth_cache_regular_file': True,
                                   'network_dependencies_verified': True})
    assert calls == [probe.QUESTION]
    assert result['status'] == 'PASS' and result['model_invocations'] == 1
    assert 'SYNTHETIC_ANSWER' not in json.dumps(result)

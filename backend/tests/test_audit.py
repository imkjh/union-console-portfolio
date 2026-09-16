import asyncio
import logging

from backend.app.service import Store
from backend.app.runners.process import RunnerError


async def test_audit_correlates_real_state_changes_without_private_content(monkeypatch, caplog):
    monkeypatch.setenv('UNION_AUDIT_LOG', '1')
    caplog.set_level(logging.INFO, logger='uvicorn.error')
    marker = 'PRIVATE_TEST_INPUT_AND_OUTPUT'

    async def runner(model, prompt, attempt):
        if model == 'gemini' and attempt == 1:
            raise RunnerError('timeout')
        return marker

    store = Store(runner, 'demo')
    try:
        run = await store.create(marker, ['gpt', 'gemini'])
        await asyncio.gather(*list(store.tasks))
        await store.retry(run['run_id'], 'gemini')
        await asyncio.gather(*list(store.tasks))
        before = caplog.text
        assert not store.publish(run['run_id'], 'gemini', 1, status='complete', response=marker)
        assert caplog.text == before
        rows = [r.getMessage() for r in caplog.records if r.getMessage().startswith('UC ')]
        assert len(rows) == 9
        assert all('run=' + run['run_id'] in row and 'mode=demo' in row for row in rows)
        assert any('model=gemini cli=Antigravity attempt=1 status=timeout' in row for row in rows)
        assert any('model=gemini cli=Antigravity attempt=2 status=complete' in row for row in rows)
        assert marker not in caplog.text
    finally:
        await store.close()


async def test_audit_is_opt_in_and_never_formats_unknown_fields(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger='uvicorn.error')
    store = Store(None)
    monkeypatch.delenv('UNION_AUDIT_LOG', raising=False)
    store.audit('a' * 32, 'gpt', 1, 'complete')
    monkeypatch.setenv('UNION_AUDIT_LOG', '1')
    for key, model, number, status in [('private/path', 'gpt', 1, 'complete'),
                                       ('a' * 32, 'PRIVATE_TEST_MARKER', 1, 'complete'),
                                       ('a' * 32, 'gpt', 'PRIVATE_TEST_MARKER', 'complete'),
                                       ('a' * 32, 'gpt', 1, 'PRIVATE_TEST_MARKER')]:
        store.audit(key, model, number, status)
    assert not caplog.records

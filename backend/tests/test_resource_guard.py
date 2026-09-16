import pytest
from harness import resource_guard as guard
from harness import resource_worker as worker
from backend.app.runners.process import RunnerError


def test_guard_rejects_missing_cpu_memory_or_group_limit(monkeypatch):
    exact = dict(memory_max=512*1024*1024, swap_max=0, tasks_max=64, cpu_quota=50000, cpu_period=100000, oom_group=1)
    monkeypatch.setattr(worker, 'read_limits', lambda: ('folder', exact))
    assert worker.verified_limits('live')[1] == exact
    for key, bad in [('memory_max', 1024*1024*1024), ('swap_max', 1), ('tasks_max', 65), ('cpu_quota', 100000), ('cpu_period', 0), ('oom_group', 0)]:
        monkeypatch.setattr(worker, 'read_limits', lambda key=key,bad=bad: ('folder', {**exact, key: bad}))
        with pytest.raises(ValueError):
            worker.verified_limits('live')


@pytest.mark.parametrize('failure', [None, 'timeout', 'output_limit'])
async def test_own_service_stop_on_success_and_transport_error(monkeypatch, failure):
    calls = []
    async def fake(argv, *args, **kwargs):
        calls.append(argv)
        try:
            if len(calls) == 1 and failure:
                raise RunnerError(failure)
            return b'answer'
        finally:
            if kwargs.get('before_stop'):
                await kwargs['before_stop']()
    monkeypatch.setattr(guard, 'execute', fake)
    if failure:
        with pytest.raises(RunnerError, match=failure):
            await guard.limited_execute(['/bin/true'], '')
    else:
        assert await guard.limited_execute(['/bin/true'], '') == b'answer'
    assert len(calls) == 2
    unit = next(a.partition('=')[2] for a in calls[0] if a.startswith('--unit='))
    assert calls[1][-2:] == ['stop', unit]
    assert 'RuntimeMaxSec=100' in calls[0]
    assert 'KillMode=control-group' in calls[0]

import asyncio
import copy
import pytest
from backend.app.service import Store, ServiceError
from backend.app.runners.process import RunnerError


async def settled(store):
    await asyncio.gather(*list(store.tasks))


async def test_T01_T02_T04_T05_independent_retry():
    calls = []
    completions = []
    release = asyncio.Event()
    async def runner(model, prompt, attempt):
        calls.append((model, prompt, attempt))
        if attempt == 2:
            await release.wait()
        if model == "gemini" and attempt == 1:
            raise RunnerError("cli_failed")
        await asyncio.sleep(0.03 if model == "gpt" else 0.01)
        completions.append(model)
        return model + ':' + prompt
    store = Store(runner)
    run = await store.create('독립 질문', ['gpt', 'gemini', 'claude'])
    key = run['run_id']
    assert all(a['status'] == 'waiting' for a in run['models'].values())
    await asyncio.sleep(0)
    assert store.get(key)['models']['gpt']['status'] == 'running'
    await settled(store)
    before = store.get(key)
    assert completions == ['claude', 'gpt']
    assert [before['models'][m]['status'] for m in ['gpt','gemini','claude']] == ['complete','failed','complete']
    results = await asyncio.gather(store.retry(key,'gemini'), store.retry(key,'gemini'),return_exceptions=True)
    assert sum(isinstance(r,ServiceError) for r in results) == 1
    assert not store.publish(key,'gemini',1,status='complete',response='stale')
    release.set()
    await settled(store)
    after = store.get(key)
    assert after['models']['gemini']['attempt_id'] == 2
    assert after['models']['gemini']['response'] == 'gemini:독립 질문'
    for m in ['gpt','claude']:
        assert before['models'][m] == after['models'][m]
    assert calls.count(('gemini','독립 질문',2)) == 1
    assert len(calls) == 4
    with pytest.raises(ServiceError):
        await store.retry(key,'gpt')


async def test_T06_T09_capacity_isolation_shutdown():
    entered = asyncio.Event()
    async def runner(model,prompt,attempt):
        entered.set()
        await asyncio.sleep(.02)
        return prompt + model
    store=Store(runner,max_active=2)
    a=await store.create('AAA',['gpt'])
    b=await store.create('BBB',['gpt'])
    with pytest.raises(ServiceError):
        await store.create('CCC',['gpt'])
    await settled(store)
    assert store.get(a['run_id'])['models']['gpt']['response']=='AAAgpt'
    assert store.get(b['run_id'])['models']['gpt']['response']=='BBBgpt'
    c=await store.create('cancel',['gpt'])
    await entered.wait()
    await asyncio.sleep(0)
    await store.close()
    assert not store.tasks
    assert store.get(c['run_id'])['models']['gpt']['error']=='cancelled'


async def test_T09_queue_timeout_and_rate_auth():
    async def runner(model,prompt,attempt):
        if model=='gemini':
            await asyncio.sleep(.08)
            return 'ok'
        raise RunnerError('auth_required' if model=='gpt' else 'rate_limited')
    store=Store(runner,queue_timeout=.02)
    run=await store.create('x',['gpt','gemini','claude'])
    await settled(store)
    result=store.get(run['run_id'])['models']
    assert result['gpt']['error']=='auth_required'
    assert result['claude']['error']=='queue_timeout'
    await store.retry(run['run_id'],'claude')
    await settled(store)
    assert store.get(run['run_id'])['models']['claude']['error']=='rate_limited'


async def test_retention_active_not_evicted():
    hold=asyncio.Event()
    async def runner(*args):
        await hold.wait()
        return 'ok'
    store=Store(runner,max_runs=1,ttl=.01)
    run=await store.create('x',['gpt'])
    await asyncio.sleep(.02)
    assert store.get(run['run_id'])
    with pytest.raises(ServiceError):
        await store.create('y',['gpt'])
    hold.set()
    await settled(store)
    await asyncio.sleep(.02)
    with pytest.raises(ServiceError) as exc:
        store.get(run['run_id'])
    assert exc.value.status==404


@pytest.mark.parametrize('value,code',[('', 'invalid_output'),('a'*65537,'output_limit'),(None,'invalid_output')])
async def test_T08_response_limits(value,code):
    async def runner(*args): return value
    store=Store(runner)
    run=await store.create('x',['gpt'])
    await settled(store)
    assert store.get(run['run_id'])['models']['gpt']['error']==code

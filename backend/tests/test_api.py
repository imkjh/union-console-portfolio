import asyncio
import httpx
import pytest
from contextlib import asynccontextmanager
from backend.app.main import create_app
from backend.app.runners.process import RunnerError


@asynccontextmanager
async def client_for(mode='demo',runner=None):
    app=create_app(mode,runner)
    client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8000')
    async with client:
        token=(await client.get('/api/health')).json()['csrf_token']
        client.headers.update({'X-Union-Token':token})
        try:
            yield app,client
        finally:
            await app.state.store.close()


async def test_T10_inputs_selection():
    calls=[]
    async def runner(m,p,a): calls.append(m);return p
    async with client_for(runner=runner) as (app,c):
        for body in [{'prompt':' ','models':['gpt']},{'prompt':'x'*4001,'models':['gpt']},{'prompt':'x','models':[]},{'prompt':'x','models':['gpt','gpt']},{'prompt':'x','models':['unknown']},{'prompt':'x','models':['gpt'],'options':['--help']}]:
            assert (await c.post('/api/runs',json=body)).status_code==422
        r=await c.post('/api/runs',json={'prompt':'x','models':['gpt']})
        assert r.status_code==201
        await asyncio.gather(*list(app.state.store.tasks))
        assert calls==['gpt']
    await app.state.store.close()


async def test_T11_origin_host_json_csrf():
    async with client_for() as (app,c):
        body={'prompt':'x','models':['gpt']}
        for headers in [{'Origin':'https://evil.example'},{'Host':'evil.example'},{'Host':'localhost.evil.example:8000'},{'Origin':'null'},{'Sec-Fetch-Site':'cross-site'},{'X-Union-Token':'wrong'}]:
            assert (await c.post('/api/runs',json=body,headers=headers)).status_code==403
        assert (await c.post('/api/runs',content='{}',headers={'Content-Type':'text/plain'})).status_code==415
        assert (await c.post('/api/runs',content='x'*32769,headers={'Content-Type':'application/json'})).status_code==413
        assert (await c.options('/api/runs',headers={'Origin':'https://evil.example'})).status_code==403
        assert (await c.get('/api/models')).headers.get('access-control-allow-origin') is None
    await app.state.store.close()


async def test_T12_no_raw_error_or_input_in_logs(caplog):
    marker='SYNTHETIC_PRIVATE_MARKER'
    async def runner(*args): raise RuntimeError(marker)
    async with client_for(runner=runner) as (app,c):
        r=await c.post('/api/runs',json={'prompt':'x','models':['gpt']})
        await asyncio.gather(*list(app.state.store.tasks))
        result=await c.get('/api/runs/'+r.json()['run_id'])
        assert marker not in result.text
        invalid=await c.post('/api/runs',json={'prompt':marker,'models':['bad']})
        assert marker not in invalid.text
        assert marker not in caplog.text
    await app.state.store.close()


async def test_live_fail_closed(monkeypatch):
    from backend.app.runners import codex, agy
    monkeypatch.setattr(codex, 'preflight', lambda: {'tested_cli_matches': False})
    monkeypatch.setattr(agy, 'preflight', lambda: False)
    async with client_for('live') as (app,c):
        assert all(not m['available'] for m in (await c.get('/api/models')).json())
        r=await c.post('/api/runs',json={'prompt':'never launch','models':['gpt','gemini','claude']})
        assert r.status_code==503
        assert not app.state.store.tasks


async def test_T05_concurrent_http_retry():
    calls=[]
    release=asyncio.Event()
    async def runner(m,p,a):
        calls.append((m,p,a))
        if a==1: raise RunnerError('cli_failed')
        await release.wait()
        return 'recovered'
    async with client_for(runner=runner) as (app,c):
        run=(await c.post('/api/runs',json={'prompt':'same prompt','models':['gpt']})).json()
        await asyncio.gather(*list(app.state.store.tasks))
        url=f"/api/runs/{run['run_id']}/models/gpt/retry"
        responses=await asyncio.gather(c.post(url,json={}),c.post(url,json={}))
        assert sorted(r.status_code for r in responses)==[200,409]
        release.set()
        await asyncio.gather(*list(app.state.store.tasks))
        assert calls==[('gpt','same prompt',1),('gpt','same prompt',2)]


async def test_static_page_served():
    async with client_for() as (app,c):
        r=await c.get('/')
        assert r.status_code==200
        assert 'Union Console' in r.text
        assert "frame-ancestors 'none'" in r.headers['content-security-policy']


@pytest.mark.parametrize('peer', ['192.0.2.10', '10.0.0.2', '::ffff:192.0.2.10', 'localhost', None])
async def test_remote_peer_cannot_read_token_or_invoke_runner(peer):
    calls = []
    async def runner(*args):
        calls.append(args)
        return 'fake'
    app = create_app('demo', runner)
    transport = httpx.ASGITransport(app=app, client=None if peer is None else (peer, 12345))
    async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1:8000') as c:
        for method, path in [('GET', '/api/health'), ('GET', '/'), ('POST', '/api/runs')]:
            response = await c.request(method, path, json={'prompt': 'fake', 'models': ['gpt']})
            assert response.status_code == 403
            assert 'csrf_token' not in response.text
    assert not calls and not app.state.store.tasks
    await app.state.store.close()


@pytest.mark.parametrize('peer', ['127.0.0.1', '::1', '::ffff:127.0.0.1'])
async def test_loopback_peer_allowed(peer):
    app = create_app('demo')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 12345)),
                                base_url='http://127.0.0.1:8000') as c:
        assert (await c.get('/api/health')).status_code == 200
    await app.state.store.close()


async def test_proxy_ambiguous_headers_and_cross_port_origin_rejected():
    async with client_for() as (app, c):
        for headers in (
            {'Forwarded': 'for=192.0.2.1;host=127.0.0.1:8000'},
            {'X-Forwarded-For': '127.0.0.1'}, {'X-Forwarded-Host': '127.0.0.1:8000'},
            {'X-Forwarded-Proto': 'http'}, {'Origin': 'http://127.0.0.1:5173'},
            [('Host', '127.0.0.1:8000'), ('Host', 'evil.example')],
            [('Origin', 'http://127.0.0.1:8000'), ('Origin', 'https://evil.example')],
        ):
            r = await c.get('/api/health', headers=headers)
            assert r.status_code == 403 and 'csrf_token' not in r.text
        body = {'prompt': 'fake', 'models': ['gpt']}
        assert (await c.post('/api/runs', json=body, headers=[(b'X-Union-Token', b'\xff')])).status_code == 403
        assert not app.state.store.tasks

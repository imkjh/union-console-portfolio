import asyncio
import ctypes
import os
from pathlib import Path
import sys
import pytest
from backend.app.runners.process import execute, RunnerError


async def test_T07_stdin_exact_and_fresh_cwd(tmp_path):
    prompt='따옴표 "\'\n한글 $() ; --help `echo unsafe`'
    script=tmp_path/'echo.py'
    script.write_text('import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())')
    dirs=[tmp_path/'a',tmp_path/'b']
    for d in dirs: d.mkdir()
    results=await asyncio.gather(*(execute([sys.executable,str(script)],prompt,d) for d in dirs))
    assert results==[prompt.encode(),prompt.encode()]
    assert not (tmp_path/'unsafe').exists()


@pytest.mark.parametrize('stream',['stdout','stderr'])
async def test_T08_output_limit(tmp_path,stream):
    script=tmp_path/'flood.py'
    script.write_text(f'import sys\nwhile True: sys.{stream}.write("x"*8192); sys.{stream}.flush()')
    with pytest.raises(RunnerError) as exc:
        await execute([sys.executable,str(script)],'',tmp_path,limit=16384,timeout=2)
    assert exc.value.code=='output_limit'


async def test_T03_timeout_descendants_reaped(tmp_path):
    script=tmp_path/'tree.py'
    pidfile=tmp_path/'child.pid'
    script.write_text('import subprocess,sys,time,signal\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\np=subprocess.Popen([sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"])\nPath(sys.argv[1]).write_text(str(p.pid))\ntime.sleep(60)\n')
    with pytest.raises(RunnerError) as exc:
        await execute([sys.executable,str(script),str(pidfile)],'',tmp_path,timeout=.3)
    assert exc.value.code=='timeout'
    pid=int(pidfile.read_text())
    assert not Path(f'/proc/{pid}').exists()


async def test_T09_cancel_reaps_direct_child(tmp_path):
    script=tmp_path/'wait.py'
    pidfile=tmp_path/'parent.pid'
    script.write_text('import os,sys,time\nfrom pathlib import Path\nPath(sys.argv[1]).write_text(str(os.getpid()))\ntime.sleep(60)')
    task=asyncio.create_task(execute([sys.executable,str(script),str(pidfile)],'',tmp_path))
    for _ in range(100):
        if pidfile.exists(): break
        await asyncio.sleep(.01)
    assert pidfile.exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert not Path('/proc/'+pidfile.read_text()).exists()


async def test_T12_stderr_redacted(tmp_path):
    script=tmp_path/'fail.py'
    script.write_text('import sys; sys.stderr.write("SYNTHETIC_PRIVATE_MARKER"); sys.exit(2)')
    with pytest.raises(RunnerError) as exc:
        await execute([sys.executable,str(script)],'',tmp_path)
    assert str(exc.value)=='cli_failed'


@pytest.mark.parametrize('exit_code', [0, 2])
async def test_bounded_observer_sees_diagnostics_without_returning_them(tmp_path, exit_code):
    observed = []
    script = tmp_path / 'notice.py'
    script.write_text('import sys; print("ANSWER"); sys.stderr.write("SYNTHETIC_NOTICE"); sys.exit(' + str(exit_code) + ')')
    kwargs = {'observe': lambda out, err: observed.append((out, err))}
    if exit_code:
        with pytest.raises(RunnerError, match='cli_failed'):
            await execute([sys.executable, str(script)], '', tmp_path, **kwargs)
    else:
        assert await execute([sys.executable, str(script)], '', tmp_path, **kwargs) == b'ANSWER\n'
    assert observed == [(b'ANSWER\n', b'SYNTHETIC_NOTICE')]


async def test_child_api_keys_not_inherited(tmp_path,monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','SYNTHETIC_PRIVATE_MARKER')
    script=tmp_path/'env.py'
    script.write_text('import os; print("absent" if "OPENAI_API_KEY" not in os.environ else "present")')
    assert (await execute([sys.executable,str(script)],'',tmp_path)).strip()==b'absent'


async def test_T03_service_timeout_preserves_other_results(tmp_path):
    from backend.app.service import Store
    import tempfile
    script=tmp_path/'model.py'
    pidfile=tmp_path/'descendant.pid'
    script.write_text('import subprocess,sys,time\nfrom pathlib import Path\nif sys.argv[1]=="claude":\n p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"])\n Path(sys.argv[2]).write_text(str(p.pid))\n time.sleep(60)\nelse:\n print(sys.argv[1]+":"+sys.stdin.read())\n')
    workdirs=[]
    async def runner(model,prompt,attempt):
        with tempfile.TemporaryDirectory(prefix='union-fake-') as cwd:
            workdirs.append(cwd)
            return (await execute([sys.executable,str(script),model,str(pidfile)],prompt,cwd,timeout=.3)).decode()
    store=Store(runner)
    run=await store.create('isolated',['gpt','gemini','claude'])
    await asyncio.gather(*list(store.tasks))
    result=store.get(run['run_id'])['models']
    assert result['claude']['status']=='timeout'
    assert result['gpt']['response'].strip()=='gpt:isolated'
    assert result['gemini']['response'].strip()=='gemini:isolated'
    assert len(set(workdirs))==3
    assert all(not Path(p).exists() for p in workdirs)
    assert not Path('/proc/'+pidfile.read_text()).exists()

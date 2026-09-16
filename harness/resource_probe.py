"""Small offline cgroup checks. No credentials, providers, or global settings."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
import uuid
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness.resource_guard import command_for, limited_execute, bus_prefix
from backend.app.runners.process import RunnerError


def check(mode):
    unit = 'union-probe-' + uuid.uuid4().hex + '.service'
    argv = command_for(unit, [], profile='test', mode=mode)
    # Keep this failed unit briefly so the manager can report the OOM cause.
    argv.remove('--collect')
    details = {}
    try:
        result = subprocess.run(argv, input=b'', capture_output=True, timeout=15,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        observed = subprocess.run([*bus_prefix(), '/usr/bin/systemctl', '--user', 'show', unit,
                                   '-p', 'Result', '-p', 'ExecMainCode', '-p', 'ExecMainStatus'],
                                  capture_output=True, timeout=5)
        details = dict(line.split('=', 1) for line in observed.stdout.decode().splitlines() if '=' in line)
    finally:
        for action in ('stop', 'reset-failed'):
            subprocess.run([*bus_prefix(), '/usr/bin/systemctl', '--user', action, unit],
                           capture_output=True, timeout=5)
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = {}
    ok = data.get('limits_verified') is True
    if mode == 'cpu':
        ok = ok and result.returncode == 0 and data.get('cpu_throttled') is True
    elif mode == 'oom':
        ok = ok and data.get('oom_test_started') is True and details.get('Result') == 'oom-kill' and details.get('ExecMainStatus') == '9'
    else:
        ok = ok and result.returncode == 0
    return {'case': mode, 'status': 'PASS' if ok else 'BLOCKED', 'exit_code': result.returncode, 'service_result': details.get('Result'), **data}


async def timeout_check():
    # File is a synthetic marker under our own temporary directory.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='union-stop-') as tmp:
        marker = Path(tmp) / 'started'
        code = 'import os,time,pathlib;pathlib.Path(__import__("sys").argv[1]).write_text(str(os.getpid()));time.sleep(30)'
        error = None
        started = time.monotonic()
        try:
            await limited_execute(['/usr/bin/python3', '-I', '-c', code, str(marker)], '', timeout=2)
        except RunnerError as exc:
            error = exc.code
        elapsed = time.monotonic() - started
        existed = marker.is_file()
        alive = False
        if existed:
            pid = int(marker.read_text())
            alive = Path(f'/proc/{pid}').exists()
        return {'case': 'timeout_cleanup', 'status': 'PASS' if error == 'timeout' and existed and not alive and elapsed < 8 else 'BLOCKED',
                'error': error, 'elapsed_seconds': round(elapsed, 2), 'child_started': existed, 'child_alive_after_stop': alive}


if __name__ == '__main__':
    reports = [check(mode) for mode in ('inspect', 'cpu', 'oom')]
    reports.append(asyncio.run(timeout_check()))
    report = {'scope': 'Offline transient cgroup; no model or credentials', 'cases': reports, 'model_calls': 0}
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if all(r['status'] == 'PASS' for r in reports) else 2)

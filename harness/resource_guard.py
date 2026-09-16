"""Request-local systemd limits; never change persistent or existing units."""
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.runners.process import execute, RunnerError

WORKER = ROOT / 'harness/resource_worker.py'


def bus_prefix():
    runtime = f'/run/user/{os.getuid()}'
    return ['/usr/bin/env', 'XDG_RUNTIME_DIR=' + runtime,
            'DBUS_SESSION_BUS_ADDRESS=unix:path=' + runtime + '/bus']


def command_for(unit, command, *, profile='live', mode='exec'):
    if profile not in {'live', 'test'} or mode not in {'exec', 'inspect', 'cpu', 'oom'}:
        raise ValueError('unsupported_resource_profile')
    if not unit.startswith('union-probe-') or not unit.endswith('.service'):
        raise ValueError('invalid_resource_unit')
    memory = '512M' if profile == 'live' else '64M'
    return [*bus_prefix(), '/usr/bin/systemd-run', '--user', '--quiet', '--pipe', '--wait',
            '--collect', '--expand-environment=no', '--no-ask-password', '--unit=' + unit,
            '-p', 'MemoryMax=' + memory, '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=50%',
            '-p', 'TasksMax=64', '-p', 'RuntimeMaxSec=100', '-p', 'TimeoutStopSec=2',
            '-p', 'OOMPolicy=kill', '-p', 'KillMode=control-group', '-p', 'LimitCORE=0',
            '-p', 'WorkingDirectory=/tmp',
            '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C.UTF-8',
            '/usr/bin/python3', '-I', str(WORKER), profile, mode, *command]


async def limited_execute(command, prompt, *, timeout=90, limit=262144, classify_failure=None):
    unit = 'union-probe-' + uuid.uuid4().hex + '.service'
    async def stop_unit():
        # Run before transport pipe draining waits for the separate service group.
        try:
            await execute([*bus_prefix(), '/usr/bin/systemctl', '--user', '--no-ask-password',
                           'stop', unit], '', '/tmp', timeout=5, limit=8192)
        except RunnerError:
            # Collected units are already gone; RuntimeMaxSec remains a fallback.
            pass
    return await execute(command_for(unit, command), prompt, '/tmp', timeout=timeout,
                         limit=limit, before_stop=stop_unit, classify_failure=classify_failure)

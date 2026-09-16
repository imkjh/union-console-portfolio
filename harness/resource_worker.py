"""Verify this transient cgroup before a fixed harness command can execute."""
import json
import os
from pathlib import Path
import sys
import time

PROFILES = {'live': 512 * 1024 * 1024, 'test': 64 * 1024 * 1024}


def read_limits():
    lines = Path('/proc/self/cgroup').read_text().splitlines()
    relative = next(line[3:] for line in lines if line.startswith('0::/'))
    folder = Path('/sys/fs/cgroup') / relative.lstrip('/')
    quota, period = (folder / 'cpu.max').read_text().split()
    return folder, {
        'memory_max': int((folder / 'memory.max').read_text()),
        'swap_max': int((folder / 'memory.swap.max').read_text()),
        'tasks_max': int((folder / 'pids.max').read_text()),
        'cpu_quota': int(quota), 'cpu_period': int(period),
        'oom_group': int((folder / 'memory.oom.group').read_text()),
    }


def verified_limits(profile):
    folder, limits = read_limits()
    if (limits['memory_max'] != PROFILES[profile] or limits['swap_max'] != 0
            or limits['tasks_max'] != 64 or limits['cpu_period'] <= 0
            or limits['cpu_quota'] / limits['cpu_period'] != 0.5 or limits['oom_group'] != 1):
        raise ValueError('resource_limits_unconfirmed')
    return folder, limits


def main():
    try:
        profile, mode, *command = sys.argv[1:]
        folder, limits = verified_limits(profile)
        if mode == 'exec' and command:
            os.execv(command[0], command)
        elif mode == 'inspect':
            print(json.dumps({'limits_verified': True, **limits}))
        elif mode == 'cpu':
            def throttled():
                stats = dict(line.split() for line in (folder / 'cpu.stat').read_text().splitlines())
                return int(stats['nr_throttled'])
            before = throttled()
            deadline = time.monotonic() + 0.8
            while time.monotonic() < deadline:
                pass
            print(json.dumps({'limits_verified': True, 'cpu_throttled': throttled() > before}))
        elif mode == 'oom' and profile == 'test':
            # Only 128 MiB requested inside a verified 64 MiB, zero-swap cgroup.
            print(json.dumps({'limits_verified': True, 'oom_test_started': True}), flush=True)
            block = bytearray(128 * 1024 * 1024)
            print(json.dumps({'unexpected_allocation': len(block)}))
            return 2
        else:
            raise ValueError('unsupported_resource_mode')
    except (OSError, ValueError, KeyError, StopIteration):
        print(json.dumps({'error': 'resource_limits_unconfirmed'}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

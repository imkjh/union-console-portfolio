"""No-model Codex sandbox canary. Never accesses credentials or sends a prompt.

This tests an OS command sandbox, NOT model-visible tools or provider live safety.
The only read/write targets are freshly created fake files in a temporary tree.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

# Reuse the tested bounded transport; this harness is deliberately outside the API.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.runners.process import execute, RunnerError

CODEX = Path('/opt/union-cli/codex')
WORKER = r'''
import json, pathlib, subprocess, sys
outside, output = map(pathlib.Path, sys.argv[1:])
observed = {}
try:
    observed['outside_read_allowed'] = outside.read_text() == 'UNION_FAKE_CANARY'
except OSError:
    observed['outside_read_allowed'] = False
try:
    output.write_text('UNION_FAKE_WRITE')
    observed['cwd_write_allowed'] = True
except OSError:
    observed['cwd_write_allowed'] = False
try:
    observed['command_exec_allowed'] = subprocess.run(['/usr/bin/true'], check=False).returncode == 0
except OSError:
    observed['command_exec_allowed'] = False
print(json.dumps(observed))
'''


async def probe():
    report = {'model_calls': 0, 'credential_access_by_harness': False,
              'scope': 'Codex command sandbox only; not a provider tool/canary PASS',
              'executable': str(CODEX), 'cases': [], 'live_ready': False}
    if not CODEX.is_file():
        report['error'] = 'cli_missing'
        return report
    try:
        report['version'] = (await execute([str(CODEX), '--version'], '', '/tmp', timeout=15)).decode().strip()
    except (RunnerError, OSError):
        report['error'] = 'version_probe_failed'
        return report
    with tempfile.TemporaryDirectory(prefix='union-security-') as temp:
        root = Path(temp)
        cwd = root / 'work'
        cwd.mkdir()
        outside = root / 'outside-canary.txt'
        outside.write_text('UNION_FAKE_CANARY')
        profiles = [
            ('read_only', ['-P', ':read-only']),
            ('explicit_canary_deny', [
                '-c', 'permissions.union_probe={extends=":read-only",filesystem={'
                      + json.dumps(str(outside)) + '="deny"}}',
                '-P', 'union_probe',
            ]),
        ]
        for name, args in profiles:
            output = cwd / f'{name}-write.txt'
            argv = [str(CODEX), 'sandbox', *args, '-C', str(cwd), '--',
                    '/usr/bin/python3', '-I', '-c', WORKER, str(outside), str(output)]
            case = {'name': name}
            try:
                raw = await execute(argv, '', cwd, timeout=20, limit=32768)
                data = json.loads(raw)
                keys = {'outside_read_allowed', 'cwd_write_allowed', 'command_exec_allowed'}
                if not isinstance(data, dict) or set(data) != keys or any(type(v) is not bool for v in data.values()):
                    raise ValueError('invalid_probe_output')
                case.update(status='observed', **data, write_side_effect=output.exists())
            except (RunnerError, OSError, ValueError) as exc:
                code = exc.code if isinstance(exc, RunnerError) else 'probe_failed'
                case.update(status='blocked', error=code)
            report['cases'].append(case)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional sanitized JSON evidence file')
    args = parser.parse_args()
    report = asyncio.run(probe())
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        # Do not replace an existing evidence file accidentally.
        with args.output.open('x') as target:
            target.write(serialized)
    print(serialized, end='')
    return 2 if report.get('error') or any(c['status'] == 'blocked' for c in report['cases']) else 0


if __name__ == '__main__':
    raise SystemExit(main())

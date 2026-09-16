"""Inside the isolated runner: inspect synthetic side effects and safe tool metadata."""
import asyncio
import json
import mmap
import os
import re
from pathlib import Path
import sys

try:
    from process import execute, RunnerError
except ModuleNotFoundError:
    from backend.app.runners.process import execute, RunnerError

TOOLS = frozenset(('view_file', 'read_file', 'write_to_file', 'run_command',
                   'ask_permission', 'list_dir', 'replace_file_content'))


def summarize(raw, marker, stderr=b'', public_binary=None):
    tools = {}
    result_seen = False
    marker_seen = marker.encode() in raw
    notices = set()
    diagnostic_terms = set()
    for line in stderr.decode(errors='replace').splitlines():
        if any(name in line for name in TOOLS) or 'headless' in line.lower():
            diagnostic_terms.update(set(re.findall(r'[a-z]+', line.lower())) & {
                'denied', 'allowed', 'permission', 'permissions', 'headless', 'approval',
                'disabled', 'unknown', 'not', 'available', 'sandbox', 'error', 'failed',
                'cancelled', 'canceled', 'rejected', 'blocked', 'required', 'validation'})
        if 'headless mode cannot prompt for' in line and 'auto-denied' in line:
            notices.update(name for name in TOOLS if re.search(r'\b' + name + r'\b', line))
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict):
            continue
        if event.get('event') == 'result':
            result_seen = True
        step = event.get('step_update')
        if not isinstance(step, dict) or step.get('step_type') != 'tool':
            continue
        info = step.get('tool_info', {})
        if not isinstance(info, dict):
            info = {}
        name = step.get('tool_name', info.get('name'))
        name = name if isinstance(name, str) and name in TOOLS else 'other'
        index = step.get('step_index')
        if type(index) is not int:
            continue
        diagnostic = json.dumps({'error': info.get('error'), 'output': info.get('output')}).lower()
        target = {'view_file': '/work/union-read-canary.txt', 'read_file': '/work/union-read-canary.txt',
                  'write_to_file': '/work/union-write-created',
                  'run_command': '/usr/bin/touch /work/union-command-created'}.get(name)
        # Installed agy 1.1.27 uses ERROR for denied tool terminal events.
        tools[index] = {'tool': name, 'done': step.get('state') in {'DONE', 'ERROR'},
                        'state': step.get('state') if step.get('state') in {
                            'DONE', 'ERROR', 'FAILED', 'CANCELED', 'CANCELLED',
                            'RUNNING', 'PENDING', 'BLOCKED', 'ABORTED'} else 'other',
                        'known_fields': sorted(set(info) & {'name', 'parameters', 'output', 'error',
                            'arguments', 'input', 'result', 'error_type', 'error_message'}),
                        'error_shape': type(info.get('error')).__name__,
                        'error_known_fields': sorted(set(info['error']) & {'type', 'message', 'code', 'error',
                            'error_type', 'error_message', 'details'}) if isinstance(info.get('error'), dict) else [],
                        'native_headless_denial': name in notices,
                        'target_matches': bool(target and target in json.dumps(info.get('parameters'))),
                        'parameter_shape': type(info.get('parameters')).__name__,
                        'error_terms': sorted(set(re.findall(r'[a-z]+', diagnostic)) & {
                            'tool', 'tools', 'name', 'allowed', 'available', 'disabled', 'enabled',
                            'permission', 'permissions', 'denied', 'invalid', 'argument', 'arguments',
                            'parameter', 'parameters', 'schema', 'validation', 'restricted', 'not',
                            'found', 'access', 'error', 'unsupported', 'approval', 'required',
                            'failed', 'read', 'write', 'sandbox', 'list', 'agent', 'policy'}),
                        'error_present': bool(info.get('error')),
                        'permission_denial': any(term in json.dumps(info.get('error')).lower() for term in
                            ('denied', 'not allowed', 'not permitted', 'permission policy', 'disallowed')),
                        'missing_file': 'no such file' in diagnostic,
                        'read_only': 'read-only file system' in diagnostic,
                        'read_marker_seen': marker.lower() in diagnostic}
        # Only an exact public executable string may be disclosed, never dynamic
        # diagnostic text. No credential file is opened by this observer.
        error = info.get('error')
        message = error.get('message') if isinstance(error, dict) else None
        if public_binary and isinstance(message, str) and 12 <= len(message) <= 500:
            with open(public_binary, 'rb') as binary:
                with mmap.mmap(binary.fileno(), 0, access=mmap.ACCESS_READ) as source:
                    if source.find(message.encode()) >= 0:
                        tools[index]['public_error_message'] = message
    return {'result_seen': result_seen, 'read_marker_seen': marker_seen,
            'native_diagnostic_terms': sorted(diagnostic_terms),
            'tool_steps': [tools[index] for index in sorted(tools)]}


async def main():
    marker = Path('/work/union-read-canary.txt').read_text()
    Path('/work/union-control-write').write_text('synthetic control')
    report = {'fixture_readable': bool(marker),
              'fixture_workspace_writable': Path('/work/union-control-write').is_file()}
    prompt = sys.stdin.read(8192)
    raw, diagnostic = b'', b''
    def observe(out, err):
        nonlocal raw, diagnostic
        raw, diagnostic = out, err
    def failure(out, err):
        nonlocal raw
        raw = out
        return 'cli_failed'
    try:
        raw = await execute(['/usr/bin/env', 'HOME=' + os.environ['HOME'],
            'PLAYWRIGHT_DRIVER_PATH=/disabled-browser', *sys.argv[1:]], prompt, '/work',
            timeout=65, limit=262144, classify_failure=failure, observe=observe)
        report['cli_exit_success'] = True
    except RunnerError as exc:
        report['cli_exit_success'] = False
        report['error'] = exc.code
    report.update(summarize(raw, marker, diagnostic, '/cli/agy'))
    report['write_canary_created'] = os.path.lexists('/work/union-write-created')
    report['command_canary_created'] = os.path.lexists('/work/union-command-created')
    print(json.dumps(report))


if __name__ == '__main__':
    asyncio.run(main())

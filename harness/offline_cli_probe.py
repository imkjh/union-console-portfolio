"""Inspect CLI configuration in a credential-free, offline mount namespace.

Only fixed metadata commands run. No model prompt, existing home/config mounts,
API keys, or global settings changes. This is NOT provider security approval.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.runners.process import execute, RunnerError

CODEX = Path('/opt/union-cli/codex')
AGY = Path('/opt/union-cli/agy')
FEATURES = (
    'shell_tool', 'unified_exec', 'shell_snapshot', 'view_image', 'apps',
    'browser_use', 'browser_use_external', 'computer_use', 'hooks', 'plugins',
    'remote_plugin', 'multi_agent', 'image_generation', 'skill_search',
    'skill_mcp_dependency_install', 'code_mode_host', 'workspace_dependencies',
    'in_app_local_automation', 'tool_suggest',
)
AGENT = '''---
name: union-offline
description: Synthetic offline discovery canary
tools: []
mainAgent: true
subagent: false
commandExecutionPolicy: "off"
mcpServers: []
skills: []
plugins: []
---
Synthetic offline discovery only.
'''
CHECK = '''
import json, os, pathlib, socket, sys
hidden, host_netns, home = sys.argv[1:]
socket_blocked = False
try:
    with socket.create_connection(('127.0.0.1', 8000), timeout=1):
        pass
except OSError:
    socket_blocked = True
print(json.dumps({
    'host_canary_hidden': not pathlib.Path(hidden).exists(),
    'synthetic_home_visible': (pathlib.Path(home) / 'union-fake-home').read_text() == 'FAKE',
    'network_namespace_changed': os.readlink('/proc/self/ns/net') != host_netns,
    'host_preview_unreachable': socket_blocked,
    'windows_mount_hidden': not pathlib.Path('/mnt/c').exists(),
}))
'''


def namespace(root, host_home):
    # HOME retains its original value; only its mount in this child is replaced
    # with a freshly created empty tree. Existing home content is never bound.
    return [
        '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/bin', '/bin',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--bind', str(root / 'home'), host_home,
        '--bind', str(root / 'work'), '/work',
        '--ro-bind', str(root / 'etc'), '/etc',
        '--clearenv', '--setenv', 'HOME', host_home,
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '--chdir', '/work',
    ]


async def probe():
    report = dict(scope='Offline metadata only; not model tool enumeration or provider PASS',
                  model_calls=0, existing_credentials_mounted=False, live_ready=False, cases=[])
    host_home = os.environ.get('HOME', '')
    if not Path('/usr/bin/bwrap').is_file() or not host_home.startswith('/home/'):
        return {**report, 'error': 'unsupported_probe_environment'}
    with tempfile.TemporaryDirectory(prefix='union-offline-') as temp:
        root = Path(temp)
        for folder in ('home', 'work', 'etc'):
            (root / folder).mkdir()
        (root / 'home/union-fake-home').write_text('FAKE')
        hidden = root / 'outside-canary'
        hidden.write_text('FAKE')
        (root / 'etc/passwd').write_text(
            f'union-probe:x:{os.getuid()}:{os.getgid()}:Offline probe:{host_home}:/bin/bash\n')
        (root / 'etc/group').write_text(f'union-probe:x:{os.getgid()}:\n')
        # Resolve only loopback inside this network namespace. This enables local
        # CLI IPC without exposing DNS, host services, or provider networks.
        (root / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
        (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
        base = namespace(root, host_home)
        try:
            raw = await execute(base + ['/usr/bin/python3', '-I', '-c', CHECK,
                                        str(hidden), os.readlink('/proc/self/ns/net'), host_home],
                                '', '/tmp', timeout=10, limit=32768)
            checks = json.loads(raw)
            expected = {'host_canary_hidden', 'synthetic_home_visible',
                        'network_namespace_changed', 'host_preview_unreachable',
                        'windows_mount_hidden'}
            if not isinstance(checks, dict) or set(checks) != expected or any(v is not True for v in checks.values()):
                return {**report, 'error': 'namespace_checks_failed'}
            report['isolation'] = checks
        except (RunnerError, OSError, ValueError):
            return {**report, 'error': 'namespace_unavailable'}

        if CODEX.is_file():
            for restricted in (False, True):
                args = base + ['--ro-bind', str(CODEX), '/cli/codex', '/cli/codex', 'features', 'list']
                if restricted:
                    for feature in FEATURES:
                        args += ['--disable', feature]
                case = {'name': 'codex_flags_disabled' if restricted else 'codex_flags_defaults'}
                try:
                    raw = await execute(args, '', '/tmp', timeout=15, limit=32768)
                    rows = {parts[0]: parts[-1] for line in raw.decode().splitlines() if (parts := line.split())}
                    flags = {key: rows.get(key) for key in FEATURES}
                    if any(v not in ('true', 'false') for v in flags.values()):
                        raise ValueError('unknown_feature_output')
                    case.update(status='observed', flags={key: value == 'true' for key, value in flags.items()})
                    if restricted and any(case['flags'].values()):
                        case.update(status='blocked', error='disable_not_effective')
                except (RunnerError, OSError, ValueError) as exc:
                    case.update(status='blocked', error=exc.code if isinstance(exc, RunnerError) else 'probe_failed')
                report['cases'].append(case)
        else:
            report['cases'].append(dict(name='codex_flags', status='blocked', error='cli_missing'))

        # This config belongs only to our synthetic home; no user config is read.
        settings = root / 'home/.gemini/antigravity-cli/settings.json'
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({'permissions': {'deny': [
            f'{action}(*)' for action in ('read_file', 'write_file', 'read_url', 'execute_url', 'command', 'unsandboxed', 'mcp')
        ]}, 'useG1Credits': False, 'enableTelemetry': False}))
        definition = root / 'work/.agents/agents/union-offline/agent.md'
        definition.parent.mkdir(parents=True)
        definition.write_text(AGENT)
        global_definition = root / 'home/.gemini/config/agents/union-global/agent.md'
        global_definition.parent.mkdir(parents=True)
        global_definition.write_text(AGENT.replace('union-offline', 'union-global'))
        case = {'name': 'agy_offline_agent_discovery'}
        try:
            raw = await execute(base + ['--ro-bind', str(AGY), '/cli/agy', '/cli/agy', 'agent'],
                                '', '/tmp', timeout=15, limit=32768)
            listed = set(raw.decode().splitlines())
            local_found = 'union-offline' in listed
            global_found = 'union-global' in listed
            case.update(status='observed' if global_found else 'blocked',
                        workspace_agent_found=local_found, synthetic_global_agent_found=global_found,
                        tool_policy_enforcement_verified=False)
            if not global_found:
                case['error'] = 'synthetic_agent_not_listed'
        except (RunnerError, OSError) as exc:
            case.update(status='blocked', error=exc.code if isinstance(exc, RunnerError) else 'probe_failed')
        report['cases'].append(case)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New sanitized evidence file; never overwrite')
    args = parser.parse_args()
    report = asyncio.run(probe())
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        with args.output.open('x') as target:
            target.write(serialized)
    print(serialized, end='')
    return 2 if report.get('error') or any(case['status'] == 'blocked' for case in report['cases']) else 0


if __name__ == '__main__':
    raise SystemExit(main())

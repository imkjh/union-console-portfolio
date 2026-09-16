"""Internal offline fixture worker. Run only via codex_protocol_probe.py.

The HTTP endpoint is a synthetic in-namespace responder, never a live provider.
Only sanitized tool names, rejection classes, and fake-file observations leave it.
"""
import asyncio
import ctypes
import json
import os
import re
from pathlib import Path
import struct
import threading
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

from runner.process import execute, RunnerError
from runner.parsers import codex_jsonl

from codex_policy import FLAGS, BASE_OPTIONS, ROOT_DENY_OPTIONS

SENTINEL = 'UNION_FAKE_READ_CANARY_A91'
STATE = {}
TLS_ALERTS = []
SYNTHETIC_OAUTH = os.environ.get('UNION_PROBE_SYNTHETIC_OAUTH') == '1'


def tool_names(items):
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('invalid_tool_inventory')
        if item.get('type') == 'namespace':
            result.extend(tool_names(item.get('tools', [])))
        else:
            result.append(item.get('name', item.get('type', 'unknown')))
    return result


class FixtureHTTPServer(HTTPServer):
    def get_request(self):
        try:
            return super().get_request()
        except ssl.SSLError as exc:
            if exc.reason in {'TLSV1_ALERT_UNKNOWN_CA', 'SSLV3_ALERT_BAD_CERTIFICATE', 'SSLV3_ALERT_CERTIFICATE_UNKNOWN'}:
                TLS_ALERTS.append(exc.reason)
            raise


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_error(404)

    def do_POST(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 2097152 or self.headers.get('Content-Encoding'):
                raise ValueError('invalid_body')
            data = json.loads(self.rfile.read(size))
            if self.path not in {'/v1/responses', '/v1/codex/responses'} or len(STATE['requests']) >= 3:
                raise ValueError('unexpected_request')
            inputs = data.get('input', [])
            # This installed build puts tool schemas in input.additional_tools;
            # a missing root tools field must NOT be interpreted as zero tools.
            inventory = list(data.get('tools', []))
            for item in inputs:
                if item.get('type') == 'additional_tools':
                    inventory.extend(item['tools'])
                if item.get('type') in ('function_call_output', 'custom_tool_call_output'):
                    output = json.dumps(item.get('output', ''))
                    STATE['canary_in_tool_output'] |= SENTINEL in output
                    STATE['tool_result_received'] = True
                    # Fixed diagnostic vocabulary only: never persist raw tool output.
                    vocabulary = {'read', 'blocked', 'filesystem', 'policy', 'permissions',
                                  'denied', 'operation', 'permitted', 'error', 'outside',
                                  'sandbox', 'file', 'directory', 'no', 'such', 'exist',
                                  'disabled', 'failed', 'permission', 'available', 'not',
                                  'path', 'allowed', 'cannot', 'access', 'write', 'expected',
                                  'find', 'lines', 'parse', 'parsing', 'validation', 'rejected'}
                    STATE['tool_output_terms'] = sorted(vocabulary.intersection(re.findall(r'[a-z]+', output.lower())))
                    STATE['os_error_numbers'] = [int(n) for n in re.findall(r'os error (\d+)', output.lower())]
                    for marker, category in (
                        ('unsupported', 'unsupported_tool'),
                        ('read-only sandbox', 'read_only_write_denied'),
                        ('not a function', 'unavailable_nested_tool'),
                        ('not defined', 'unavailable_runtime_binding'),
                        ('permission denied', 'permission_denied'),
                        ('access denied', 'access_denied'),
                        ('not allowed', 'policy_denied'),
                        ('operation not permitted', 'operation_not_permitted'),
                        ('read is blocked', 'read_denied'),
                        ('parsing', 'invalid_tool_call'),
                        ('unknown tool', 'unknown_tool'),
                        ('not found', 'not_found'),
                        ('unrecognized', 'unrecognized_call'),
                        ('unexpected', 'unexpected_call'),
                        ('unknown', 'unknown_call'),
                        ('missing', 'missing_call_field'),
                        ('disabled', 'disabled_tool'),
                        ('not enabled', 'disabled_tool'),
                        ('not available', 'unavailable_tool'),
                        ('unavailable', 'unavailable_tool'),
                        ('cannot handle', 'unhandled_tool'),
                    ):
                        if marker in output.lower():
                            STATE['rejections'].append(category)
            STATE['requests'].append({
                'model': data.get('model'), 'tool_names': tool_names(inventory),
                'auth_header_present': 'Authorization' in self.headers,
                'expected_synthetic_auth': (self.headers.get('Authorization') == 'Bearer UNION_FAKE_ACCESS'
                                            if SYNTHETIC_OAUTH else 'Authorization' not in self.headers),
                'synthetic_account_header': self.headers.get('chatgpt-account-id') == 'union-fake-account',
                'tls_active': isinstance(self.connection, ssl.SSLSocket),
            })
        except (ValueError, TypeError, KeyError):
            STATE['error'] = 'invalid_protocol_request'
            self.send_error(400)
            return
        if len(STATE['requests']) == 1 and STATE['call']:
            item = STATE['call']
        else:
            item = {'id': 'msg_offline', 'type': 'message', 'role': 'assistant',
                    'content': [{'type': 'output_text', 'text': 'UNION_OFFLINE_OK', 'annotations': []}],
                    'status': 'completed'}
        response = {'id': 'resp_offline', 'object': 'response', 'status': 'completed',
                    'output': [item], 'usage': {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0}}
        events = [
            {'type': 'response.created', 'response': {'id': 'resp_offline', 'object': 'response', 'status': 'in_progress', 'output': []}},
            {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
            {'type': 'response.completed', 'response': response},
        ]
        body = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n' for e in events).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def watch_canary():
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise RuntimeError('canary_watch_unavailable')
    if libc.inotify_add_watch(fd, b'/work/read-canary', 0x1 | 0x20) < 0:
        os.close(fd)
        raise RuntimeError('canary_watch_unavailable')
    return fd


def read_watch(fd):
    accessed, opened = False, False
    try:
        while True:
            try:
                events = os.read(fd, 8192)
            except BlockingIOError:
                break
            if not events:
                break
            offset = 0
            while offset < len(events):
                _, mask, _, length = struct.unpack_from('iIII', events, offset)
                accessed |= bool(mask & 0x1)
                opened |= bool(mask & 0x20)
                offset += 16 + length
    finally:
        os.close(fd)
    return {'canary_accessed': accessed, 'canary_opened': opened}


def function(name, args):
    return {'id': 'fc_offline', 'type': 'function_call', 'call_id': 'call_offline',
            'name': name, 'arguments': json.dumps(args)}


def code(source):
    return {'id': 'fc_offline', 'type': 'custom_tool_call', 'call_id': 'call_offline',
            'name': 'exec', 'input': source}


async def main():
    # The outer harness supplies this marker after checking the offline namespace.
    if not Path('/work/namespace-verified').is_file():
        raise RuntimeError('outer_probe_required')
    auth_fixture = {'enabled': SYNTHETIC_OAUTH}
    if SYNTHETIC_OAUTH:
        try:
            diagnostic = '''import json,os,re,subprocess
r=subprocess.run(['/cli/codex','login','status'],env={'HOME':os.environ['HOME'],'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},capture_output=True,timeout=8)
words=set(re.findall(r'[a-z_]+',(r.stdout+r.stderr).decode(errors='replace').lower()))
allowed={'invalid','missing','field','id_token','email','decode','jwt','parse','signature','auth','file','not','logged','in','failed','keyring','unsupported','chatgpt','token','error','credentials'}
print(json.dumps({'official_status_exit_zero':r.returncode==0,'diagnostic_terms':sorted(words & allowed)}))
'''
            observed = await execute(['/usr/bin/env', 'HOME=' + os.environ['HOME'], '/usr/bin/python3', '-I', '-c', diagnostic],
                          '', '/work', timeout=10, limit=8192)
            auth_fixture.update(json.loads(observed))
        except RunnerError:
            auth_fixture['official_status_exit_zero'] = False
        try:
            with (Path.home() / '.codex/auth.json').open('ab'):
                pass
            auth_fixture['read_only_mount_enforced'] = False
        except OSError:
            auth_fixture['read_only_mount_enforced'] = True
        if not auth_fixture.get('official_status_exit_zero') or not auth_fixture.get('read_only_mount_enforced'):
            print(json.dumps({'error': 'synthetic_auth_not_recognized', 'auth_fixture': auth_fixture}))
            return
    catalog = await execute(['/cli/codex', 'debug', 'models', '--bundled'], '', '/work', timeout=10, limit=4194304)
    Path('/work/catalog.json').write_bytes(catalog)
    Path('/work/read-canary').write_text(SENTINEL)
    Path('/work/read-link').symlink_to('/work/read-canary')
    os.link('/work/read-canary', '/work/read-hardlink')
    Path('/work/subdir').mkdir()
    # A harmless fake notifier/MCP must never start from ignored user config.
    config = Path.home() / '.codex/config.toml'
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('notify = ["/usr/bin/python3", "/work/config-canary.py"]\n'
                      '[mcp_servers.union_fake]\ncommand = "/usr/bin/python3"\nargs = ["/work/config-canary.py"]\n')
    Path('/work/config-canary.py').write_text('from pathlib import Path\nPath("/work/config-started").write_text("FAKE")\n')
    server = FixtureHTTPServer(('127.0.0.1', 0), Handler)
    if SYNTHETIC_OAUTH:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain('/work/fixture-cert.pem', '/work/fixture-key.pem')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    endpoint = f'{"https" if SYNTHETIC_OAUTH else "http"}://127.0.0.1:{port}/v1'
    command = function('exec_command', {'cmd': '/usr/bin/cat /work/read-canary', 'max_output_tokens': 100})
    patch = {'id': 'fc_offline', 'type': 'custom_tool_call', 'call_id': 'call_offline', 'name': 'apply_patch',
             'input': '*** Begin Patch\n*** Add File: /work/write-canary\n+FAKE_WRITE\n*** End Patch'}
    patch_read = {**patch, 'input': '*** Begin Patch\n*** Update File: /work/read-canary\n@@\n-UNION_NONMATCHING\n+FAKE_WRITE\n*** End Patch'}
    cases = [
        ('baseline_read', False, command), ('restricted_answer', True, None),
        ('restricted_exec', True, command), ('restricted_patch', True, patch),
        ('restricted_patch_read', True, patch_read),
        ('restricted_image', True, function('view_image', {'path': '/work/read-canary'})),
        ('restricted_mcp', True, function('read_mcp_resource', {'server': 'union_fake', 'uri': 'fake://canary'})),
        ('restricted_read_file', True, function('read_file', {'file_path': '/work/read-canary', 'offset': 1, 'limit': 10})),
        ('restricted_grep', True, function('grep_files', {'path': '/work/read-canary', 'pattern': '.', 'limit': 1})),
        ('restricted_list', True, function('list_dir', {'dir_path': '/work', 'depth': 1})),
        ('restricted_web', True, function('web.run', {'search_query': [{'q': 'offline fixture'}]})),
        ('restricted_stdin', True, function('write_stdin', {'session_id': 0, 'chars': ''})),
        ('explicit_deny_patch_read', True, patch_read),
        ('restricted_code_exec', True, code('text(await tools.exec_command({cmd:"/usr/bin/cat /work/read-canary"}));')),
        ('restricted_code_patch_read', True, code('text(await tools.apply_patch(' + json.dumps(patch_read['input']) + '));')),
        ('explicit_deny_code_patch_read', True, code('text(await tools.apply_patch(' + json.dumps(patch_read['input']) + '));')),
        ('restricted_code_require', True, code('text(require("fs").readFileSync("/work/read-canary", "utf8"));')),
    ]
    path_variants = dict((
        ('absolute', '/work/read-canary'), ('relative', 'read-canary'),
        ('parent', '/work/subdir/../read-canary'),
        ('symlink', '/work/read-link'), ('hardlink', '/work/read-hardlink'),
        ('proc_alias', '/proc/self/cwd/read-canary'),
    ))
    for label, path in path_variants.items():
        cases.append(('baseline_path_' + label, False,
                      function('exec_command', {'cmd': '/usr/bin/cat ' + path, 'max_output_tokens': 100})))
    cases += [('root_deny_answer', True, None)]
    for label, path in path_variants.items():
        cases.append(('root_deny_' + label, True,
                      {**patch_read, 'input': patch_read['input'].replace('/work/read-canary', path)}))
    cases.append(('root_deny_write', True, patch))
    if os.environ.get('UNION_PROBE_SMOKE') == '1':
        cases = [case for case in cases if case[0] == 'root_deny_answer']
    reports = []
    seen_threads = set()
    try:
        for label, restricted, call in cases:
            STATE.clear()
            STATE.update(call=call, requests=[], canary_in_tool_output=False,
                         tool_result_received=False, rejections=[])
            argv = ['/cli/codex', 'exec', *BASE_OPTIONS,
                    '-c', 'model_provider="union_probe"', '-c',
                    f'model_providers.union_probe={{name="Union offline fixture",base_url="{endpoint}",wire_api="responses",request_max_retries=0,stream_max_retries=0,requires_openai_auth={str(SYNTHETIC_OAUTH).lower()},supports_websockets=false}}',
                    ]
            if SYNTHETIC_OAUTH:
                argv += ['-c', f'chatgpt_base_url="{endpoint}"']
            if label.startswith('root_deny_'):
                argv += ROOT_DENY_OPTIONS
            elif label.startswith('explicit_deny_'):
                argv += ['-c', 'default_permissions="union_probe"', '-c',
                         'permissions.union_probe={extends=":read-only",filesystem={"/work/read-canary"="deny"}}']
            else:
                argv += ['-s', 'read-only']
            for flag in FLAGS:
                if restricted or flag not in ('shell_tool', 'unified_exec', 'view_image'):
                    argv += ['--disable', flag]
            # Preserve the existing HOME value in the already isolated child.
            argv = ['/usr/bin/env', 'HOME=' + os.environ['HOME']] + argv
            if SYNTHETIC_OAUTH:
                argv.insert(2, 'CODEX_CA_CERTIFICATE=/work/fixture-ca.pem')
                argv.insert(2, 'SSL_CERT_FILE=/work/fixture-ca.pem')
            report = {'case': label}
            variant = label.removeprefix('root_deny_')
            if variant in path_variants:
                target = Path(path_variants[variant])
                report['target_exists_outside_cli'] = target.is_file()
                report['target_matches_canary_inode'] = target.stat().st_ino == Path('/work/read-canary').stat().st_ino
            watch = watch_canary()
            try:
                raw = await execute(argv + ['-'], 'UNION_OFFLINE_PROTOCOL_CANARY', '/work', timeout=25, limit=65536)
                report['completion_seen'] = b'UNION_OFFLINE_OK' in raw
                report['installed_cli_parser_matches_fixture'] = codex_jsonl(raw) == 'UNION_OFFLINE_OK'
                events = [json.loads(line) for line in raw.splitlines() if line.strip()]
                ids = [event.get('thread_id') for event in events if event.get('type') == 'thread.started']
                report['fresh_cli_thread'] = len(ids) == 1 and isinstance(ids[0], str) and ids[0] not in seen_threads
                seen_threads.update(value for value in ids if isinstance(value, str))
            except (RunnerError, OSError) as exc:
                report['error'] = exc.code if isinstance(exc, RunnerError) else 'probe_failed'
                if SYNTHETIC_OAUTH and not reports:
                    diagnostic = '''import json,re,subprocess,sys
r=subprocess.run(sys.argv[1:],input=b'UNION_OFFLINE_PROTOCOL_CANARY',capture_output=True,timeout=12)
output=(r.stdout+r.stderr).decode(errors='replace').lower()
words=set(re.findall(r'[a-z_]+',output))
allowed={'certificate','unknown','issuer','self','signed','tls','ssl','invalid','connect','connection','refused','root','ca','file','permission','failed','denied','builder','client','error','unsupported','decode','pem','empty','bundled','not','found','rustls','native','certs','certificates','crypto','provider','loaded','loading','load','roots','der','process','handshake','stream','request','refresh','access','token','expired','unauthorized','key','status','initialize','start','secure','https','tcp','url','such','directory','create','required','read','system','internal','os','environment','variable','path','host','account','auth','config','configuration','format'}
keys={a.partition('=')[0] for a in sys.argv[1:] if '=' in a and a.startswith(('agents.','otel.','history.','analytics.','feedback.','approval_policy','model_','permissions.','default_permissions','tools.'))}
print(json.dumps({'exit_code':r.returncode,'diagnostic_terms':sorted(words & allowed),'unknown_fields':re.findall('unknown field .([a-z_]+)',output),'config_key_mentions':sorted(k for k in keys if k in output)}))
'''
                    try:
                        raw_diag = await execute(['/usr/bin/python3', '-I', '-c', diagnostic] + argv + ['-'],
                                                 '', '/work', timeout=15, limit=8192)
                        auth_fixture['transport_diagnostic'] = json.loads(raw_diag)
                    except RunnerError:
                        auth_fixture['transport_diagnostic'] = {'error': 'diagnostic_unavailable'}
            finally:
                report.update(read_watch(watch))
            report.update({k: v for k, v in STATE.items() if k != 'call'})
            report['write_side_effect'] = Path('/work/write-canary').exists()
            report['config_process_started'] = Path('/work/config-started').exists()
            common_ok = (report.get('completion_seen') and not report.get('error')
                         and report.get('installed_cli_parser_matches_fixture') and report.get('fresh_cli_thread')
                         and bool(report['requests'])
                         and not report['write_side_effect'] and not report['config_process_started']
                         and all(r['model'] == 'gpt-6-astra' and r['expected_synthetic_auth'] for r in report['requests']))
            if SYNTHETIC_OAUTH:
                common_ok = common_ok and all(r['tls_active'] and r['synthetic_account_header'] for r in report['requests'])
            if not restricted:
                ok = common_ok and report['canary_accessed'] and report['canary_in_tool_output']
            else:
                ok = common_ok and not report['canary_opened'] and not report['canary_accessed'] and not report['canary_in_tool_output']
                if call:
                    boundary_rejections = {'unsupported_tool', 'read_only_write_denied',
                                           'permission_denied', 'unavailable_nested_tool',
                                           'unavailable_runtime_binding', 'disabled_tool',
                                           'access_denied', 'policy_denied',
                                           'operation_not_permitted', 'read_denied'}
                    ok = ok and report['tool_result_received'] and bool(boundary_rejections.intersection(report['rejections']))
                    # ENOENT alone is not security evidence. Require a successful
                    # exact-path positive control and an extant matching inode.
                    masked = (variant in path_variants and report.get('os_error_numbers') == [2]
                              and report.get('target_exists_outside_cli')
                              and report.get('target_matches_canary_inode')
                              and any(r['case'] == 'baseline_path_' + variant and r['status'] == 'PASS'
                                      for r in reports))
                    if masked:
                        report['rejections'].append('path_hidden_under_root_deny')
                        ok = (common_ok and report['tool_result_received']
                              and not report['canary_opened'] and not report['canary_accessed']
                              and not report['canary_in_tool_output'])
            report['status'] = 'PASS' if ok else 'BLOCKED'
            reports.append(report)
        if SYNTHETIC_OAUTH:
            # Same running HTTPS fixture, OAuth and CLI options; remove only the
            # disposable CA. A certificate failure must not send HTTP credentials.
            STATE.clear()
            STATE.update(call=None, requests=[], canary_in_tool_output=False,
                         tool_result_received=False, rejections=[])
            untrusted = [arg for arg in argv if not arg.startswith(('CODEX_CA_CERTIFICATE=', 'SSL_CERT_FILE='))]
            rejected = False
            TLS_ALERTS.clear()
            try:
                await execute(untrusted + ['-'], 'UNION_OFFLINE_PROTOCOL_CANARY', '/work', timeout=15, limit=65536)
            except RunnerError as exc:
                auth_fixture['untrusted_cli_error'] = exc.code
                rejected = True
            auth_fixture['untrusted_certificate_alerts'] = list(TLS_ALERTS)
            auth_fixture['untrusted_http_requests'] = len(STATE['requests'])
            auth_fixture['untrusted_tls_rejected_before_http'] = rejected and bool(TLS_ALERTS) and not STATE['requests']
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    # Inspect only the newly created synthetic CLI home, never a real auth store.
    residue = {'scope': 'synthetic CLI home only', 'files_checked': 0, 'matches': [], 'incomplete': []}
    for path in (Path.home() / '.codex').rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        relative = str(path.relative_to(Path.home()))
        if path.stat().st_size > 8 * 1024 * 1024 or residue['files_checked'] >= 1000:
            residue['incomplete'].append(relative)
            continue
        raw = path.read_bytes()
        residue['files_checked'] += 1
        markers = [kind for kind, value in [('prompt', b'UNION_OFFLINE_PROTOCOL_CANARY'),
                   ('response', b'UNION_OFFLINE_OK'), ('canary', SENTINEL.encode())] if value in raw]
        if markers:
            residue['matches'].append({'path': relative, 'marker_types': markers})
    residue['status'] = 'PASS' if not residue['matches'] and not residue['incomplete'] else 'BLOCKED'
    print(json.dumps({'cases': reports, 'synthetic_residue': residue, 'auth_fixture': auth_fixture,
                      'real_model_calls': 0, 'live_ready': False}))


if __name__ == '__main__':
    asyncio.run(main())

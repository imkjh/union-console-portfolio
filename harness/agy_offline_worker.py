"""Synthetic OAuth/HTTPS responder inside an offline namespace, never a proxy."""
import json
import os
from pathlib import Path
import ssl
import selectors
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import agy_bootstrap_worker as observer
except ModuleNotFoundError:
    from harness import agy_bootstrap_worker as observer

REQUESTS = []
HOSTS = frozenset(('accounts.google.com', 'oauth2.googleapis.com', 'www.googleapis.com',
                  'antigravity.google', 'daily-cloudcode-pa.googleapis.com',
                  'lh3.googleusercontent.com', 'play.googleapis.com'))
TLS = None
REQUEST_LOCK = threading.Lock()
PUBLIC_PATHS = frozenset(('/oauth2/v2/userinfo', '/v1internal:loadCodeAssist',
    '/v1internal:fetchAdminControls', '/v1internal:fetchUserInfo',
    '/v1internal:retrieveUserQuotaSummary', '/v1internal:fetchAvailableModels',
    '/v1internal:listExperiments', '/v1internal:writeTrajectoryAcls',
    '/v1internal:tabChat', '/log', '/v1internal:streamGenerateContent',
    '/v1internal:generateContent'))


def public_path(path):
    # Fixed public paths; no dynamic/private path or query is retained.
    return path if path in PUBLIC_PATHS else None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        # Terminate synthetic TLS locally; never connect or forward anywhere.
        if self.path not in {host + ':443' for host in HOSTS}:
            self.send_error(403)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.flush()
        self.connection = TLS.wrap_socket(self.connection, server_side=True)
        self.connection.settimeout(5)
        self.rfile = self.connection.makefile('rb')
        self.wfile = self.connection.makefile('wb')
        self.close_connection = True
        self.handle_one_request()

    def reply(self):
        # All clients and tokens are synthetic and external networking is absent.
        # Still retain only fixed categories/counts, never request bodies/headers.
        path = self.path.split('?', 1)[0]
        known = ('userinfo', 'oauth', 'token', 'loadCodeAssist', 'fetchUserInfo',
                 'retrieveUserQuota', 'streamGenerateContent', 'generateContent')
        category = next((name for name in known if name.lower() in path.lower()), 'other')
        with REQUEST_LOCK:
            if len(REQUESTS) >= 64:
                self.send_error(429)
                return
            REQUESTS.append({'method': self.command, 'category': category,
                             'public_binary_path': public_path(path),
                             'json_request': 'json' in self.headers.get('Content-Type', '')})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = -1
        if self.headers.get('Transfer-Encoding') or not 0 <= length <= 1048576:
            self.send_error(413)
            return
        self.rfile.read(length)
        data = {'id': 'union-offline-user', 'sub': 'union-offline-user',
                'email': 'offline@invalid.test', 'email_verified': True,
                'verified_email': True, 'name': 'Union synthetic user'}
        if path == '/v1internal:loadCodeAssist':
            data = {'cloudaicompanionProject': 'union-offline-project',
                    'currentTier': {'id': 'standard-tier', 'name': 'Synthetic fixture'}}
        elif path == '/v1internal:fetchAvailableModels':
            data = {'models': {
                'gemini-3.1-pro-high': {'displayName': 'Gemini 3.1 Pro (High)',
                    'model': 'MODEL_GOOGLE_GEMINI_2_5_PRO', 'modelProvider': 'MODEL_PROVIDER_GOOGLE',
                    'apiProvider': 'API_PROVIDER_GOOGLE_GEMINI',
                    'vertexModelId': 'gemini-3.1-pro-high',
                    'modelUrl': 'gemini-3.1-pro-high',
                    'toolFormatterType': 'TOOL_FORMATTER_TYPE_NONE',
                    'maxTokens': 32000, 'maxOutputTokens': 1024},
                'claude-sonnet-4-6': {'displayName': 'Claude Sonnet 4.6',
                    'model': 'MODEL_PLACEHOLDER_M1', 'modelProvider': 'MODEL_PROVIDER_ANTHROPIC',
                    'maxTokens': 32000, 'maxOutputTokens': 1024}},
                'defaultAgentModelId': 'gemini-3.1-pro-high',
                'agentModelSorts': [{'displayName': 'Synthetic fixture',
                    'groups': [{'displayName': 'Synthetic fixture',
                                'modelIds': ['gemini-3.1-pro-high', 'claude-sonnet-4-6']}]}]}
        elif path == '/v1internal:listExperiments':
            data = {'experiments': []}
        elif path == '/v1internal:retrieveUserQuotaSummary':
            data = {'buckets': []}
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = reply
    do_POST = reply


def dispatch(env, *, send_question):
    """One fixed synthetic question; bounded output and runtime, no approvals."""
    argv = ['/cli/agy', '--input-format', 'stream-json', '--output-format', 'stream-json',
            '--agent', 'union-settings', '--model', 'gemini-3.1-pro-high',
            '--disable-slash-commands', '--sandbox', '--log-file', '/dev/stderr', '--print-timeout', '8s']
    message = (json.dumps({'event': 'user', 'message': {'content':
        'Synthetic fixture test. Reply with UNION_OFFLINE_OK.'}}) + '\n').encode()
    if not send_question:
        message = b''
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    streams = selectors.DefaultSelector()
    buffers = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    limited = timed_out = False
    try:
        proc.stdin.write(message)
        proc.stdin.close()
        for stream in buffers:
            streams.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + 11
        while streams.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, _ in streams.select(0.1):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                target = buffers[key.fileobj]
                if len(target) + len(chunk) > 65536:
                    limited = True
                    break
                target.extend(chunk)
            if limited:
                break
    finally:
        streams.close()
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1)
    out, err = bytes(buffers[proc.stdout]), bytes(buffers[proc.stderr])
    proc.stdout.close()
    proc.stderr.close()
    result = observer.summarize(out, err, proc.returncode, limited, timed_out)
    result['stdin_bytes'] = len(message)
    diagnostic = (out + err).decode(errors='replace').lower()
    result['fixture_diagnostics'] = sorted(label for label in
        ('unsupported', 'unimplemented', 'model not found', 'invalid model', 'quota',
         'permission denied', 'missing', 'failed to parse', 'unknown model',
         'panic', 'permission', 'unmarshal', 'http 404', 'no user status', 'no model')
        if label in diagnostic)
    print(json.dumps(result))


def main(args=None):
    global TLS
    args = sys.argv[1:] if args is None else args
    if args not in ([], ['--dispatch']):
        raise ValueError('unsupported_fixture_mode')
    if not Path('/work/namespace-verified').is_file():
        raise SystemExit('offline_namespace_required')
    server = ThreadingHTTPServer(('127.0.0.1', 8080), Handler)
    TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    TLS.load_cert_chain('/work/fixture-cert.pem', '/work/fixture-key.pem')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        environment = {**observer.startup_environment(),
                       'SSL_CERT_FILE': '/work/fixture-cert.pem',
                       'HTTPS_PROXY': 'http://127.0.0.1:8080'}
        dispatch(environment, send_question=bool(args))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    print(json.dumps({'synthetic_requests': REQUESTS, 'real_model_calls': 0,
                      'existing_credentials_mounted': False,
                      'policy_enforcement_verified': False}))


if __name__ == '__main__':
    main()

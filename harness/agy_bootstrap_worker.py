"""Offline startup observer: stdin is EOF; emit only allowlisted metadata."""
import json
import os
import re
import resource
import sys
import selectors
import subprocess
import time


def dns_names(diagnostic):
    # DNS is case-insensitive; a final dot denotes the same absolute name.
    return {host.lower().rstrip('.') for host in
            re.findall(r'\blookup ([A-Za-z0-9.-]+)(?=[:\s]|$)', diagnostic)}


def dns_families(diagnostic):
    """Fixed suffix labels only. Never emit an unknown account/tenant hostname.

    This is observation, not proof of ownership or permission to connect.
    """
    suffixes = ('googleapis.com', 'google.com', 'googleusercontent.com',
                'gstatic.com', 'google', 'goog', 'run.app', 'azureedge.net', 'sentry.io')
    families = set()
    for host in dns_names(diagnostic) - KNOWN_DNS_HOSTS:
        family = next((suffix for suffix in suffixes
                       if host == suffix or host.endswith('.' + suffix)), None)
        families.add(family or ('single_label' if '.' not in host else 'other'))
    return sorted(families)


def embedded_dns_hosts(diagnostic, binary='/cli/agy'):
    """Only disclose unknown DNS names also present in the public CLI binary.

    This never reads the authentication cache and never changes egress policy.
    Dynamic/private names not found in the binary stay undisclosed.
    """
    candidates = {host.encode('ascii') for host in dns_names(diagnostic)
                  if host not in KNOWN_DNS_HOSTS and 3 <= len(host) <= 253
                  and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', host)}
    if not candidates:
        return []
    found = set()
    try:
        # Bounded streaming: do not load a large executable into memory.
        with open(binary, 'rb') as source:
            if os.fstat(source.fileno()).st_size > 512 * 1024 * 1024:
                return []
            tail = b''
            while chunk := source.read(65536):
                block = tail + chunk
                found.update(host for host in candidates if host in block)
                if found == candidates:
                    break
                tail = block[-253:]
    except OSError:
        return []
    return sorted(host.decode('ascii') for host in found)

AUTH_DIAGNOSTICS = {
    'keyring_token_load_failed': 'keyringAuth: failed to load stored token:',
    'keyring_token_invalid': 'keyringAuth: saved token invalid:',
    'keyring_userinfo_failed': 'keyringAuth: failed to fetch user info:',
    'keyring_oauth_params_failed': 'keyringAuth: failed to get oauth params:',
    'keyring_email_claim_missing': 'keyringAuth: no email claim in stored ID token:',
    'keyring_token_loaded': 'keyringAuth: loaded token,',
    'token_json_invalid': 'failed to unmarshal token:',
    'network_unreachable': 'network is unreachable',
    'dns_unavailable': 'no such host',
    'oauth_token_fetch_failed': 'oauth2: cannot fetch token:',
    'read_only_write_denied': 'read-only file system',
}

# Observation labels only, NOT additions to the outbound firewall allowlist.
KNOWN_DNS_HOSTS = frozenset({
    'accounts.google.com', 'oauth2.googleapis.com', 'www.googleapis.com',
    'antigravity.google', 'antigravity.google.com', 'auth.cloud.google',
    'oauth2.mtls.googleapis.com', 'www.mtls.googleapis.com',
    'cloudcode-pa.googleapis.com', 'daily-cloudcode-pa.googleapis.com',
    'antigravity-unleash.goog',
    'play.googleapis.com', 'playwright.azureedge.net',
    'playwright-akamai.azureedge.net', 'playwright-verizon.azureedge.net',
    'autopush-cloudcode-pa.sandbox.googleapis.com',
    'preprod-daily-cloudcode-pa.sandbox.googleapis.com',
    'agentaicode.googleapis.com', 'businessaicode.googleapis.com',
    'sts.googleapis.com', 'iamcredentials.googleapis.com',
    'www.google.com', 'www.gstatic.com', 'storage.googleapis.com',
    # Public Google Sign-In codelab picture host; observation only, no egress grant.
    'lh3.googleusercontent.com',
})
KNOWN_WRITE_TARGETS = {
    'oauth_cache': '/.gemini/antigravity-cli/antigravity-oauth-token',
    'candidate_settings': '/.gemini/antigravity-cli/settings.json',
    'browser_driver': '/disabled-browser',
}
BLOCKED_BROWSER_PATH = '/disabled-browser'

# Fixed cause labels scoped to one native auth log line. Never export its text.
AUTH_CAUSES = {
    'unknown_auth_method': 'unknown auth method',
    'dns_unavailable': 'no such host',
    'read_only_write_denied': 'read-only file system',
    'file_missing': 'no such file or directory',
    'executable_missing': 'executable file not found',
    'permission_denied': 'permission denied',
    'connection_refused': 'connection refused',
    'network_unreachable': 'network is unreachable',
    'deadline_exceeded': 'context deadline exceeded',
    'language_server': 'language server',
    'secret_service': 'org.freedesktop.secrets',
    'invalid_json': 'invalid character',
}


def auth_failure_context(diagnostic):
    contexts = []
    for code, marker in AUTH_DIAGNOSTICS.items():
        if not code.startswith('keyring_') or code == 'keyring_token_loaded':
            continue
        # Same-line association only, not proof of root cause or a cross-line guess.
        tails = [line.split(marker, 1)[1] for line in diagnostic.splitlines() if marker in line]
        if tails:
            contexts.append({'stage': code,
                             'causes': sorted({cause for tail in tails for cause, text in AUTH_CAUSES.items()
                                               if text in tail.lower()}),
                             'boundary': boundary_diagnostics('\n'.join(tails))})
    return contexts


def startup_environment():
    """Do not let Playwright prepare a driver in the writable temporary HOME."""
    if os.path.lexists(BLOCKED_BROWSER_PATH) or not (os.statvfs('/').f_flag & os.ST_RDONLY):
        raise ValueError('browser_boundary_unverified')
    return {'HOME': os.environ['HOME'], 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
            'PLAYWRIGHT_DRIVER_PATH': BLOCKED_BROWSER_PATH}


def boundary_diagnostics(diagnostic):
    """Classify known names/paths without exporting URLs, paths or error text."""
    dns = dns_names(diagnostic)
    writes = set()
    unknown_write = False
    for line in diagnostic.splitlines():
        if 'read-only file system' not in line:
            continue
        matched = {label for label, suffix in KNOWN_WRITE_TARGETS.items()
                   if re.search(re.escape(suffix) + r'(?=[:\s\"\']|$)', line)}
        writes.update(matched)
        unknown_write |= not bool(matched)
    return {'dns_failed_known_hosts': sorted(dns & KNOWN_DNS_HOSTS),
            'unknown_dns_host_seen': bool(dns - KNOWN_DNS_HOSTS),
            'read_only_targets': sorted(writes),
            'unclassified_read_only_failure': unknown_write}


def summarize(stdout, stderr, exit_code, limited=False, timed_out=False):
    report = {'stdin_bytes': 0, 'exit_code': exit_code, 'output_limited': limited,
              'timed_out': timed_out, 'init_seen': False, 'tool_registry_observed': False,
              'policy_enforcement_verified': False}
    for line in stdout.decode(errors='replace').splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get('event') == 'init':
            report['init_seen'] = True
            init = event.get('init', {})
            if isinstance(init, dict):
                report['requested_agent_reported'] = init.get('agent') == 'union-settings'
                report['requested_model_reported'] = init.get('model') == 'gemini-3.1-pro-high'
                report['review_permission_mode_reported'] = init.get('permission_mode') == 'request-review'
            names = init.get('tools') if isinstance(init, dict) else None
            if isinstance(names, list) and all(isinstance(n, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,80}', n) for n in names):
                known = {'ask_permission', 'run_command', 'write_to_file', 'read_file', 'read_url',
                         'view_file', 'list_dir', 'find_by_name', 'grep_search', 'replace_file_content',
                         'multi_replace_file_content', 'search_web', 'browser_subagent'}
                report.update(tool_registry_observed=True, tool_count=len(names),
                              known_tool_names=sorted(set(names) & known),
                              unknown_tool_count=sum(n not in known for n in names))
        result = event.get('result', event)
        if isinstance(result, dict):
            if isinstance(result.get('status'), str) and result['status'] in {'SUCCESS', 'ERROR', 'CANCELED', 'INTERRUPTED'}:
                report['result_status'] = result['status']
            if type(result.get('num_turns')) is int:
                report['num_turns'] = result['num_turns']
            if result.get('status') == 'ERROR' and isinstance(result.get('error'), str):
                error = result['error'].lower()
                markers = {
                    'authentication_required': 'authentication required',
                    'unauthenticated': 'unauthenticated',
                    'permission_denied': 'permission denied',
                    'no_prompt': 'no prompt', 'no_input': 'no input',
                    'no_user_message': 'no user message',
                    'initialization_failed': 'failed to initialize',
                    'startup_failed': 'failed to start',
                    'invalid_model': 'invalid model', 'unknown_model': 'unknown model',
                    'dns_unavailable': 'no such host',
                    'deadline_exceeded': 'deadline exceeded',
                    'connection_refused': 'connection refused',
                    'download': 'download', 'model_listing': 'list models',
                    'user_info': 'user info', 'oauth': 'oauth',
                    'profile_picture': 'profile picture',
                }
                report['result_error'] = {
                    'known_causes': sorted(code for code, text in markers.items() if text in error),
                    'boundary': boundary_diagnostics(result['error']),
                    'unknown_dns_families': dns_families(result['error']),
                    'embedded_dns_hosts': embedded_dns_hosts(result['error'])}
    diagnostic = stderr.decode(errors='replace')
    report['auth_diagnostics'] = sorted(code for code, message in AUTH_DIAGNOSTICS.items() if message in diagnostic)
    expiry_flags = set(re.findall(r'keyringAuth: loaded token, [^\r\n]{0,256}? expired=(true|false)\b', diagnostic))
    if len(expiry_flags) == 1:
        report['cached_token_expired'] = expiry_flags.pop() == 'true'
    words = set(re.findall(r'[a-z]+', diagnostic.lower()))
    report['diagnostic_terms'] = sorted(words & {'authentication', 'required', 'login', 'credentials',
                                                 'network', 'refused', 'connect', 'denied', 'invalid', 'settings',
                                                 'json', 'unmarshal', 'token', 'expired', 'refresh', 'parse'})
    report['boundary_diagnostics'] = boundary_diagnostics(diagnostic)
    report['auth_failure_context'] = auth_failure_context(diagnostic)
    return report


def main(args=None):
    args = [] if args is None else args
    try:
        if args not in ([], ['--cache-write'], ['--native-startup'], ['--native-startup', '--cache-write']):
            raise ValueError('unsupported_worker_mode')
        env = startup_environment()
        if '--cache-write' in args:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    except (OSError, ValueError, KeyError):
        print(json.dumps({'error': 'browser_boundary_unverified', 'stdin_bytes': 0,
                          'init_seen': False, 'policy_enforcement_verified': False}))
        return
    argv = ['/cli/agy', '--input-format', 'stream-json', '--output-format', 'stream-json',
            '--agent', 'union-settings', '--model', 'gemini-3.1-pro-high',
            '--disable-slash-commands', '--sandbox', '--log-file', '/dev/stderr', '--print-timeout', '3s']
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env)
    streams = selectors.DefaultSelector()
    for stream in (proc.stdout, proc.stderr):
        streams.register(stream, selectors.EVENT_READ)
    buffers = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    limit = False
    timed_out = False
    deadline = time.monotonic() + (15 if '--native-startup' in args else 6)
    try:
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
                    limit = True
                    break
                target.extend(chunk)
            if limit:
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
    print(json.dumps(summarize(bytes(buffers[proc.stdout]), bytes(buffers[proc.stderr]), proc.returncode, limit, timed_out)))


if __name__ == '__main__':
    main(sys.argv[1:])

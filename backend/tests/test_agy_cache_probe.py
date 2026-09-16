import json
import pytest
from harness import agy_cache_probe as cache
from harness import agy_settings_probe as startup
from harness.agy_bootstrap_worker import summarize, AUTH_DIAGNOSTICS, boundary_diagnostics


def test_review_does_not_mount_credentials_or_launch_cli(monkeypatch, capsys):
    monkeypatch.setattr(cache, 'review', lambda: {'model_calls': 0})
    monkeypatch.setattr(cache.sys, 'argv', ['agy_cache_probe.py'])
    def forbidden(*args):
        raise AssertionError('review cannot start a CLI')
    monkeypatch.setattr(cache, 'run_once', forbidden)
    assert cache.main() == 0
    assert json.loads(capsys.readouterr().out) == {'model_calls': 0}


def test_profile_flag_without_execute_only_reviews(monkeypatch, capsys):
    monkeypatch.setattr(cache.sys, 'argv', ['agy_cache_probe.py', '--native-network', '--allow-profile-host'])
    monkeypatch.setattr(cache, 'review', lambda **kwargs: kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError('review must not launch CLI')
    monkeypatch.setattr(cache, 'run_once', forbidden)
    assert cache.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        'native_network': True, 'allow_profile_host': True, 'allow_cache_write': False}


@pytest.mark.parametrize('plan', [{}, {'allow_profile_host': False},
                                {'allow_profile_host': True, 'network_policy': {'hosts': ['evil.invalid']}}])
async def test_profile_execution_requires_matching_review(monkeypatch, plan):
    async def forbidden(**kwargs):
        raise AssertionError('unreviewed destination cannot launch CLI')
    monkeypatch.setattr(cache, 'probe', forbidden)
    result = await cache.run_once(plan, native_network=True, allow_profile_host=True)
    assert result['error'] == 'profile_host_review_required'


async def test_profile_host_requires_native_mode_before_any_execution(monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError('invalid options cannot launch')
    monkeypatch.setattr(startup, 'limited_execute', forbidden)
    with pytest.raises(ValueError, match='profile_host_requires_native_review'):
        await startup.probe(allow_profile_host=True)


@pytest.mark.parametrize('plan', [{}, {'tested_cli_matches': False, 'cache_regular_file': True},
                                   {'tested_cli_matches': True, 'cache_regular_file': False}])
async def test_preflight_failure_prevents_cache_mount(monkeypatch, plan):
    async def forbidden(**kwargs):
        raise AssertionError('unverified cache or binary must not be mounted')
    monkeypatch.setattr(cache, 'probe', forbidden)
    assert (await cache.run_once(plan))['error'] == 'preflight_blocked'


def test_report_does_not_echo_unknown_tool_or_error_content():
    marker = 'PRIVATE_SYNTHETIC_MARKER'
    stdout = json.dumps({'event': 'init', 'init': {'tools': ['run_command', marker], 'cwd': marker}}).encode()
    result = summarize(stdout, (marker + ' authentication required').encode(), 1)
    assert marker not in json.dumps(result)
    assert result['tool_count'] == 2
    assert result['unknown_tool_count'] == 1
    assert result['known_tool_names'] == ['run_command']
    assert result['diagnostic_terms'] == ['authentication', 'required']


@pytest.mark.parametrize('matches', [True, False])
def test_selected_agent_metadata_never_grants_policy_or_echoes_values(matches):
    marker = 'PRIVATE_SELECTION'
    init = {'agent': 'union-settings' if matches else marker,
            'model': 'gemini-3.1-pro-high' if matches else marker,
            'permission_mode': 'request-review' if matches else marker,
            'tools': ['run_command', 'view_file']}
    report = summarize(json.dumps({'event': 'init', 'init': init}).encode(), b'', 0)
    assert report['requested_agent_reported'] is matches
    assert report['requested_model_reported'] is matches
    assert report['review_permission_mode_reported'] is matches
    assert report['policy_enforcement_verified'] is False
    assert report['tool_count'] == 2
    assert marker not in json.dumps(report)


def test_terminal_error_is_distinguished_from_stderr_without_echoing_values():
    event = {'event': 'result', 'result': {'status': 'ERROR', 'num_turns': 0,
             'error': 'no user message PRIVATE_VALUE'}}
    result = summarize(json.dumps(event).encode(), b'lookup play.googleapis.com: no such host', 1)
    assert result['result_error']['known_causes'] == ['no_user_message']
    assert result['result_error']['boundary']['dns_failed_known_hosts'] == []
    assert 'PRIVATE_VALUE' not in json.dumps(result)


def test_picture_dns_observation_does_not_grant_network_or_disclose_url():
    from harness.network_guard import AGY_HOSTS
    raw = ('failed to get profile picture: Get "https://lh3.googleusercontent.com/'
           'PRIVATE_ACCOUNT_PATH?token=PRIVATE_VALUE": lookup lh3.googleusercontent.com: no such host')
    report = summarize(json.dumps({'result': {'status': 'ERROR', 'error': raw}}).encode(), b'', 1)
    assert report['result_error']['known_causes'] == ['dns_unavailable', 'profile_picture']
    assert report['result_error']['boundary']['dns_failed_known_hosts'] == ['lh3.googleusercontent.com']
    assert 'PRIVATE' not in json.dumps(report)
    assert 'lh3.googleusercontent.com' not in AGY_HOSTS
    lookalike = boundary_diagnostics('lookup lh3.googleusercontent.com.evil: no such host')
    assert lookalike['dns_failed_known_hosts'] == []
    assert lookalike['unknown_dns_host_seen'] is True


def test_unknown_dns_only_disclosed_if_present_in_public_binary(tmp_path):
    from harness.agy_bootstrap_worker import embedded_dns_hosts
    binary = tmp_path / 'public-fixture'
    binary.write_bytes(b'x' * 65530 + b'https://public-fixture.example/path')
    diagnostic = ('lookup public-fixture.example: no such host\n'
                  'lookup private-account.example: no such host\n')
    assert embedded_dns_hosts(diagnostic, binary) == ['public-fixture.example']
    assert embedded_dns_hosts(diagnostic, tmp_path / 'missing') == []


@pytest.mark.parametrize('code,message', list(AUTH_DIAGNOSTICS.items()))
def test_auth_diagnostic_emits_code_without_values(code, message):
    marker = 'PRIVATE_SYNTHETIC_AUTH_VALUE'
    report = summarize(b'', (message + marker).encode(), 1)
    assert report['auth_diagnostics'] == [code]
    assert marker not in json.dumps(report)
    assert report['policy_enforcement_verified'] is False


@pytest.mark.parametrize('status', [[], {}, None, 1])
def test_unknown_status_type_does_not_escape_report(status):
    report = summarize(json.dumps({'result': {'status': status}}).encode(), b'', 1)
    assert 'result_status' not in report


@pytest.mark.parametrize('flag', ['true', 'false'])
def test_expiry_metadata_never_copies_timestamp_or_token(flag):
    marker = 'PRIVATE_SYNTHETIC_VALUE'
    raw = f'keyringAuth: loaded token, expiry={marker} expired={flag}'
    report = summarize(b'', raw.encode(), 1)
    assert report['cached_token_expired'] is (flag == 'true')
    assert marker not in json.dumps(report)


def test_unrelated_or_conflicting_expiry_is_not_reported():
    for raw in [b'other logger expired=true',
                b'keyringAuth: loaded token, expiry=FAKE expired=true\nkeyringAuth: loaded token, expiry=FAKE expired=false']:
        assert 'cached_token_expired' not in summarize(b'', raw, 1)


def test_native_network_flag_alone_only_reviews(monkeypatch, capsys):
    monkeypatch.setattr(cache.sys, 'argv', ['agy_cache_probe.py', '--native-network'])
    monkeypatch.setattr(cache, 'review', lambda **kwargs: {'native_review': kwargs.get('native_network')})
    def forbidden(*args, **kwargs):
        raise AssertionError('network review cannot execute')
    monkeypatch.setattr(cache, 'run_once', forbidden)
    assert cache.main() == 0
    assert json.loads(capsys.readouterr().out) == {'native_review': True}


@pytest.mark.parametrize('plan,flag', [({}, True), ({'mode': 'offline_cache_review'}, True),
                                    ({'mode': 'native_auth_review', 'external_network': 'true'}, True), ({}, 'true')])
async def test_network_cannot_be_added_to_offline_plan(monkeypatch, plan, flag):
    async def forbidden(**kwargs):
        raise AssertionError('unreviewed network cannot start')
    monkeypatch.setattr(cache, 'probe', forbidden)
    assert (await cache.run_once(plan, native_network=flag))['error'] == 'network_review_required'


@pytest.mark.parametrize('options', [
    {}, {'inspect_help': True}, {'inspect_bootstrap': True},
    {'inspect_bootstrap': True, 'fake_login': 'oauth-shaped', 'existing_cache': '/not-used'},
])
async def test_network_mode_rejects_unrelated_startup(monkeypatch, options):
    async def forbidden(*args, **kwargs):
        raise AssertionError('invalid network mode cannot launch a process')
    monkeypatch.setattr(startup, 'limited_execute', forbidden)
    with pytest.raises(ValueError, match='unsupported_network_probe'):
        await startup.probe(native_network=True, **options)


def test_boundary_diagnostics_only_export_fixed_labels():
    raw = ('lookup oauth2.googleapis.com: no such host\n'
           'lookup private.synthetic.example: no such host\n'
           'open /home/PRIVATE/.gemini/antigravity-cli/settings.json: read-only file system\n'
           'open /home/PRIVATE/.gemini/antigravity-cli/antigravity-oauth-token: read-only file system\n'
           'open /PRIVATE/unknown: read-only file system')
    report = boundary_diagnostics(raw)
    assert report == {'dns_failed_known_hosts': ['oauth2.googleapis.com'],
                      'unknown_dns_host_seen': True,
                      'read_only_targets': ['candidate_settings', 'oauth_cache'],
                      'unclassified_read_only_failure': True}
    assert 'PRIVATE' not in json.dumps(report)
    assert 'private.synthetic' not in json.dumps(report)


def test_dns_observer_normalizes_names_without_revealing_private_labels():
    from harness.agy_bootstrap_worker import dns_families
    raw = ('lookup OAUTH2.GOOGLEAPIS.COM.: no such host\n'
           'lookup private-account.googleapis.com: no such host\n'
           'lookup googleapis.com.evil.invalid: no such host\n'
           'lookup private-machine: no such host')
    assert boundary_diagnostics(raw)['dns_failed_known_hosts'] == ['oauth2.googleapis.com']
    assert dns_families(raw) == ['googleapis.com', 'other', 'single_label']
    report = summarize(json.dumps({'result': {'status': 'ERROR', 'error': raw}}).encode(), b'', 1)
    assert report['result_error']['unknown_dns_families'] == ['googleapis.com', 'other', 'single_label']
    for private in ('private-account', 'evil.invalid', 'private-machine'):
        assert private not in json.dumps(report)


@pytest.mark.parametrize('lookalike', ['oauth2.googleapis.com.evil', 'prefix.oauth2.googleapis.com'])
def test_dns_lookalikes_do_not_become_known_hosts(lookalike):
    report = boundary_diagnostics('lookup ' + lookalike + ': no such host')
    assert report['dns_failed_known_hosts'] == []
    assert report['unknown_dns_host_seen'] is True
    assert lookalike not in json.dumps(report)


def test_unrelated_or_similar_paths_are_not_classified_as_credential_writes():
    report = boundary_diagnostics('open /tmp/settings.json: read-only file system\n'
                                 'open /x/.gemini/antigravity-cli/antigravity-oauth-token.backup: read-only file system')
    assert report['read_only_targets'] == []
    assert report['unclassified_read_only_failure'] is True


def test_auth_and_permission_claims_remain_unverified_after_diagnostics():
    report = summarize(b'', b'lookup auth.cloud.google: no such host', 1)
    assert report['boundary_diagnostics']['dns_failed_known_hosts'] == ['auth.cloud.google']
    assert report['policy_enforcement_verified'] is False
    assert report['init_seen'] is False


def test_browser_download_observation_does_not_expand_network_policy():
    from harness.network_guard import AGY_HOSTS
    hosts = ['play.googleapis.com', 'playwright.azureedge.net',
             'playwright-akamai.azureedge.net', 'playwright-verizon.azureedge.net']
    report = boundary_diagnostics('\n'.join('lookup ' + host + ': no such host' for host in hosts))
    assert report['dns_failed_known_hosts'] == sorted(hosts)
    assert report['unknown_dns_host_seen'] is False
    assert set(hosts).isdisjoint(AGY_HOSTS)


@pytest.mark.parametrize('existing,read_only', [(True, True), (False, False), (True, False)])
def test_browser_boundary_fails_before_cli_launch(monkeypatch, capsys, existing, read_only):
    from harness import agy_bootstrap_worker as worker
    from types import SimpleNamespace
    monkeypatch.setattr(worker.os.path, 'lexists', lambda _: existing)
    monkeypatch.setattr(worker.os, 'statvfs', lambda _: SimpleNamespace(f_flag=worker.os.ST_RDONLY if read_only else 0))
    def forbidden(*args, **kwargs):
        raise AssertionError('no CLI before browser boundary is established')
    monkeypatch.setattr(worker.subprocess, 'Popen', forbidden)
    worker.main()
    assert json.loads(capsys.readouterr().out)['error'] == 'browser_boundary_unverified'


def test_startup_environment_ignores_parent_browser_overrides(monkeypatch):
    from harness import agy_bootstrap_worker as worker
    from types import SimpleNamespace
    monkeypatch.setattr(worker.os.path, 'lexists', lambda _: False)
    monkeypatch.setattr(worker.os, 'statvfs', lambda _: SimpleNamespace(f_flag=worker.os.ST_RDONLY))
    monkeypatch.setenv('HOME', '/home/union')
    monkeypatch.setenv('PLAYWRIGHT_DRIVER_PATH', '/tmp/unsafe')
    monkeypatch.setenv('PLAYWRIGHT_NODEJS_PATH', '/tmp/unsafe-node')
    monkeypatch.setenv('PLAYWRIGHT_DOWNLOAD_HOST', 'https://untrusted.invalid')
    assert worker.startup_environment() == {'HOME': '/home/union', 'PATH': '/usr/bin:/bin',
        'LANG': 'C.UTF-8', 'PLAYWRIGHT_DRIVER_PATH': '/disabled-browser'}


def test_browser_write_failure_is_distinct_from_auth_cache():
    report = boundary_diagnostics('could not create driver directory: mkdir /disabled-browser: read-only file system')
    assert report['read_only_targets'] == ['browser_driver']
    assert report['unclassified_read_only_failure'] is False


def test_auth_context_does_not_attribute_unrelated_network_or_write_errors():
    raw = (b'keyringAuth: failed to get oauth params: permission denied PRIVATE_VALUE\n'
           b'lookup play.googleapis.com: no such host\n'
           b'mkdir /disabled-browser: read-only file system')
    report = summarize(b'', raw, 1)
    context, = report['auth_failure_context']
    assert context['stage'] == 'keyring_oauth_params_failed'
    assert context['causes'] == ['permission_denied']
    assert context['boundary']['dns_failed_known_hosts'] == []
    assert context['boundary']['read_only_targets'] == []
    assert 'PRIVATE_VALUE' not in json.dumps(report)


def test_auth_context_retains_only_known_same_line_causes():
    raw = (b'keyringAuth: failed to get oauth params: lookup oauth2.googleapis.com: no such host PRIVATE_VALUE\n'
           b'keyringAuth: failed to get oauth params: unrecognized PRIVATE_VALUE\n'
           b'keyringAuth: failed to fetch user info: lookup secret.invalid: no such host')
    context = summarize(b'', raw, 1)['auth_failure_context']
    by_stage = {entry['stage']: entry for entry in context}
    assert by_stage['keyring_oauth_params_failed']['boundary']['dns_failed_known_hosts'] == ['oauth2.googleapis.com']
    assert by_stage['keyring_userinfo_failed']['boundary']['unknown_dns_host_seen'] is True
    assert 'PRIVATE_VALUE' not in json.dumps(context)
    assert 'secret.invalid' not in json.dumps(context)


def test_unknown_auth_cause_does_not_become_a_diagnosis():
    context, = summarize(b'', b'keyringAuth: saved token invalid: PRIVATE_VALUE', 1)['auth_failure_context']
    assert context['causes'] == []


def test_unknown_auth_method_is_not_reported_as_dns_or_account_expiry():
    report = summarize(b'', b'keyringAuth: failed to get oauth params: unknown auth method: PRIVATE_VALUE', 1)
    context, = report['auth_failure_context']
    assert context['causes'] == ['unknown_auth_method']
    assert context['boundary']['dns_failed_known_hosts'] == []
    assert 'cached_token_expired' not in report
    assert 'PRIVATE_VALUE' not in json.dumps(report)


@pytest.mark.parametrize('native,plan', [(False, {}), (True, {}),
    (True, {'allow_cache_write': True, 'writable_cache_safe': False})])
async def test_cache_write_cannot_be_added_to_read_only_review(monkeypatch, native, plan):
    async def forbidden(**kwargs):
        raise AssertionError('no credential access without write review')
    monkeypatch.setattr(cache, 'probe', forbidden)
    result = await cache.run_once(plan, native_network=native, allow_cache_write=True)
    assert result['error'] == 'cache_write_review_required'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public', 'directory', 'empty'])
def test_writable_binding_rejects_unsafe_file_metadata(tmp_path, kind):
    target = tmp_path / 'cache'
    target.write_text('FAKE')
    target.chmod(0o600)
    if kind == 'symlink':
        alias = tmp_path / 'alias'
        alias.symlink_to(target)
        target = alias
    elif kind == 'hardlink':
        (tmp_path / 'alias').hardlink_to(target)
    elif kind == 'public':
        target.chmod(0o644)
    elif kind == 'directory':
        target = tmp_path
    elif kind == 'empty':
        target.write_text('')
    with pytest.raises(ValueError):
        startup.cache_binding(target, writable=True)


def test_worker_rejects_unknown_write_mode_before_cli(monkeypatch, capsys):
    from harness import agy_bootstrap_worker as worker
    def forbidden(*args, **kwargs):
        raise AssertionError('unknown options must not launch CLI')
    monkeypatch.setattr(worker.subprocess, 'Popen', forbidden)
    worker.main(['--write-home'])
    assert json.loads(capsys.readouterr().out)['error'] == 'browser_boundary_unverified'


@pytest.mark.parametrize('name,expected', [('agy', True), ('python3', False)])
def test_protected_process_metadata_uses_name_for_concurrency_check(monkeypatch, tmp_path, name, expected):
    process = tmp_path / '123'
    process.mkdir()
    (process / 'comm').write_text(name + '\n')
    def protected(*args):
        raise PermissionError(13, 'protected synthetic process')
    monkeypatch.setattr(cache.os, 'readlink', protected)
    assert cache.active_agy(tmp_path) is expected

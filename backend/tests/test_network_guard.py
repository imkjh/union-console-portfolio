"""Policy rejection and integration tests; no real credentials/network."""
import json
from pathlib import Path
import pytest
from harness import network_guard as guard
from harness import network_worker as worker
from harness import agy_settings_probe as startup


def test_service_endpoint_is_exact_and_does_not_open_other_observed_hosts():
    assert set(guard.AGY_HOSTS) == {'accounts.google.com', 'oauth2.googleapis.com',
        'www.googleapis.com', 'antigravity.google', 'daily-cloudcode-pa.googleapis.com'}
    assert 'play.googleapis.com' not in guard.AGY_HOSTS


def test_picture_review_is_an_exact_opt_in_profile():
    assert guard.hosts_for('agy') == guard.AGY_HOSTS
    assert guard.hosts_for('agy-profile-review') == (*guard.AGY_HOSTS, 'lh3.googleusercontent.com')
    assert 'lh3.googleusercontent.com' not in guard.hosts_for('agy')
    assert 'play.googleapis.com' not in guard.hosts_for('agy-profile-review')


def test_provider_profiles_cannot_merge_or_accept_user_endpoints(monkeypatch, tmp_path):
    queried = []
    def lookup(host, *args):
        queried.append(host)
        return [(0, 0, 0, '', ('8.8.8.8', 443))]
    monkeypatch.setattr(guard.socket, 'getaddrinfo', lookup)
    assert set(guard.resolve_hosts('codex')) == {'chatgpt.com', 'auth.openai.com'}
    assert queried == ['chatgpt.com.', 'auth.openai.com.']
    assert 'api.openai.com' not in guard.CODEX_HOSTS
    for provider in ('*', 'https://evil.invalid', 'codex,agy'):
        with pytest.raises(ValueError, match='unsupported_network_provider'):
            guard.guarded_command(['/usr/bin/bwrap', '--unshare-all'], tmp_path, provider=provider)


@pytest.mark.parametrize('values', [[], ['127.0.0.1'], ['10.0.0.1'], ['169.254.169.254'],
    ['192.168.1.1'], ['100.64.0.1'], ['::1'], ['2606:4700::1111'], ['0.0.0.0'],
    ['224.0.0.1'], ['142.250.1.1; accept'], ['142.250.1.1', '10.0.0.1'], ['8.8.8.8'] * 65])
def test_reject_unsafe_destinations(values):
    with pytest.raises(ValueError):
        guard.rules_for(values)


def test_dns_private_answer_prevents_launch(monkeypatch):
    monkeypatch.setattr(guard.socket, 'getaddrinfo', lambda *args: [(0, 0, 0, '', ('127.0.0.1', 443))])
    with pytest.raises(ValueError):
        guard.resolve_google()


@pytest.mark.parametrize('command', [[], ['/bin/bash'],
    ['/usr/bin/bwrap', '--share-net', '--unshare-all'],
    ['/usr/bin/bwrap', '--unshare-all', '--netns', '3']])
def test_reject_existing_network_sharing(command, tmp_path):
    with pytest.raises(ValueError, match='isolated_bwrap_required'):
        guard.guarded_command(command, tmp_path)


def test_missing_dependencies_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(guard, 'dependencies_verified', lambda: False)
    with pytest.raises(ValueError, match='network_dependencies_unverified'):
        guard.guarded_command(['/usr/bin/bwrap', '--unshare-all'], tmp_path)


def test_child_cannot_install_rules_on_host(monkeypatch):
    monkeypatch.setattr(worker.os, 'readlink', lambda _: 'host-net')
    def forbidden(*args, **kwargs):
        raise AssertionError('host firewall must never be touched')
    monkeypatch.setattr(worker.subprocess, 'run', forbidden)
    with pytest.raises(ValueError, match='private_network_required'):
        worker.child(['host-net', '8', '9', '["8.8.8.8"]', '/unused', '--',
                      '/usr/bin/bwrap', '--unshare-all'])


@pytest.mark.parametrize('guard_ready', [True, False])
@pytest.mark.parametrize('writable', [True, False])
@pytest.mark.parametrize('profile_host', [True, False])
async def test_agy_online_bootstrap_always_uses_guard(monkeypatch, tmp_path, guard_ready, writable, profile_host):
    home = '/home/union'
    cache = Path(home) / '.gemini/antigravity-cli/antigravity-oauth-token'
    cli = tmp_path / 'fake-agy'
    cli.write_text('FAKE')
    cli.chmod(0o600)
    monkeypatch.setenv('HOME', home)
    monkeypatch.setattr(startup, 'AGY', cli)
    original_stat = Path.stat
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **kw: original_stat(cli if p == cache else p, *a, **kw))
    calls = []
    def wrap(command, fixture, *, provider='agy'):
        assert provider == ('agy-profile-review' if profile_host else 'agy')
        if not guard_ready:
            raise ValueError('network_dependencies_unverified')
        assert '--share-net' not in command
        assert '/etc/resolv.conf' not in command
        assert command[command.index(str(cache)) - 1] == ('--bind' if writable else '--ro-bind')
        assert ('--cache-write' in command) is writable
        (fixture / 'network-boundary.json').write_text('{"private_namespace":true}')
        calls.append(command)
        return ['FILTERED', *command]
    async def fake_execute(command, *args, **kwargs):
        if command[0] == 'FILTERED':
            return b'{"stdin_bytes":0,"policy_enforcement_verified":false}'
        assert '--share-net' not in command
        return json.dumps({key: True for key in (
            'host_canary_hidden', 'synthetic_home_visible', 'network_namespace_changed',
            'host_preview_unreachable', 'windows_mount_hidden')}).encode()
    monkeypatch.setattr(startup, 'guarded_command', wrap)
    monkeypatch.setattr(startup, 'limited_execute', fake_execute)
    if not guard_ready:
        with pytest.raises(ValueError, match='network_dependencies_unverified'):
            await startup.probe(inspect_bootstrap=True, existing_cache=cache, native_network=True, allow_cache_write=writable, allow_profile_host=profile_host)
        assert calls == []
        return
    result = await startup.probe(inspect_bootstrap=True, existing_cache=cache, native_network=True, allow_cache_write=writable, allow_profile_host=profile_host)
    assert len(calls) == 1
    assert result['network_boundary']['private_namespace'] is True
    assert result['security_gate'] == 'BLOCKED'
    assert result['real_model_calls'] == 0
    assert result['network_policy']['hosts'] == list(guard.AGY_PROFILE_HOSTS if profile_host else guard.AGY_HOSTS)

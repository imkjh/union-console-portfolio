import hashlib
import io
import json
from unittest.mock import Mock

import pytest

from harness import agy_offline_probe as probe
from harness import agy_offline_worker as worker


def test_review_never_executes_cli(monkeypatch, capsys):
    monkeypatch.setattr(probe, 'probe', Mock(side_effect=AssertionError('no execution')))
    assert probe.main(['--dispatch']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['execution'] is False
    assert report['security_gate'] == 'BLOCKED'
    assert report['existing_credentials_mounted'] is False


async def test_changed_binary_stops_before_namespace(monkeypatch, tmp_path):
    binary = tmp_path / 'fake-binary'
    binary.write_bytes(b'synthetic')
    monkeypatch.setattr(probe, 'AGY', binary)
    monkeypatch.setattr(probe, 'limited_execute', Mock(side_effect=AssertionError('must stop')))
    assert await probe.probe() == {'error': 'installation_changed'}


@pytest.mark.parametrize('isolation_ok', [False, True])
async def test_isolation_gate_and_synthetic_only_mounts(monkeypatch, tmp_path, isolation_ok):
    binary = tmp_path / 'fake-binary'
    binary.write_bytes(b'synthetic')
    monkeypatch.setattr(probe, 'AGY', binary)
    monkeypatch.setattr(probe, 'TESTED_SHA256', hashlib.sha256(b'synthetic').hexdigest())
    monkeypatch.setattr(probe.subprocess, 'run', Mock())
    calls = []

    async def execute(command, prompt, **kwargs):
        calls.append(command)
        assert '--unshare-all' in command and '--share-net' not in command
        assert prompt == ''
        for i, word in enumerate(command):
            if word == '--ro-bind' and 'antigravity-oauth-token' in command[i + 1]:
                # Only a newly generated fixture tree, never the user's home.
                assert command[i + 1].startswith('/tmp/union-agy-offline-')
        if len(calls) == 1:
            return json.dumps(dict.fromkeys(('host_canary_hidden', 'synthetic_home_visible',
                'network_namespace_changed', 'host_preview_unreachable', 'windows_mount_hidden'), isolation_ok))
        assert command[-1] == '--dispatch'
        # Even a misleading worker success cannot open the provider gate.
        return json.dumps({'init_seen': True, 'policy_enforcement_verified': True})

    monkeypatch.setattr(probe, 'limited_execute', execute)
    result = await probe.probe(dispatch=True)
    if isolation_ok:
        assert len(calls) == 2
        assert result['security_gate'] == 'BLOCKED'
        assert result['existing_credentials_mounted'] is False
        assert result['external_network'] is False
    else:
        assert len(calls) == 1
        assert result == {'error': 'isolation_failed'}


def handler(path='/', headers=None):
    instance = object.__new__(worker.Handler)
    instance.path = path
    instance.command = 'POST'
    instance.headers = headers or {}
    instance.rfile = io.BytesIO()
    instance.wfile = io.BytesIO()
    instance.send_error = Mock()
    return instance


@pytest.mark.parametrize('destination', ['evil.invalid:443', 'www.googleapis.com.evil.invalid:443',
                                         'www.googleapis.com:80'])
def test_connect_never_forwards_unknown_authority(monkeypatch, destination):
    tls = Mock()
    monkeypatch.setattr(worker, 'TLS', tls)
    instance = handler(destination)
    instance.do_CONNECT()
    instance.send_error.assert_called_once_with(403)
    tls.wrap_socket.assert_not_called()


@pytest.mark.parametrize('headers', [{'Content-Length': '-1'}, {'Content-Length': 'not-a-number'},
                                     {'Content-Length': '1048577'}, {'Transfer-Encoding': 'chunked'}])
def test_invalid_or_unbounded_request_body_is_rejected(monkeypatch, headers):
    monkeypatch.setattr(worker, 'REQUESTS', [])
    instance = handler(headers=headers)
    instance.reply()
    instance.send_error.assert_called_once_with(413)


def test_request_limit_is_terminal(monkeypatch):
    monkeypatch.setattr(worker, 'REQUESTS', [{}] * 64)
    instance = handler()
    instance.reply()
    instance.send_error.assert_called_once_with(429)
    assert len(worker.REQUESTS) == 64


def test_observer_does_not_retain_dynamic_private_path_or_diagnostics():
    assert worker.public_path('/v1internal:fetchAvailableModels') is not None
    assert worker.public_path('/private-account/avatar/secret-value') is None
    probe.DIAGNOSTIC.clear()
    assert probe.classify(b'', b'PermissionError: private-value') == 'cli_failed'
    assert 'private-value' not in json.dumps(probe.DIAGNOSTIC)

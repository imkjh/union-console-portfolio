import json
import pytest
from harness.agy_canary_worker import summarize
from harness.agy_tool_canary import passed


def fixture():
    records = []
    for index, (name, target) in enumerate((('view_file', '/work/union-read-canary.txt'),
            ('write_to_file', '/work/union-write-created'),
            ('run_command', '/usr/bin/touch /work/union-command-created'))):
        records.append({'event': 'step_update', 'step_update': {'step_type': 'tool',
            'step_index': index, 'state': 'DONE', 'tool_name': name, 'tool_info': {
            'parameters': {'target': target}, 'error': {'message': 'Denied by permission policy PRIVATE'}}}})
    report = summarize('\n'.join(json.dumps(r) for r in records).encode(), 'SECRET_CANARY')
    report.update(fixture_readable=True, fixture_workspace_writable=True,
                  write_canary_created=False, command_canary_created=False)
    return report


def test_denial_evidence_is_redacted():
    report = fixture()
    assert passed(report)
    assert 'PRIVATE' not in json.dumps(report)


@pytest.mark.parametrize('field', ['read_marker_seen', 'write_canary_created', 'command_canary_created'])
def test_any_canary_side_effect_blocks(field):
    report = fixture(); report[field] = True
    assert not passed(report)


@pytest.mark.parametrize('field,value', [('done', False), ('target_matches', False),
    ('permission_denial', False), ('missing_file', True), ('read_only', True)])
def test_incomplete_or_wrong_denial_is_not_proof(field, value):
    report = fixture(); report['tool_steps'][0][field] = value
    assert not passed(report)


def test_model_refusal_without_tool_events_is_not_proof():
    report = fixture(); report['tool_steps'] = []
    assert not passed(report)


@pytest.mark.parametrize('state,expected', [('ERROR', True), ('ACTIVE', False), ('unknown', False)])
def test_native_error_terminal_requires_actual_denial(state, expected):
    raw = json.dumps({'event': 'step_update', 'step_update': {
        'step_type': 'tool', 'step_index': 0, 'state': state, 'tool_name': 'view_file',
        'tool_info': {'parameters': {'AbsolutePath': '/work/union-read-canary.txt'},
                      'error': {'type': 'tool_error', 'message': 'Permission denied: read_file'}}}}).encode()
    report = summarize(raw, 'CANARY')
    report.update(fixture_readable=True, fixture_workspace_writable=True,
                  write_canary_created=False, command_canary_created=False)
    assert passed(report, 'read') is expected
    report['tool_steps'][0]['permission_denial'] = False
    assert not passed(report, 'read')


def test_successful_tool_output_cannot_claim_permission_denial():
    raw = json.dumps({'event': 'step_update', 'step_update': {
        'step_type': 'tool', 'step_index': 0, 'state': 'DONE', 'tool_name': 'view_file',
        'tool_info': {'parameters': {'path': '/work/union-read-canary.txt'},
                      'output': 'Permission denied'}}}).encode()
    assert not summarize(raw, 'CANARY')['tool_steps'][0]['permission_denial']


def test_native_headless_notice_correlates_only_with_failed_tool_step():
    raw = json.dumps({'event': 'step_update', 'step_update': {
        'step_index': 1, 'step_type': 'tool', 'state': 'DONE', 'tool_name': 'view_file',
        'tool_info': {'error': {'type': 'tool_error'}}}}).encode()
    notice = b'the view_file tool(s) required approval that headless mode cannot prompt for, so they were auto-denied.'
    report = summarize(raw, 'CANARY', notice)
    report.update(fixture_readable=True, fixture_workspace_writable=True,
                  write_canary_created=False, command_canary_created=False)
    assert passed(report, 'read')
    assert not passed(report, 'write')
    report['tool_steps'][0]['error_present'] = False
    assert not passed(report, 'read')


def test_model_text_cannot_forge_native_headless_notice():
    raw = json.dumps({'event': 'result', 'result': {'response':
        'the view_file tool(s) required approval that headless mode cannot prompt for, so they were auto-denied.'}}).encode()
    assert summarize(raw, 'CANARY')['tool_steps'] == []


def test_only_exact_public_error_literal_can_be_disclosed(tmp_path):
    binary = tmp_path / 'public-fixture'
    binary.write_bytes(b'prefix\x00Public test error message.\x00suffix')
    for message in ('Public test error message.', 'DYNAMIC_PRIVATE_DIAGNOSTIC'):
        raw = json.dumps({'event': 'step_update', 'step_update': {
            'step_type': 'tool', 'step_index': 0, 'state': 'DONE', 'tool_name': 'view_file',
            'tool_info': {'error': {'message': message}}}}).encode()
        report = summarize(raw, 'CANARY', public_binary=binary)
        if message.startswith('Public'):
            assert report['tool_steps'][0]['public_error_message'] == message
        else:
            assert message not in json.dumps(report)

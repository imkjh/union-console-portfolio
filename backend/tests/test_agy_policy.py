import json
import pytest
from harness.agy_policy import candidate_settings, validated_settings
from backend.app.runners.process import RunnerError


def test_owned_candidate_is_valid_and_has_no_shared_mutable_grants():
    one = candidate_settings()
    assert json.loads(validated_settings(json.dumps(one))) == one
    one['permissions']['allow'].append('command(*)')
    assert candidate_settings()['permissions']['allow'] == []


@pytest.mark.parametrize('change', ['credits_true', 'credits_zero', 'credits_string', 'missing_credit',
                                   'missing_deny', 'grant', 'unknown', 'telemetry', 'sandbox'])
def test_reject_candidate_before_any_cli_can_use_it(change):
    config = candidate_settings()
    if change == 'credits_true': config['useG1Credits'] = True
    elif change == 'credits_zero': config['useG1Credits'] = 0
    elif change == 'credits_string': config['useG1Credits'] = 'false'
    elif change == 'missing_credit': del config['useG1Credits']
    elif change == 'missing_deny': config['permissions']['deny'].remove('read_file(*)')
    elif change == 'grant': config['permissions']['allow'] = ['command(*)']
    elif change == 'unknown': config['unrecognizedOverride'] = True
    elif change == 'telemetry': config['enableTelemetry'] = True
    else: config['enableTerminalSandbox'] = False
    with pytest.raises(RunnerError, match='unsafe_configuration'):
        validated_settings(json.dumps(config))


def test_duplicate_key_cannot_hide_an_enabled_credit_flag():
    raw = json.dumps(candidate_settings()).replace('"useG1Credits": false', '"useG1Credits": true, "useG1Credits": false')
    with pytest.raises(RunnerError, match='unsafe_configuration'):
        validated_settings(raw)

"""Strict candidate settings owned by Union probes, not provider security proof."""
import json
from backend.app.runners.process import RunnerError


def candidate_settings():
    return {
        'permissions': {'allow': [], 'ask': [], 'deny': [
            f'{action}(*)' for action in ('read_file', 'write_file', 'read_url',
                                          'execute_url', 'command', 'unsandboxed', 'mcp')]},
        'useG1Credits': False, 'enableTelemetry': False,
        'enableTerminalSandbox': True, 'allowNonWorkspaceAccess': False,
        'toolPermission': 'request-review', 'notifications': False,
        'showTips': False, 'showFeedbackSurvey': False,
    }


def validated_settings(raw):
    """Reject duplicate keys, wrong types, missing restrictions and added grants."""
    def unique(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise ValueError('duplicate_key')
            data[key] = value
        return data
    try:
        data = json.loads(raw, object_pairs_hook=unique)
        encoded = json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False)
        expected = json.dumps(candidate_settings(), sort_keys=True, separators=(',', ':'))
        if encoded != expected:
            raise ValueError('unexpected_configuration')
        return encoded
    except (ValueError, TypeError, UnicodeError):
        raise RunnerError('unsafe_configuration') from None

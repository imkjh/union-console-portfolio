"""Bounded output parsers for the registered Codex and candidate agy runners.

Codex matches this installation's JSONL under an offline Responses fixture and
actual subscription responses including the web adapter (2026-09-14).
agy remains synthetic and requires provider gates before registration.
agy follows https://antigravity.google/docs/cli/headless/ (2026-09-14).
"""
import json
from .process import RunnerError

RAW_LIMIT = 262144
ANSWER_LIMIT = 65536


def decode_output(raw):
    if len(raw) > RAW_LIMIT:
        raise RunnerError('output_limit')
    return raw.decode('utf-8')


def strict_json(text):
    # Last-key-wins decoding can turn a failed result into a success.
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError('non_finite_json_number')
    return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)


def checked_answer(answer):
    if not isinstance(answer, str) or not answer.strip():
        raise ValueError('empty_answer')
    if len(answer.encode('utf-8')) > ANSWER_LIMIT:
        raise RunnerError('output_limit')
    return answer


def codex_jsonl(raw):
    try:
        events=[strict_json(line) for line in decode_output(raw).splitlines() if line.strip()]
        if not events or any(not isinstance(e,dict) for e in events):
            raise ValueError()
        if any(e.get('type') in {'error','turn.failed'} for e in events):
            raise RunnerError('cli_failed')
        if events[-1].get('type')!='turn.completed':
            raise ValueError()
        if sum(e.get('type')=='turn.completed' for e in events)!=1:
            raise ValueError()
        answers=[e['item']['text'] for e in events if e.get('type')=='item.completed' and isinstance(e.get('item'),dict) and e['item'].get('type')=='agent_message']
        if not answers:
            raise ValueError()
        return checked_answer(answers[-1])
    except (ValueError,KeyError,TypeError,UnicodeError,RecursionError):
        raise RunnerError('invalid_output') from None


def agy_json(raw):
    try:
        data=strict_json(decode_output(raw))
        if not isinstance(data,dict):
            raise ValueError()
        status = data.get('status')
        if status in {'CANCELED', 'INTERRUPTED'}:
            raise RunnerError('cancelled')
        if status == 'ERROR' or data.get('error'):
            raise RunnerError('cli_failed')
        if status != 'SUCCESS':
            raise ValueError()
        # The MVP never resumes or sends a second prompt into a conversation.
        if type(data.get('num_turns')) is not int or data['num_turns'] != 1:
            raise ValueError()
        if not isinstance(data.get('conversation_id'), str) or not data['conversation_id'].strip():
            raise ValueError()
        result=data.get('response')
        return checked_answer(result)
    except (ValueError,KeyError,TypeError,UnicodeError,RecursionError):
        raise RunnerError('invalid_output') from None


def agy_stream_json(raw):
    """Extract one identified turn, not the last arbitrary JSON object."""
    try:
        events = [strict_json(line) for line in decode_output(raw).splitlines() if line.strip()]
        if any(not isinstance(event, dict) for event in events):
            raise ValueError()
        if len(events) < 2 or events[0].get('event') != 'init' or events[-1].get('event') != 'result':
            raise ValueError()
        conversation = events[0].get('conversation_id')
        if not isinstance(conversation, str) or not conversation.strip():
            raise ValueError()
        # Only one init/result envelope; every intermediate step belongs to it.
        for event in events[1:-1]:
            if event.get('event') != 'step_update':
                raise ValueError()
            step = event.get('step_update')
            if not isinstance(step, dict) or step.get('conversation_id') != conversation:
                raise ValueError()
        payload = events[-1].get('result')
        if not isinstance(payload, dict) or payload.get('conversation_id') != conversation:
            raise ValueError()
        return agy_json(json.dumps(payload, ensure_ascii=False).encode('utf-8'))
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise RunnerError('invalid_output') from None


def agy_stdin(prompt):
    """One documented stream-json message; use a new CLI process per call."""
    return (json.dumps({'event': 'user', 'message': {'content': prompt}}, ensure_ascii=False) + '\n').encode()

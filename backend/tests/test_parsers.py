import pytest
import json
from backend.app.runners.parsers import codex_jsonl, agy_json, agy_stream_json, agy_stdin
from backend.app.runners.process import RunnerError


def test_T08_synthetic_protocol_success():
    assert codex_jsonl(b'{"type":"item.completed","item":{"type":"agent_message","text":"synthetic"}}\n{"type":"turn.completed"}')=='synthetic'
    assert agy_json(b'{"conversation_id":"synthetic-id","status":"SUCCESS","num_turns":1,"response":"synthetic"}')=='synthetic'


@pytest.mark.parametrize('parser,raw,code',[
    (codex_jsonl,b'broken','invalid_output'),
    (codex_jsonl,b'{"type":"turn.completed"}','invalid_output'),
    (codex_jsonl,b'{"type":"item.completed","item":{"type":"agent_message","text":"x"}}','invalid_output'),
    (codex_jsonl,b'{"type":"turn.failed","error":"SYNTHETIC_PRIVATE_MARKER"}','cli_failed'),
    (agy_json,b'[]','invalid_output'),
    (agy_json,b'{"conversation_id":"synthetic-id","status":"SUCCESS","num_turns":1,"response":""}','invalid_output'),
    (agy_json,b'{"status":"ERROR","error":"SYNTHETIC_PRIVATE_MARKER"}','cli_failed'),
    (agy_json,b'{"status":"SUCCESS","error":"SYNTHETIC_PRIVATE_MARKER","response":"x"}','cli_failed'),
    (agy_json,b'noise {"type":"result","is_error":false,"result":"x"}','invalid_output'),
])
def test_T08_T12_synthetic_failures(parser,raw,code):
    with pytest.raises(RunnerError) as exc:parser(raw)
    assert exc.value.code==code
    assert 'PRIVATE' not in str(exc.value)


@pytest.mark.parametrize('status,code',[
    ('RUNNING', 'invalid_output'), ('WAITING', 'invalid_output'), ('INVALID', 'invalid_output'),
    ('CANCELED', 'cancelled'), ('INTERRUPTED', 'cancelled'), ('UNRECOGNIZED', 'invalid_output'),
])
def test_agy_non_success_states(status, code):
    with pytest.raises(RunnerError) as exc:
        agy_json(json.dumps({'status': status, 'response': 'do not accept'}).encode())
    assert exc.value.code == code


@pytest.mark.parametrize('turns', [0, 2, True, None])
def test_agy_rejects_missing_or_reused_turn(turns):
    with pytest.raises(RunnerError):
        agy_json(json.dumps({'status': 'SUCCESS', 'conversation_id': 'synthetic',
                             'num_turns': turns, 'response': 'wrong turn'}).encode())


def test_agy_stream_identifies_single_result_and_exact_stdin():
    prompt = '한글 "따옴표"\n$(echo fake); --help `fake`'
    message = agy_stdin(prompt)
    assert len(message.splitlines()) == 1
    assert json.loads(message) == {'event': 'user', 'message': {'content': prompt}}
    events = [
        {'event': 'init', 'conversation_id': 'synthetic'},
        {'event': 'step_update', 'step_update': {'conversation_id': 'synthetic', 'text_delta': 'not final'}},
        {'event': 'result', 'result': {'status': 'SUCCESS', 'conversation_id': 'synthetic', 'num_turns': 1, 'response': 'final'}},
    ]
    encode = lambda rows: '\n'.join(json.dumps(e) for e in rows).encode()
    assert agy_stream_json(encode(events)) == 'final'
    for invalid in [events + [events[2]], events[1:], list(reversed(events))]:
        with pytest.raises(RunnerError):
            agy_stream_json(encode(invalid))
    events[2]['result']['conversation_id'] = 'other-run'
    with pytest.raises(RunnerError):
        agy_stream_json(encode(events))


def test_agy_rejects_unsubstantiated_legacy_candidate():
    with pytest.raises(RunnerError):
        agy_json(b'{"type":"result","is_error":false,"result":"not documented"}')


@pytest.mark.parametrize('mutation', ['after_result', 'before_init', 'foreign_step', 'missing_step_id', 'duplicate_init', 'unknown_event'])
def test_agy_stream_rejects_ambiguous_or_foreign_events(mutation):
    start = {'event': 'init', 'conversation_id': 'one'}
    step = {'event': 'step_update', 'step_update': {'conversation_id': 'one', 'state': 'DONE'}}
    end = {'event': 'result', 'result': {'conversation_id': 'one', 'status': 'SUCCESS', 'num_turns': 1, 'response': 'safe'}}
    events = [start, step, end]
    if mutation == 'after_result':
        events.append(step)
    elif mutation == 'before_init':
        events.insert(0, step)
    elif mutation == 'foreign_step':
        step['step_update']['conversation_id'] = 'other'
    elif mutation == 'missing_step_id':
        del step['step_update']['conversation_id']
    elif mutation == 'duplicate_init':
        events.insert(1, start)
    else:
        step['event'] = 'unrecognized'
    with pytest.raises(RunnerError, match='invalid_output'):
        agy_stream_json('\n'.join(json.dumps(e) for e in events).encode())


@pytest.mark.parametrize('parser,raw', [
    (agy_json, b'{"conversation_id":"one","num_turns":1,"status":"ERROR","status":"SUCCESS","response":"x"}'),
    (codex_jsonl, b'{"type":"item.completed","item":{"type":"agent_message","text":"x"}}\n{"type":"turn.failed","type":"turn.completed"}'),
    (codex_jsonl, b'{"type":"item.completed","item":{"type":"agent_message","text":"private","text":"x"}}\n{"type":"turn.completed"}'),
    (agy_stream_json, b'{"event":"init","conversation_id":"one"}\n{"event":"result","result":{"conversation_id":"foreign","conversation_id":"one","num_turns":1,"status":"SUCCESS","response":"x"}}'),
])
def test_duplicate_keys_cannot_hide_failure_or_foreign_session(parser, raw):
    with pytest.raises(RunnerError, match='invalid_output'):
        parser(raw)


@pytest.mark.parametrize('parser', [codex_jsonl, agy_json, agy_stream_json])
@pytest.mark.parametrize('raw,code', [
    (b' ' * 262145, 'output_limit'),
    (b'[' * 1500 + b']' * 1500, 'invalid_output'),
    (b'\xff', 'invalid_output'),
])
def test_parser_bounds_and_malformed_data_are_safe_errors(parser, raw, code):
    with pytest.raises(RunnerError, match=code):
        parser(raw)


def encoded_answer(provider, answer, **extra):
    payload = {'status': 'SUCCESS', 'conversation_id': 'one', 'num_turns': 1,
               'response': answer, **extra}
    if provider == 'agy':
        return agy_json, json.dumps(payload, ensure_ascii=True).encode()
    if provider == 'stream':
        events = [{'event': 'init', 'conversation_id': 'one'},
                  {'event': 'result', 'result': payload}]
        return agy_stream_json, '\n'.join(json.dumps(e, ensure_ascii=True) for e in events).encode()
    events = [{'type': 'item.completed', 'item': {'type': 'agent_message', 'text': answer}, **extra},
              {'type': 'turn.completed'}]
    return codex_jsonl, '\n'.join(json.dumps(e, ensure_ascii=True) for e in events).encode()


@pytest.mark.parametrize('provider', ['agy', 'stream', 'codex'])
@pytest.mark.parametrize('answer,code', [('\ud800', 'invalid_output'), ('x' * 65537, 'output_limit')])
def test_answer_encoding_and_size(provider, answer, code):
    parser, raw = encoded_answer(provider, answer)
    with pytest.raises(RunnerError, match=code):
        parser(raw)


@pytest.mark.parametrize('provider', ['agy', 'stream', 'codex'])
@pytest.mark.parametrize('number', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_json_is_rejected_even_in_metadata(provider, number):
    parser, raw = encoded_answer(provider, 'x', usage=number)
    with pytest.raises(RunnerError, match='invalid_output'):
        parser(raw)


@pytest.mark.parametrize('provider', ['agy', 'stream', 'codex'])
def test_korean_answer_at_byte_limit_is_accepted(provider):
    # Escaped input remains below 256 KiB; decoded UTF-8 answer is exactly 64 KiB.
    answer = '가' * 21845 + 'x'
    parser, raw = encoded_answer(provider, answer)
    assert parser(raw) == answer

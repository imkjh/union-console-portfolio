import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
type Model = {
    id: string;
    name: string;
    model_id: string;
    provider: string;
    available: boolean;
    mode: string;
};
type Attempt = {
    attempt_id: number;
    status: string;
    response: string | null;
    error: string | null;
    queued_at: number;
    started_at: number | null;
    finished_at: number | null;
};
type Run = {
    run_id: string;
    prompt: string;
    models: Record<string, Attempt>;
    mode: string;
};
const labels: Record<string, string> = { waiting: '대기', running: '실행 중', complete: '완료', failed: '실패', timeout: '시간 초과' };
const errors: Record<string, string> = { network_unavailable: '모델 서버에 연결하지 못했어요. 잠시 후 다시 시도해 주세요.', cli_failed: '답변을 가져오지 못했어요. 다시 시도해 주세요.', timeout: '답변 시간이 길어졌어요. 다시 시도할 수 있어요.', queue_timeout: '대기 시간이 길어졌어요. 잠시 후 다시 시도해 주세요.', provider_unavailable: '안전한 연결을 확인하고 있어요. 지금은 사용할 수 없어요.', busy: '다른 질문을 처리 중이에요. 잠시 후 다시 시도해 주세요.', run_limit: '보관할 수 있는 질문이 가득 찼어요. 만료 후 다시 시도해 주세요.', run_missing: '결과가 만료되었거나 서버가 다시 시작됐어요.', session_expired: '서버 연결이 갱신됐어요. 새로고침해 주세요.', invalid_input: '질문과 선택한 모델을 확인해 주세요.', output_limit: '답변이 표시 가능한 길이를 넘었어요.', retry_conflict: '이미 처리 중이거나 완료된 답변이에요.', auth_required: 'CLI 로그인을 확인해 주세요.', rate_limited: '구독 사용 한도에 도달했어요. 잠시 후 다시 시도해 주세요.' };
const active = (run: Run | null) => !!run && Object.values(run.models).some(x => ['waiting', 'running'].includes(x.status));
class ApiError extends Error {
    constructor(message: string, readonly code: string) { super(message); }
}
function App() {
    const [models, setModels] = useState<Model[]>([]), [selected, setSelected] = useState(['gpt', 'gemini', 'claude']);
    const [prompt, setPrompt] = useState(''), [run, setRun] = useState<Run | null>(null), [mode, setMode] = useState('');
    const [error, setError] = useState(''), [pending, setPending] = useState(false), [retrying, setRetrying] = useState<string[]>([]), [now, setNow] = useState(Date.now());
    const token = useRef(''), submitting = useRef(false), retryLocks = useRef(new Set<string>());
    const busy = active(run) || pending;
    async function api(path: string, body?: unknown) {
        const response = await fetch('/api' + path, { method: body === undefined ? 'GET' : 'POST', headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-Union-Token': token.current }, body: body === undefined ? undefined : JSON.stringify(body) });
        const data = await response.json();
        if (!response.ok)
            throw new ApiError(errors[data.error] || '요청을 처리하지 못했어요. 잠시 후 다시 시도해 주세요.', data.error);
        return data;
    }
    useEffect(() => { Promise.all([api('/health'), api('/models')]).then(([health, list]) => { token.current = health.csrf_token; setMode(health.mode); setModels(list); setSelected(list.filter((m: Model) => m.available).map((m: Model) => m.id)); }).catch(() => setError('서버에 연결하지 못했어요. 새로고침해 주세요.')); }, []);
    useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 500); return () => clearInterval(timer); }, []);
    useEffect(() => { if (!run || !active(run))
        return; let disposed = false; let timer: number; const poll = async () => { try {
        const updated = await api('/runs/' + run.run_id);
        if (!disposed) {
            setRun(updated);
            setError('');
        }
    }
    catch (e) {
        if (!disposed) {
            setError((e as Error).message);
            if (e instanceof ApiError && e.code === 'run_missing') {
                // The server lost this run; stop polling and unlock the composer.
                disposed = true;
                setRun(null);
            }
        }
    } if (!disposed)
        timer = window.setTimeout(poll, 500); }; timer = window.setTimeout(poll, 300); return () => { disposed = true; clearTimeout(timer); }; }, [run?.run_id, active(run)]);
    async function ask(e: React.FormEvent) { e.preventDefault(); if (submitting.current || busy)
        return; if (!prompt.trim() || !selected.length) {
        setError('질문을 적고 모델을 하나 이상 선택해 주세요.');
        return;
    } if (!selected.every(id => models.some(m => m.id === id && m.available))) {
        setError(errors.provider_unavailable);
        return;
    } submitting.current = true; setPending(true); setError(''); try {
        const result = await api('/runs', { prompt, models: selected });
        setRun(result);
    }
    catch (e) {
        setError((e as Error).message);
    }
    finally {
        submitting.current = false;
        setPending(false);
    } }
    async function retry(id: string) { if (!run || retryLocks.current.has(id))
        return; retryLocks.current.add(id); setRetrying([...retryLocks.current]); setError(''); try {
        const result = await api(`/runs/${run.run_id}/models/${id}/retry`, {});
        setRun(result);
    }
    catch (e) {
        setError((e as Error).message);
    }
    finally {
        retryLocks.current.delete(id);
        setRetrying([...retryLocks.current]);
    } }
    const canAsk = !!prompt.trim() && selected.length > 0 && !busy && selected.every(id => models.some(m => m.id === id && m.available));
    const availableCount = models.filter(m => m.available).length;
    const done = run ? Object.values(run.models).filter(a => !['waiting', 'running'].includes(a.status)).length : 0;
    return <><header className="topbar"><div className="brand"><span className="brand-mark" aria-hidden="true">u<span>·</span></span>Union Console</div><span className="local"><i /> 내 컴퓨터에서</span></header>
 <main><section className="intro"><p className="eyebrow">하나의 질문, 여러 관점</p><h1>한 번 묻고,<br className="mobile-break"/> 한 번에 비교하세요.</h1><p>GPT, Gemini, Claude의 답변을 한곳에서 살펴보세요.</p></section>
 {mode === 'demo' && <div className="notice"><span className="demo-badge">Demo</span><p>지금은 체험 모드예요. 예시 답변이며 실제 모델을 호출하지 않아요.</p></div>}
 {mode === 'live' && <div className={'notice' + (availableCount === 0 ? ' blocked' : '')}><strong>{availableCount === 0 ? '연결 준비 중' : availableCount < models.length ? '일부 모델 연결됨' : 'Live'}</strong><p>{availableCount === 0 ? '모델의 안전한 실행 제한이 아직 확인되지 않아 실제 연결을 잠가 두었어요.' : availableCount < models.length ? '연결된 모델에 질문을 보내요. 기존 구독의 사용량이 소모돼요. 나머지는 준비 중이에요.' : '선택한 모델에 질문을 보내요. 기존 구독의 사용량이 소모돼요.'}</p></div>}
 <form className="composer" onSubmit={ask}><div className="section-title"><label htmlFor="question">어떤 점이 궁금하세요?</label><span>01 · 질문 입력</span></div>
 <textarea id="question" placeholder="예: 처음 만드는 개인 프로젝트, 무엇부터 시작하면 좋을까요?" maxLength={4000} value={prompt} disabled={busy} onChange={e => setPrompt(e.target.value)} aria-describedby="question-help"/>
 <div className="input-meta"><span id="question-help">같은 질문을 각 모델에 독립적으로 전달해요.</span><span>{prompt.length.toLocaleString()} / 4,000</span></div>
 <div className="composer-bottom"><fieldset disabled={busy}><legend>02 · 비교할 모델</legend><div className="chips">{models.map(m => <label className={'chip ' + (selected.includes(m.id) ? 'selected' : '')} key={m.id}><input type="checkbox" checked={selected.includes(m.id)} disabled={!m.available} onChange={e => setSelected(e.target.checked ? [...selected, m.id] : selected.filter(x => x !== m.id))}/><span>{m.name}</span></label>)}</div></fieldset><button className="primary" type="submit" disabled={!canAsk}>{busy ? '답변을 모으고 있어요' : '답변 비교하기'}<span aria-hidden="true">↗</span></button></div>
 <p className="form-hint">{busy ? '현재 답변을 모두 받은 뒤 새 질문을 보낼 수 있어요.' : mode === 'live' && availableCount === 0 ? '사용 가능한 모델이 아직 없어요.' : selected.length === 0 ? '비교할 모델을 하나 이상 선택해 주세요.' : '민감한 개인정보는 질문에 넣지 마세요.'}</p></form>
 {error && <div role="alert" className="error-banner">{error}</div>}
 <section className="comparison" aria-label="모델 답변 비교"><div className="compare-title"><div><p className="eyebrow">03 · 답변 비교</p><h2>{run ? '각자의 답변을 살펴보세요' : '어떤 답변이 돌아올까요?'}</h2></div><span aria-live="polite">{run ? `${done} / ${Object.keys(run.models).length} 처리 완료` : '질문을 보내면 여기에 모여요'}</span></div>
 {run && <p className="asked"><strong>보낸 질문</strong> {run.prompt}</p>}
 <div className="cards">{models.map(m => {
            const a = run?.models[m.id];
            const state = a?.status;
            const elapsed = a?.started_at ? ((a.finished_at || now / 1000) - a.started_at).toFixed(1) : null;
            return <article className={'model-card ' + (state || 'empty')} key={m.id} aria-label={m.name + ' 응답'}><div className="card-heading"><div className={'model-icon ' + m.id} aria-hidden="true">{m.id === 'gpt' ? 'G' : m.id === 'gemini' ? <svg width="20" height="20" viewBox="0 0 24 24"><path fill="currentColor" d="M12 1C11 8 8 11 1 12c7 1 10 4 11 11 1-7 4-10 11-11C16 11 13 8 12 1Z"/></svg> : 'C'}</div><div><h3>{m.name}</h3><span className="provider">{m.provider}</span></div><span className={'status ' + (state || '')} aria-live="polite">{state ? labels[state] : !m.available ? '연결 불가' : run ? '선택 안 함' : '시작 전'}</span></div><div className="model-detail"><code>{m.model_id}</code><span>{mode === 'demo' ? 'Demo' : m.available ? 'Live' : '연결 불가'}</span></div>
 <div className="answer" tabIndex={a?.response ? 0 : undefined} aria-label={m.name + ' 답변 내용'}>{a?.response ? <div className="response">{a.response}</div> : state === 'failed' || state === 'timeout' ? <div className="card-message"><span className="message-icon">!</span><h4>{state === 'timeout' ? '조금 오래 걸리고 있어요' : '답변을 가져오지 못했어요'}</h4><p>{errors[a?.error || ''] || '잠시 후 다시 시도해 주세요.'}</p><button className="retry" disabled={retrying.includes(m.id)} onClick={() => retry(m.id)}>{retrying.includes(m.id) ? '요청 중…' : '다시 시도'}</button></div> : state === 'running' ? <div className="card-message"><span className="pulse"/><h4>답변을 작성하고 있어요</h4><p>완료되면 바로 보여드릴게요.</p><div className="skeleton"><i /><i /><i /></div></div> : state === 'waiting' ? <div className="card-message"><span className="message-icon">···</span><h4>차례를 기다리고 있어요</h4><p>실행할 준비가 되면 시작해요.</p></div> : <div className="card-message"><span className="empty-symbol" aria-hidden="true">“</span><h4>{!m.available ? '연결을 준비하고 있어요' : run ? '이번 질문에는 선택하지 않았어요' : '새로운 관점을 기다리는 중'}</h4><p>{!m.available ? '준비가 끝나면 선택할 수 있어요.' : run ? '다음 질문에서 함께 비교해 보세요.' : '질문을 보내면 답변이 여기에 나타나요.'}</p></div>}</div>
 <footer className="card-footer"><span>{a ? `시도 ${a.attempt_id}` : '독립적인 답변'}</span><span>{elapsed !== null ? `${elapsed}초` : '—'}</span></footer></article>;
        })}</div></section>
 <footer className="page-footer"><span>Union Console</span><p>답변은 잠시 보관돼요. 서버를 다시 시작하면 사라지며, 완료 후 1시간이 지나면 만료돼요.</p></footer></main></>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);

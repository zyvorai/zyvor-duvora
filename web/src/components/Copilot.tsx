import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { useFleet, useResource } from '../store';
import type { AiStatus, CopilotMessage, CopilotPlan, CopilotReply } from '../types';
import { Badge } from './kit';

type Turn = CopilotMessage & { tools?: CopilotReply['tools']; plans?: CopilotPlan[] };

const STARTERS = ['What needs attention right now?', 'Explain the newest incident.', 'Suggest an allow-list for a node in shadow.'];

export default function Copilot() {
  const { isAdmin, openPlanFor } = useFleet();
  const [open, setOpen] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const { data: ai } = useResource<AiStatus>(open ? 'ai' : null);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => end.current?.scrollIntoView({ block: 'end' }), [turns, busy]);

  async function ask(question: string) {
    const q = question.trim();
    if (!q || busy) return;
    const next: Turn[] = [...turns, { role: 'user', content: q }];
    setTurns(next);
    setText('');
    setError('');
    setBusy(true);
    try {
      const r = await api<CopilotReply>('copilot', 'POST', { messages: next.slice(-20).map(({ role, content }) => ({ role, content: content.slice(0, 4000) })) });
      setTurns([...next, { role: 'assistant', content: r.reply || '(no answer)', tools: r.tools, plans: r.plans }]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function review(p: CopilotPlan) {
    const action = p.spec.action as 'isolate' | 'release';
    openPlanFor(action, p.spec.devices, action === 'isolate' ? { stage: p.spec.stage, policy: p.spec.policy } : undefined);
  }

  return (
    <>
      <button type="button" className="dv-copilot-fab primary" onClick={() => setOpen(!open)} aria-expanded={open} aria-controls="dv-copilot">
        {open ? 'Close copilot' : 'Ask copilot'}
      </button>
      {open && (
        <aside id="dv-copilot" className="dv-copilot card" aria-label="Ops copilot">
          <header className="dv-copilot-head">
            <div>
              <p className="eyebrow">OPS COPILOT</p>
              <small className="dv-muted">{ai?.llm ? `${ai.model}${ai.redact ? ' · addresses redacted' : ''}` : 'No language model configured'}</small>
            </div>
            {turns.length > 0 && (
              <button type="button" className="btn-secondary" onClick={() => setTurns([])}>
                Clear
              </button>
            )}
          </header>
          <div className="dv-copilot-log" aria-live="polite">
            {!turns.length && (
              <div className="dv-copilot-empty">
                <p className="dv-fine">
                  Ask about devices, incidents, telemetry and isolation. The copilot reads fleet data{isAdmin ? ' and can draft a plan for you to review' : ''}; it never applies a change.
                </p>
                {STARTERS.map((s) => (
                  <button type="button" key={s} className="btn-secondary" onClick={() => void ask(s)} disabled={busy || ai?.llm === false}>
                    {s}
                  </button>
                ))}
              </div>
            )}
            {turns.map((t, i) => (
              <div key={i} className={`dv-copilot-turn ${t.role}`}>
                <p>{t.content}</p>
                {t.tools && t.tools.length > 0 && (
                  <div className="chips">
                    {t.tools.map((u, j) => (
                      <Badge key={j} tone={u.ok ? 'info' : 'warn'}>
                        {u.name}
                      </Badge>
                    ))}
                  </div>
                )}
                {t.plans?.map((p) => (
                  <div key={p.id} className="dv-plan">
                    <Badge tone={p.blockers.length ? 'bad' : 'info'}>{p.mode}</Badge>
                    <p>
                      {p.spec.action} on {p.spec.devices.join(', ')}
                      {p.spec.policy ? ` · ${p.spec.policy.cidr} ports ${p.spec.policy.ports.join(', ') || 'any'}` : ''}
                    </p>
                    {p.blockers.length > 0 && <p className="login-error">{p.blockers.join(' · ')}</p>}
                    <button type="button" className="primary" onClick={() => review(p)}>
                      Review plan
                    </button>
                  </div>
                ))}
              </div>
            ))}
            {busy && <p className="dv-muted">Thinking…</p>}
            {error && (
              <p className="login-error" role="alert">
                {error}
              </p>
            )}
            <div ref={end} />
          </div>
          <form
            className="dv-copilot-input"
            onSubmit={(e) => {
              e.preventDefault();
              void ask(text);
            }}
          >
            <label className="sr-only" htmlFor="copilot-q">
              Question
            </label>
            <input id="copilot-q" value={text} onChange={(e) => setText(e.target.value)} maxLength={4000} placeholder="Ask about the fleet…" autoComplete="off" disabled={busy} />
            <button type="submit" className="primary" disabled={busy || !text.trim()}>
              Send
            </button>
          </form>
        </aside>
      )}
    </>
  );
}

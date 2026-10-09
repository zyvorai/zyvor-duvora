import { useMemo, useState } from 'react';

type Rule = { proto: string; port: number | null; net: string; action: 'bypass' | 'allow' | 'inspect' | 'drop' };
const RULES: Rule[] = [
  { proto: 'tcp', port: 22, net: 'any', action: 'bypass' },
  { proto: 'tcp', port: 443, net: '10.', action: 'allow' },
  { proto: 'tcp', port: 443, net: 'any', action: 'inspect' },
  { proto: 'tcp', port: 9001, net: '185.220.', action: 'drop' },
];
const DEFAULT = 'allow';

export default function RuleDemo() {
  const [dst, setDst] = useState('185.220.101.9');
  const [port, setPort] = useState(9001);
  const [stage, setStage] = useState<'shadow' | 'enforce'>('shadow');
  const hit = useMemo(() => {
    const i = RULES.findIndex((r) => r.port === port && (r.net === 'any' || dst.startsWith(r.net)));
    return i;
  }, [dst, port]);
  const action = hit >= 0 ? RULES[hit].action : DEFAULT;
  const would = action === 'drop' && stage === 'shadow';
  return (
    <section id="try" className="section demo">
      <p className="eyebrow">Try it</p>
      <h2>Which rule wins?</h2>
      <p className="lede">First match wins. Change the flow, flip the stage, and see what Duvora would do. This is a model of the console's rule test, not a live system.</p>
      <div className="demo-grid">
        <div className="card">
          <label>Destination<input value={dst} onChange={(e) => setDst(e.target.value)} spellCheck={false} /></label>
          <label>Port
            <select value={port} onChange={(e) => setPort(Number(e.target.value))}>
              {[22, 443, 9001, 8080].map((p) => <option key={p}>{p}</option>)}
            </select>
          </label>
          <div className="seg">
            {(['shadow', 'enforce'] as const).map((s) => (
              <button key={s} className={stage === s ? 'on' : ''} onClick={() => setStage(s)}>{s}</button>
            ))}
          </div>
        </div>
        <div className="card rules">
          {RULES.map((r, i) => (
            <div key={i} className={`rule${i === hit ? ' hit' : ''}`}>
              <span>{i + 1}</span><code>{r.proto}/{r.port} → {r.net === 'any' ? 'any' : `${r.net}*`}</code><b className={r.action}>{r.action}</b>
            </div>
          ))}
          <div className={`rule${hit < 0 ? ' hit' : ''}`}><span>·</span><code>default</code><b className={DEFAULT}>{DEFAULT}</b></div>
          <p className={`verdict ${action}`}>
            {would ? 'Shadow: counted as would-drop. Nothing is blocked yet.' : action === 'drop' ? 'Enforce (leased): dropped in the host kernel.' : `Verdict: ${action}`}
          </p>
        </div>
      </div>
    </section>
  );
}

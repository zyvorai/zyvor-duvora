import { useState } from 'react';
import { asset } from '../hooks';

const SHOTS = [
  ['console-overview.jpg', 'Overview', 'Fleet pulse, devices and active incidents'],
  ['console-steering.jpg', 'Steering', 'Rule sets, shadow verdicts and "which rule wins?"'],
  ['console-ai-traffic.jpg', 'AI traffic', 'LLM endpoints, findings and inspection coverage'],
  ['console-threats.jpg', 'Threats', 'Intel matches, feeds and artifact scans'],
  ['console-report.jpg', 'Report', 'Shift briefing with the AI posture score'],
  ['console-services.jpg', 'Services', 'Deployments and resource headroom'],
];

export default function Gallery() {
  const [i, setI] = useState(0);
  const [file, name, cap] = SHOTS[i];
  return (
    <section className="section">
      <p className="eyebrow">The console</p>
      <h2>Shaped around the operator.</h2>
      <div className="tabs" role="tablist">
        {SHOTS.map((s, k) => <button key={s[0]} role="tab" aria-selected={k === i} className={k === i ? 'on' : ''} onClick={() => setI(k)}>{s[1]}</button>)}
      </div>
      <figure className="shot">
        <img key={file} src={asset(file)} alt={`${name}: ${cap}`} />
        <figcaption>{cap}</figcaption>
      </figure>
    </section>
  );
}

import { useEffect, useState } from 'react';
import { links } from '../links';

const LINES = [
  '$ duvoractl plan examples/isolate.json',
  '  plan 7f3a  expires in 5m  shadow run: 0 would-block of 1,284 flows',
  "$ duvoractl apply 7f3a --confirm 'APPLY SIMULATION'",
  '  job complete · revision-guarded · audit entry written',
  '$ duvoractl rollback JOB --confirm',
  '  restored snapshot · no later changes overwritten',
];

export default function Hero() {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { setN(LINES.join('\n').length); return; }
    const total = LINES.join('\n').length;
    const id = setInterval(() => setN((v) => (v >= total + 40 ? 0 : v + 1)), 35);
    return () => clearInterval(id);
  }, []);
  const text = LINES.join('\n').slice(0, n);
  return (
    <section className="hero">
      <div className="aurora" aria-hidden />
      <p className="eyebrow">DPU fleet control plane</p>
      <h1>Plans, isolation, evidence.<br /><span className="grad">In your control.</span></h1>
      <p className="lede">One server, one API, one CLI and one console for DPU inventory, traffic steering, AI security and change evidence. Run the whole workflow on four simulated BlueField devices before the hardware arrives.</p>
      <div className="cta-row">
        <a className="btn" href={links.demo}>Book a demo</a>
        <a className="btn btn-dark" href={links.poc}>Start a 30-day PoC</a>
        <a className="btn btn-ghost" href="#start">Quickstart in one command</a>
      </div>
      <div className="term" role="img" aria-label="Terminal showing plan, apply and rollback with duvoractl">
        <div className="term-bar"><i /><i /><i /></div>
        <pre>{text}<span className="caret" /></pre>
      </div>
    </section>
  );
}

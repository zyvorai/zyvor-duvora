import { asset, useInView } from '../hooks';

const FEATURES = [
  {
    id: 'steering', tag: 'Traffic steering', title: 'Decide what every flow does, safely.',
    body: 'Ordered 5-tuple rules end in bypass, allow, inspect or drop. A steer plan replays recent flows against the new set first. Shadow counts verdicts and would-drops; enforce is leased and falls back to shadow by itself. SSH and the control plane are always exempt.',
    bullets: ['Shadow before enforce', 'Per-device bypass on demand', 'Rollback restores the previous set'],
    img: 'steering-flow.svg', alt: 'Animated traffic steering flow',
  },
  {
    id: 'ai', tag: 'AI security', title: 'See what leaves for LLM APIs.',
    body: 'Inspect samples the start of each flow and flags prompt injection, secrets and personal data with redacted snippets. Shadow-AI discovery, image and model scans, threat-intel feeds and an AI posture score sit around it. Playbooks draft the block plan; a human applies it.',
    bullets: ['LLM traffic inspection', 'Artifact scans that can gate deploys', 'Draft-only playbooks, never auto-apply'],
    img: 'ai-inspect.svg', alt: 'Animated AI traffic inspection',
  },
  {
    id: 'arch', tag: 'Change evidence', title: 'Every change has an owner and a receipt.',
    body: 'Plans bind to their creator, expire in five minutes and capture device revisions. Apply is idempotent, job progress survives restart, and rollback refuses to overwrite later changes. Export the audit trail as JSON evidence.',
    bullets: ['Actor-bound, expiring plans', 'Revision-guarded rollback', 'SIEM export and agent mTLS'],
    img: 'architecture.svg', alt: 'Animated architecture diagram',
  },
];

function Feature({ f, flip }: { f: typeof FEATURES[number]; flip: boolean }) {
  const [ref, seen] = useInView<HTMLDivElement>(0.2);
  return (
    <div ref={ref} className={`feature reveal${seen ? ' in' : ''}${flip ? ' flip' : ''}`}>
      <div className="feature-copy">
        <p className="eyebrow">{f.tag}</p>
        <h2>{f.title}</h2>
        <p>{f.body}</p>
        <ul>{f.bullets.map((b) => <li key={b}>{b}</li>)}</ul>
      </div>
      <img className="feature-art" src={asset(f.img)} alt={f.alt} loading="lazy" />
    </div>
  );
}

export default function Features() {
  return (
    <section id="features" className="section">
      {FEATURES.map((f, i) => <Feature key={f.id} f={f} flip={i % 2 === 1} />)}
    </section>
  );
}

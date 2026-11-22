// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { Empty, Section, ToneDot, scoreTone } from '../components/kit';
import { useResource } from '../store';
import type { Scorecard as Card } from '../types';

export function Ring({ score }: { score: number | null }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const v = score ?? 0;
  return (
    <svg width="140" height="140" viewBox="0 0 140 140" className={`dv-ring tone-${scoreTone(score)}`} role="img" aria-label={`Score ${score ?? 'not available'}`}>
      <circle cx="70" cy="70" r={r} className="track" />
      <circle cx="70" cy="70" r={r} className="value" strokeDasharray={`${(v / 100) * c} ${c}`} transform="rotate(-90 70 70)" />
      <text x="70" y="78" textAnchor="middle">
        {score ?? '—'}
      </text>
    </svg>
  );
}

export default function Scorecard() {
  const { data } = useResource<Card>('scorecard', 5000);
  if (!data) return null;
  return (
    <div className="grid">
      <Section span={1} eyebrow="SHIFT SCORE" title={data.grade}>
        <div className="dv-score">
          <Ring score={data.score} />
          <p>{data.devices ? `${data.devices} devices scored. Observe-only; nothing on this page changes the fleet.` : 'Connect devices to compute a score.'}</p>
        </div>
      </Section>
      <Section span={2} eyebrow="BREAKDOWN" title="How the score is built" lede="Each part contributes up to its weight; the total is out of 100.">
        {data.devices ? (
          <div className="dv-parts">
            {data.parts.map((p) => {
              const pct = Math.round((p.score / p.weight) * 100);
              return (
                <div key={p.name} className="dv-part">
                  <div>
                    <strong>
                      <ToneDot tone={scoreTone(pct)} /> {p.name}
                    </strong>
                    <span>
                      {p.score} / {p.weight}
                    </span>
                  </div>
                  <meter min={0} max={p.weight} value={p.score} aria-label={p.name} />
                  <small>{p.detail}</small>
                </div>
              );
            })}
          </div>
        ) : (
          <Empty title="No devices yet." />
        )}
      </Section>
    </div>
  );
}

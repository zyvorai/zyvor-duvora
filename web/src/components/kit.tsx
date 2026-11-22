// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode } from 'react';

// Color is deviation: 'ok' is confirmed good, 'warn'/'bad' only when a value
// really deviates, 'idle' when there is no data yet.
export type Tone = 'ok' | 'warn' | 'bad' | 'idle' | 'info';

export function scoreTone(score: number | null | undefined, warnBelow = 80, badBelow = 50): Tone {
  if (score === undefined || score === null || !Number.isFinite(score)) return 'idle';
  if (score < badBelow) return 'bad';
  return score < warnBelow ? 'warn' : 'ok';
}

export function healthTone(health: string): Tone {
  if (health === 'healthy') return 'ok';
  if (health === 'degraded') return 'warn';
  if (health === 'stale') return 'bad';
  return 'idle';
}

export function severityTone(severity: string): Tone {
  return severity === 'critical' ? 'bad' : severity === 'warning' ? 'warn' : 'info';
}

export function ToneDot({ tone }: { tone: Tone }) {
  return <span className={`kit-dot tone-${tone}`} aria-hidden />;
}

export function Badge({ tone = 'idle', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`dv-badge tone-${tone}`}>{children}</span>;
}

export function Section({
  eyebrow,
  title,
  lede,
  actions,
  children,
  span = 3,
  className,
}: {
  eyebrow?: string;
  title?: string;
  lede?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  span?: 1 | 2 | 3;
  className?: string;
}) {
  const spanClass = span === 3 ? 'span3' : span === 2 ? 'span2' : '';
  return (
    <section className={['card', 'kit-section', spanClass, className].filter(Boolean).join(' ')}>
      {(eyebrow || title || actions) && (
        <header className="kit-section__head">
          <div>
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            {title && <h2 className="card-title">{title}</h2>}
          </div>
          {actions && <div className="kit-section__actions">{actions}</div>}
        </header>
      )}
      {lede && <p className="kit-lede">{lede}</p>}
      {children}
    </section>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      {children && <div>{children}</div>}
    </div>
  );
}

export function Metrics({ items }: { items: { label: string; value: ReactNode; note?: string }[] }) {
  return (
    <div className="metrics">
      {items.map((m) => (
        <div key={m.label}>
          <b>{m.value}</b>
          <span>{m.label}</span>
          {m.note && <span>{m.note}</span>}
        </div>
      ))}
    </div>
  );
}

export function Table({ heads, children, label }: { heads: string[]; children: ReactNode; label?: string }) {
  return (
    <div className="table-wrap">
      <table aria-label={label}>
        <thead>
          <tr>
            {heads.map((h, i) => (
              <th scope="col" key={i}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'warn'; children: ReactNode }) {
  return <div className={`dv-notice ${tone === 'warn' ? 'warning' : ''}`}>{children}</div>;
}

/** A small inline-SVG trend line; last N values, no axes. */
export function Sparkline({ values, width = 160, height = 32, fill = false }: { values: number[]; width?: number; height?: number; fill?: boolean }) {
  if (values.length < 2) return <span className="dv-muted">No trend yet</span>;
  const max = Math.max(...values, 0.0001);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * width},${height - ((v - min) / span) * (height - 2) - 1}`).join(' ');
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="sparkline" role="img" aria-label="trend">
      {fill && <polygon points={`0,${height} ${pts} ${width},${height}`} fill="currentColor" opacity="0.12" stroke="none" />}
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

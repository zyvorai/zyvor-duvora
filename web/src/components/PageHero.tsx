// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import type { ReactNode } from 'react';

export type HeroTint = 'green' | 'amber' | 'purple' | 'red';

export default function PageHero({
  eyebrow,
  title,
  lede,
  tint,
  actions,
}: {
  eyebrow: string;
  title: string;
  lede: string;
  tint?: HeroTint;
  actions?: ReactNode;
}) {
  return (
    <header className={tint ? `page-hero hero-tint-${tint}` : 'page-hero'}>
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <p>{lede}</p>
      {actions && <div className="dv-hero-actions">{actions}</div>}
    </header>
  );
}

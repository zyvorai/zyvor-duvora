// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { describe, expect, it } from 'vitest';
import { pageHero } from '../App';
import { PAGES, navGroups } from './navGroups';
import { readRoute, routeHash } from './route';

describe('navGroups', () => {
  const linked = navGroups.flatMap((g) => (g.children ? g.children.map((c) => c.page) : g.page ? [g.page] : []));

  it('reaches every routable page exactly once', () => {
    expect([...linked].sort()).toEqual([...PAGES].sort());
  });

  it('gives every menu link a label and blurb', () => {
    for (const g of navGroups) for (const c of g.children || []) expect(c.label && c.blurb).toBeTruthy();
  });

  it('has a hero for every page', () => {
    for (const p of PAGES) expect(pageHero[p].title).toBeTruthy();
  });
});

describe('route', () => {
  it('round-trips a page through the hash', () => {
    expect(readRoute(routeHash('incidents'))).toBe('incidents');
  });

  it('falls back to the overview', () => {
    expect(readRoute('')).toBe('overview');
    expect(readRoute('#page=nope')).toBe('overview');
    expect(readRoute('#fleet')).toBe('overview');
  });
});

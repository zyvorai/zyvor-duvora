// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useMemo, useState } from 'react';
import { Badge, Empty, Section, healthTone } from '../components/kit';
import { sourceLabel } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { Topology as Topo, TopologyNode } from '../types';

const COLUMNS: TopologyNode['kind'][] = ['site', 'host', 'dpu', 'policy'];
const COL_LABEL = { site: 'Sites', host: 'Hosts', dpu: 'DPUs', policy: 'Isolation policies' };
const ROW = 64;
const COL = 260;
const NODE_W = 190;
const NODE_H = 44;

export function layout(topo: Topo) {
  const cols = COLUMNS.map((k) => topo.nodes.filter((n) => n.kind === k));
  const rows = Math.max(1, ...cols.map((c) => c.length));
  const pos: Record<string, { x: number; y: number }> = {};
  cols.forEach((col, ci) => {
    const offset = ((rows - col.length) * ROW) / 2;
    col.forEach((n, ri) => {
      pos[n.id] = { x: ci * COL + 16, y: offset + ri * ROW + 40 };
    });
  });
  return { pos, width: COLUMNS.length * COL, height: rows * ROW + 56 };
}

export default function Topology() {
  const { inspect } = useFleet();
  const { data } = useResource<Topo>('topology', 5000);
  const [focus, setFocus] = useState<string | null>(null);
  const geo = useMemo(() => (data ? layout(data) : null), [data]);
  if (!data || !geo) return null;
  if (!data.nodes.length)
    return (
      <div className="grid">
        <Section>
          <Empty title="Nothing to draw yet.">Connect an inventory source to see sites, hosts, and DPUs.</Empty>
        </Section>
      </div>
    );
  const linked = new Set<string>();
  if (focus) {
    linked.add(focus);
    data.edges.forEach((e) => {
      if (e.from === focus) linked.add(e.to);
      if (e.to === focus) linked.add(e.from);
    });
  }
  const selectedNode = data.nodes.find((n) => n.id === focus);
  return (
    <div className="grid">
      <Section eyebrow="GRAPH" title="Sites → hosts → DPUs → policies" lede="Select a node to highlight its neighbours. Select a DPU twice to inspect it.">
        <div className="dv-topology">
          <svg width={geo.width} height={geo.height} viewBox={`0 0 ${geo.width} ${geo.height}`} role="img" aria-label="Fleet topology">
            {COLUMNS.map((k, i) => (
              <text key={k} x={i * COL + 16} y={20} className="dv-topo-col">
                {COL_LABEL[k]}
              </text>
            ))}
            {data.edges.map((e, i) => {
              const a = geo.pos[e.from];
              const b = geo.pos[e.to];
              if (!a || !b) return null;
              const [from, to] = a.x < b.x ? [a, b] : [b, a];
              const x1 = from.x + NODE_W;
              const y1 = from.y + NODE_H / 2;
              const x2 = to.x;
              const y2 = to.y + NODE_H / 2;
              const mid = (x1 + x2) / 2;
              const dim = focus && !(linked.has(e.from) && linked.has(e.to));
              return <path key={i} d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`} className={`dv-topo-edge ${e.kind} ${dim ? 'dim' : ''}`} />;
            })}
            {data.nodes.map((n) => {
              const p = geo.pos[n.id];
              const tone = n.kind === 'dpu' ? healthTone(n.health || '') : n.kind === 'policy' ? 'info' : 'idle';
              const dim = focus && !linked.has(n.id);
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  className={`dv-topo-node kind-${n.kind} tone-${tone} ${dim ? 'dim' : ''} ${focus === n.id ? 'focus' : ''}`}
                  tabIndex={0}
                  role="button"
                  aria-label={`${n.kind} ${n.label}`}
                  onClick={() => {
                    if (focus === n.id && n.kind === 'dpu') inspect(n.label);
                    setFocus(focus === n.id ? null : n.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') setFocus(focus === n.id ? null : n.id);
                  }}
                >
                  <rect width={NODE_W} height={NODE_H} rx={12} />
                  <circle cx={16} cy={NODE_H / 2} r={5} />
                  <text x={30} y={19}>
                    {n.label}
                  </text>
                  <text x={30} y={34} className="sub">
                    {n.kind === 'dpu' ? `${n.health} · ${n.mode}` : n.kind === 'policy' ? `tenant ${n.tenant}` : n.kind}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        {selectedNode && (
          <p className="dv-fine">
            Selected <strong>{selectedNode.label}</strong> ({selectedNode.kind})
            {selectedNode.kind === 'dpu' && (
              <>
                {' '}
                · <Badge tone={healthTone(selectedNode.health || '')}>{selectedNode.health}</Badge> · {sourceLabel(selectedNode.source || '')}{' '}
                <button type="button" className="btn-diag" onClick={() => inspect(selectedNode.label)}>
                  Inspect
                </button>
              </>
            )}
          </p>
        )}
      </Section>
    </div>
  );
}

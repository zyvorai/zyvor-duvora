// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useState } from 'react';
import { Badge, Empty, Section, Table, healthTone } from '../components/kit';
import { sourceLabel } from '../lib/format';
import { useFleet } from '../store';

const SOURCES = ['all', 'simulator', 'linux-pci', 'nvidia-dpf'];

export default function Devices() {
  const { snapshot, selected, setSelected, inspect, openPlan, isAdmin } = useFleet();
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('all');
  if (!snapshot) return null;
  const q = query.toLowerCase();
  const devices = snapshot.devices.filter(
    (x) => (source === 'all' || x.source === source) && [x.id, x.host, x.site, x.model].some((v) => v.toLowerCase().includes(q)),
  );
  const toggle = (id: string, on: boolean) => {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    setSelected(next);
  };
  return (
    <div className="grid">
      <Section
        eyebrow="INVENTORY"
        title={`${devices.length} device${devices.length === 1 ? '' : 's'}`}
        actions={
          <>
            <button type="button" className="primary" disabled={!isAdmin} onClick={() => openPlan('upgrade')}>
              Plan upgrade
            </button>
            <button type="button" className="btn-secondary" disabled={!isAdmin} onClick={() => openPlan('release')}>
              Release isolation
            </button>
          </>
        }
      >
        <div className="toolbar">
          <input aria-label="Search fleet" placeholder="Search devices, hosts, or sites" value={query} onChange={(e) => setQuery(e.target.value)} />
          <label>
            Source
            <select aria-label="Inventory source" value={source} onChange={(e) => setSource(e.target.value)}>
              {SOURCES.map((x) => (
                <option key={x} value={x}>
                  {x === 'all' ? 'All sources' : sourceLabel(x)}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="btn-secondary" onClick={() => setSelected(new Set([...selected, ...devices.map((d) => d.id)]))}>
            Select visible
          </button>
          <button type="button" className="btn-secondary" disabled={!selected.size} onClick={() => setSelected(new Set())}>
            Clear
          </button>
          <span className="dv-selected">{selected.size} selected</span>
        </div>
        {devices.length ? (
          <Table heads={['', 'Device', 'Host / site', 'Health', 'Source', 'Firmware', '']} label="Devices">
            {devices.map((x) => (
              <tr key={x.id} className={selected.has(x.id) ? 'dv-row-selected' : ''}>
                <td>
                  <input type="checkbox" aria-label={`Select ${x.id}`} checked={selected.has(x.id)} onChange={(e) => toggle(x.id, e.target.checked)} />
                </td>
                <td>
                  <strong>{x.id}</strong>
                  <small className="dv-sub">{x.model}</small>
                </td>
                <td>
                  {x.host}
                  <small className="dv-sub">{x.site}</small>
                </td>
                <td>
                  <Badge tone={healthTone(x.health)}>{x.health}</Badge>
                </td>
                <td>
                  <Badge tone={x.source === 'simulator' ? 'info' : 'idle'}>{sourceLabel(x.source)}</Badge>
                </td>
                <td>
                  {x.firmware}
                  <small className="dv-sub">Revision {x.version}</small>
                </td>
                <td>
                  <button type="button" className="btn-diag" onClick={() => inspect(x.id)}>
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No matching devices.">Change your search or connect an inventory source.</Empty>
        )}
      </Section>
    </div>
  );
}

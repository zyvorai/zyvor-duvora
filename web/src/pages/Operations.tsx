// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { api } from '../api';
import { Badge, Empty, Section, Table } from '../components/kit';
import { when } from '../lib/format';
import { useFleet } from '../store';

export default function Operations() {
  const { snapshot, isAdmin, toast, refresh } = useFleet();
  if (!snapshot) return null;
  const jobs = [...snapshot.jobs].sort((a, b) => b.created - a.created);

  async function rollback(id: string) {
    if (!window.confirm('Roll back this simulated change? Later device changes can block rollback.')) return;
    try {
      await api(`jobs/${id}/rollback`, 'POST', {});
      toast('Simulation rolled back.');
      await refresh();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  return (
    <div className="grid">
      <Section eyebrow="CHANGE HISTORY" title="Jobs" lede="Jobs survive a control-plane restart.">
        {jobs.length ? (
          <Table heads={['Operation', 'Targets', 'State', 'Latest step', '']} label="Jobs">
            {jobs.map((j) => (
              <tr key={j.id}>
                <td>
                  <strong>{j.action}</strong>
                  <small className="dv-sub dv-mono">{j.id}</small>
                </td>
                <td>{j.spec.devices.join(', ')}</td>
                <td>
                  <Badge tone={j.state === 'succeeded' ? 'ok' : j.state === 'running' ? 'info' : j.state === 'failed' ? 'bad' : 'idle'}>{j.state}</Badge>
                </td>
                <td>
                  {j.events.at(-1)?.step || 'queued'}
                  <small className="dv-sub">
                    {when(j.created)} · {j.actor}
                  </small>
                </td>
                <td>
                  {j.state === 'succeeded' && isAdmin && (
                    <button type="button" className="btn-warn" onClick={() => rollback(j.id)}>
                      Roll back
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="A clean change history.">Create a plan from Devices, Services, or Isolation.</Empty>
        )}
      </Section>
    </div>
  );
}

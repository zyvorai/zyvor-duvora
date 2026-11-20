// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { Badge, Empty, Metrics, Notice, Section, Table, ToneDot, healthTone, scoreTone, severityTone } from '../components/kit';
import { ago, sourceLabel } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { Incident, Scorecard } from '../types';

export default function Overview() {
  const { snapshot: s, navigate } = useFleet();
  const { data: card } = useResource<Scorecard>('scorecard', 10000);
  const { data: incidents } = useResource<Incident[]>('incidents?state=active', 10000);
  if (!s) return null;
  const d = s.devices;
  const simulated = d.filter((x) => x.source === 'simulator').length;
  const traffic = d.reduce((a, x) => a + (x.metrics.throughput_gbps || 0), 0);
  const active = s.jobs.filter((j) => ['queued', 'running'].includes(j.state)).length;
  return (
    <div className="grid">
      <section className="card span3 dv-pulse">
        <p className="eyebrow">FLEET PULSE</p>
        <h2 className="card-title">
          {d.length ? `${d.filter((x) => x.health === 'healthy').length} of ${d.length} DPUs healthy · ${s.open_incidents} active incident${s.open_incidents === 1 ? '' : 's'}.` : 'Your fleet starts here.'}
        </h2>
        <Metrics
          items={[
            { label: 'DPUs in your fleet', value: d.length, note: `${simulated} simulated · ${d.length - simulated} observed` },
            { label: 'Fleet score', value: card?.score ?? '—', note: card?.grade },
            { label: 'Reported throughput', value: `${Math.round(traffic)} Gb/s`, note: 'Snapshot sum · includes simulated samples' },
            { label: 'Active operations', value: active, note: 'Durable workflows with audit evidence' },
          ]}
        />
      </section>
      <div className="span3">
        <Notice>
          {s.demo
            ? 'Simulation is enabled. Demo actions change the local model; they do not provision hardware or filter real traffic.'
            : 'Hardware observations are read-only. Hardware mutation adapters are unavailable in this release.'}
        </Notice>
      </div>
      <Section
        span={2}
        eyebrow="FLEET"
        title="Your DPU fleet"
        lede="Devices, sources, and operational posture."
        actions={
          <button type="button" className="btn-diag" onClick={() => navigate('devices')}>
            View all
          </button>
        }
      >
        {d.length ? (
          <Table heads={['Device / host', 'Health', 'Source', 'Mode']}>
            {d.slice(0, 6).map((x) => (
              <tr key={x.id}>
                <td>
                  <strong>{x.id}</strong>
                  <small className="dv-sub">
                    {x.host} · {x.site}
                  </small>
                </td>
                <td>
                  <Badge tone={healthTone(x.health)}>{x.health}</Badge>
                </td>
                <td>
                  <Badge tone={x.source === 'simulator' ? 'info' : 'idle'}>{sourceLabel(x.source)}</Badge>
                </td>
                <td>{x.mode}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="Your fleet starts here.">Submit a Linux PCI agent report or import your NVIDIA DPF inventory.</Empty>
        )}
      </Section>
      <Section
        span={1}
        eyebrow="MONITOR"
        title="Active incidents"
        actions={
          <button type="button" className="btn-diag" onClick={() => navigate('incidents')}>
            Open
          </button>
        }
      >
        {incidents?.length ? (
          <div className="list">
            {incidents.slice(0, 5).map((i) => (
              <div className="agent wide" key={i.id}>
                <b>
                  <ToneDot tone={severityTone(i.severity)} /> {i.title}
                </b>
                <small>
                  {i.detail} · {ago(i.opened)}
                </small>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="All clear.">No alert rule is firing.</Empty>
        )}
        {card && (
          <p className="dv-fine">
            <ToneDot tone={scoreTone(card.score)} /> Fleet score {card.score ?? '—'} · {card.grade}
          </p>
        )}
      </Section>
      <Section span={2} eyebrow="PLACEMENT" title="Fleet map" lede="Host placement across your sites.">
        {d.length ? (
          <div className="dv-fabric">
            {d.map((x) => (
              <div className="dv-fabric-node" key={x.id}>
                <strong>{x.host}</strong>
                <p>
                  {x.id} · {x.site}
                </p>
                <Badge tone={healthTone(x.health)}>{x.health}</Badge> <Badge>{x.mode}</Badge>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No devices yet.">Connect your first inventory source.</Empty>
        )}
      </Section>
      <Section span={1} eyebrow="ACTIVITY" title="Recent activity" lede="Every workflow leaves a trace.">
        {s.audit.length ? (
          <div className="list">
            {s.audit.slice(0, 6).map((x) => (
              <div className="agent wide" key={x.seq}>
                <b>{x.action}</b>
                <small>
                  {x.actor} · {ago(x.time)}
                </small>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No activity yet.">Your first operation will appear here.</Empty>
        )}
      </Section>
    </div>
  );
}

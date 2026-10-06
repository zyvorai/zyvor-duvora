import { useState } from 'react';
import { Badge, Empty, Notice, Section, Table } from '../components/kit';
import { useFleet, useResource } from '../store';
import type { Budget, Resources } from '../types';

const RESOURCES: { key: keyof Resources; label: string; unit: string }[] = [
  { key: 'arm_cores', label: 'Arm cores', unit: '' },
  { key: 'memory_gb', label: 'Memory', unit: ' GB' },
  { key: 'storage_gb', label: 'Storage', unit: ' GB' },
];

function BudgetPanel({ devices }: { devices: string[] }) {
  const [picked, setPicked] = useState('');
  const device = picked || devices[0] || '';
  const { data } = useResource<Budget>(device ? `devices/${device}/budget` : null, 15000, [device]);
  return (
    <Section
      eyebrow="BUDGET"
      title="Resource headroom"
      lede="Capacity minus platform reservations and deployed services. Deploy plans that ask for more than is free are blocked."
      actions={
        <select aria-label="Device" value={device} onChange={(e) => setPicked(e.target.value)}>
          {devices.map((d) => (
            <option key={d}>{d}</option>
          ))}
        </select>
      }
    >
      {!data ? null : !data.free ? (
        <Empty title="Capacity unknown.">This device reports no capacity and its model has no published specification, so requests cannot be checked.</Empty>
      ) : (
        <>
          <Table heads={['Resource', 'Capacity', 'Reserved', 'In use', 'Free', '']}>
            {RESOURCES.map(({ key, label, unit }) => {
              const cap = data.capacity[key] ?? 0;
              const free = data.free[key] ?? 0;
              const usedShare = cap ? Math.min(100, Math.round((100 * (cap - free)) / cap)) : 0;
              return (
                <tr key={key}>
                  <td>{label}</td>
                  <td>{cap}{unit}</td>
                  <td>{data.reserved[key] ?? 0}{unit}</td>
                  <td>{data.used[key] ?? 0}{unit}</td>
                  <td>
                    <Badge tone={free <= 0 ? 'bad' : usedShare >= 80 ? 'warn' : 'ok'}>
                      {free}{unit}
                    </Badge>
                  </td>
                  <td>
                    <meter min={0} max={100} low={60} high={80} optimum={0} value={usedShare} aria-label={`${label} ${usedShare}% committed`} />
                  </td>
                </tr>
              );
            })}
          </Table>
          <small className="dv-sub">
            {data.model || 'Unknown model'} · capacity from {String(data.source)} · {data.services.length} service{data.services.length === 1 ? '' : 's'}
          </small>
        </>
      )}
    </Section>
  );
}

export default function Services() {
  const { snapshot, openPlan, isAdmin } = useFleet();
  if (!snapshot) return null;
  const rows = snapshot.devices.flatMap((d) => d.services.map((x) => ({ device: d.id, ...x })));
  return (
    <div className="grid">
      <div className="span3">
        <Notice>Service deployment is simulated in this release. No containers are launched on physical DPUs.</Notice>
      </div>
      <Section
        eyebrow="SERVICES"
        title="Deployed services"
        lede="Image digests, placement, and reported state."
        actions={
          <button type="button" className="primary" disabled={!isAdmin} onClick={() => openPlan('deploy')}>
            Deploy service
          </button>
        }
      >
        {rows.length ? (
          <Table heads={['Service / image', 'Device', 'State']}>
            {rows.map((x) => (
              <tr key={x.device + x.name}>
                <td>
                  <strong>{x.name}</strong>
                  <small className="dv-sub dv-mono">{x.image}</small>
                </td>
                <td>{x.device}</td>
                <td>
                  <Badge tone="info">{x.state}</Badge>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="Ready for your first service.">Select devices in Fleet → Devices, then deploy an image pinned to its SHA-256 digest.</Empty>
        )}
      </Section>
      {snapshot.devices.length > 0 && <BudgetPanel devices={snapshot.devices.map((d) => d.id)} />}
      <Section span={1} eyebrow="CATEGORY" title="Networking">
        <p>Plan the lifecycle of switching and traffic-processing services. Hardware acceleration requires a validated backend.</p>
      </Section>
      <Section span={1} eyebrow="CATEGORY" title="Security">
        <p>Bring tenant isolation and policy workflows into the same operating model.</p>
      </Section>
      <Section span={1} eyebrow="FUTURE" title="Storage">
        <p>NVMe-oF and storage acceleration are planned, with separate compatibility and hardware acceptance tests.</p>
      </Section>
    </div>
  );
}

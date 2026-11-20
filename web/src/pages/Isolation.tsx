// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Notice, Section, Table } from '../components/kit';
import { bytes, policyModeLabel, providerLabel, remaining } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { Device, EbpfOverview, KillSwitch } from '../types';

interface Verdict {
  verdict: 'allow' | 'deny';
  matched: string[];
}

function NodeIsolation() {
  const { snapshot, openPlanFor, isAdmin, toast, refresh } = useFleet();
  const { data, reload } = useResource<EbpfOverview>('ebpf', 5000);
  if (!snapshot || !data || !(data.netra.configured || data.devices.some((d) => d.provider === 'native'))) return null;
  const { netra } = data;
  const providers = new Set(data.devices.map((d) => d.provider || 'netra'));
  const kill = netra.kill_switch;
  const rows = snapshot.devices.filter((d): d is Device & { ebpf: NonNullable<Device['ebpf']> } => Boolean(d.ebpf) && d.source !== 'simulator');

  async function toggleKill() {
    const engage = !kill.engaged;
    if (engage && !window.confirm('Engage the kill switch? Every enforced node goes back to shadow now, and enforcement is refused until released.')) return;
    try {
      const out = await api<KillSwitch & { demoted: string[]; errors: Record<string, string> }>('ebpf/kill-switch', 'POST', { engaged: engage });
      const errs = Object.keys(out.errors || {});
      toast(engage ? `Kill switch engaged; ${out.demoted.length} device(s) back in shadow${errs.length ? `; failed: ${errs.join(', ')}` : ''}` : 'Kill switch released');
      await Promise.all([reload(), refresh()]);
    } catch (err) {
      toast((err as Error).message);
    }
  }

  return (
    <Section
      eyebrow="KERNEL eBPF"
      title="Node isolation"
      lede={
        <>
          Allow-lists enforced in the kernel on the node behind each device, by the native Duvora agent or by Netra. Run in shadow first; promote one device at a time. Enforcement{' '}
          {netra.enforce_allowed ? 'is enabled' : 'is disabled'} on this server
          {netra.configured && providers.has('netra') && !netra.isolation_supported ? '; this Netra build has no node isolation API' : ''}.
        </>
      }
      actions={
        <button type="button" className={kill.engaged ? 'primary' : 'danger'} disabled={!isAdmin} onClick={toggleKill} aria-pressed={kill.engaged}>
          {kill.engaged ? 'Release kill switch' : 'Kill switch'}
        </button>
      }
    >
      {kill.engaged && (
        <Notice tone="warn">
          Kill switch engaged{kill.by ? ` by ${kill.by}` : ''}. Every node runs in shadow; enforce plans are refused.
        </Notice>
      )}
      {rows.length ? (
        <Table heads={['Device / node', 'Allow-list', 'Stage', 'Kernel counters', 'Top blocked destinations', 'Lease', '']} label="Node isolation">
          {rows.map((d) => {
            const ni = d.netra_isolation;
            const st = d.ebpf.isolation;
            const tone = st?.mode === 'enforce' ? 'warn' : st ? 'info' : 'idle';
            return (
              <tr key={d.id}>
                <td>
                  <strong>{d.id}</strong>
                  <small className="dv-sub">
                    {d.ebpf.node} · {providerLabel(d.ebpf.provider)}
                    {d.ebpf.nodeiso_available ? '' : ` · isolation not attached${d.ebpf.isolation?.unavailable ? ` (${d.ebpf.isolation.unavailable})` : ''}`}
                  </small>
                </td>
                <td className="dv-mono">{ni ? `${ni.policy.cidr} ${ni.policy.ports.length ? ni.policy.ports.join(',') : 'all ports'}` : '—'}</td>
                <td>
                  <Badge tone={tone}>{ni && ni.stage !== st?.mode ? `${ni.stage} (applying)` : st ? st.mode : 'none'}</Badge>
                  {st?.demoted && <small className="dv-sub">Demoted: {st.demoted}</small>}
                  {st?.agent_stale && <small className="dv-sub">Agent stale</small>}
                </td>
                <td>
                  {st ? (
                    <>
                      {st.mode === 'enforce' ? `${st.blocked_packets} blocked (${bytes(st.blocked_bytes)})` : `${st.would_block_packets} would block (${bytes(st.would_block_bytes)})`}
                      <small className="dv-sub">{st.allowed_packets} allowed</small>
                    </>
                  ) : (
                    '—'
                  )}
                </td>
                <td className="dv-mono">{st?.top.map((t) => `${t.address || t.peer}:${t.port}`).join(', ') || '—'}</td>
                <td>{ni?.stage === 'enforce' ? remaining(ni.lease_until) : '—'}</td>
                <td className="dv-actions">
                  {ni?.stage === 'shadow' && (
                    <button type="button" disabled={!isAdmin || kill.engaged || !netra.enforce_allowed} onClick={() => openPlanFor('isolate', [d.id], { stage: 'enforce', policy: ni.policy })}>
                      Promote to enforce
                    </button>
                  )}
                  {ni?.stage === 'enforce' && (
                    <button type="button" disabled={!isAdmin} onClick={() => openPlanFor('isolate', [d.id], { stage: 'shadow', policy: ni.policy })}>
                      Back to shadow
                    </button>
                  )}
                  {ni ? (
                    <button type="button" disabled={!isAdmin} onClick={() => openPlanFor('release', [d.id])}>
                      Release
                    </button>
                  ) : (
                    <button type="button" disabled={!isAdmin || !d.ebpf.nodeiso_available} onClick={() => openPlanFor('isolate', [d.id], { stage: 'shadow' })}>
                      Shadow allow-list
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      ) : (
        <Empty title="No eBPF-backed devices.">
          Run <code>duvora-agent --ebpf auto</code> on the host, or map devices to Netra nodes (DUVORA_NETRA_NODE_MAP / DUVORA_NETRA_DISCOVER=1).
        </Empty>
      )}
    </Section>
  );
}

export default function Isolation() {
  const { snapshot, openPlan, isAdmin, toast } = useFleet();
  const [device, setDevice] = useState('');
  const [address, setAddress] = useState('10.42.0.20');
  const [port, setPort] = useState('443');
  const [result, setResult] = useState<Verdict | null>(null);
  if (!snapshot) return null;
  const simulated = snapshot.devices.filter((d) => d.source === 'simulator');
  const target = device || simulated[0]?.id || '';

  async function evaluate(e: React.FormEvent) {
    e.preventDefault();
    try {
      setResult(await api<Verdict>('evaluate', 'POST', { device: target, address, port: Number(port) }));
    } catch (err) {
      toast((err as Error).message);
    }
  }

  return (
    <div className="grid">
      <div className="span3">
        <Notice>
          Simulated policies are model-only: they do not enforce a firewall, VLAN, VRF, or tenant boundary. Multiple allow-lists combine as a union. Node isolation (below) is real kernel
          enforcement on the node, by the native agent or Netra.
        </Notice>
      </div>
      <Section
        eyebrow="POLICIES"
        title="Isolation policies"
        lede="Scoped by device and labeled with tenant ownership."
        actions={
          <button type="button" className="primary" disabled={!isAdmin} onClick={() => openPlan('isolate')}>
            Create policy
          </button>
        }
      >
        {snapshot.policies.length ? (
          <Table heads={['Policy / tenant', 'Allowed CIDR', 'TCP/UDP ports', 'Devices', 'Mode']}>
            {snapshot.policies.map((p) => (
              <tr key={p.id}>
                <td>
                  <strong>{p.name}</strong>
                  <small className="dv-sub">Tenant {p.tenant}</small>
                </td>
                <td className="dv-mono">{p.cidr}</td>
                <td>{p.ports.length ? p.ports.join(', ') : 'All ports'}</td>
                <td>{p.devices.join(', ')}</td>
                <td>
                  <Badge tone={p.mode.endsWith('-enforce') ? 'warn' : 'info'}>{policyModeLabel(p.mode)}</Badge>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No isolation policies yet.">Select fleet devices and create a reviewed allow-list.</Empty>
        )}
      </Section>
      <NodeIsolation />
      <Section eyebrow="MODEL" title="Test a destination" lede="Evaluate the model without sending a packet.">
        <form className="toolbar" onSubmit={evaluate}>
          <label>
            Simulated device
            <select id="eval-device" value={target} onChange={(e) => setDevice(e.target.value)}>
              {simulated.map((d) => (
                <option key={d.id}>{d.id}</option>
              ))}
            </select>
          </label>
          <label className="tokenbox">
            Destination IP
            <input id="eval-ip" required value={address} onChange={(e) => setAddress(e.target.value)} />
          </label>
          <label className="tokenbox">
            Port
            <input id="eval-port" type="number" min={1} max={65535} required value={port} onChange={(e) => setPort(e.target.value)} />
          </label>
          <button className="primary" type="submit" disabled={!simulated.length || !isAdmin}>
            Evaluate
          </button>
        </form>
        {result && (
          <p className={`dv-verdict ${result.verdict}`} role="status">
            {result.verdict.toUpperCase()} · simulation only · {result.matched.join(', ') || 'No matching allow-list'}
          </p>
        )}
      </Section>
    </div>
  );
}

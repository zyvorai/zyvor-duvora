// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { Badge, Empty, Section, Table } from '../components/kit';
import { ago, providerLabel } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { EbpfOverview } from '../types';

const COPY: Record<string, string> = {
  simulator: 'Durable plans, jobs, policies, service records, upgrades, and rollback in the local model.',
  linux_discovery: 'Reads Linux sysfs PCI identity. No device writes or automatic readiness claims.',
  dpf_import: 'Imports Kubernetes DPF DPU objects using a read-only kubectl bridge.',
  ebpf_telemetry: 'Kernel-measured rates, drop reasons, TCP health, and talkers from the native Duvora agent (duvora-agent --ebpf) or Netra. Read-only.',
  hardware_enforcement:
    'DPU hardware enforcement is unavailable. Node isolation runs in the host kernel, through the native agent or Netra: shadow first, then a leased enforce with a kill switch.',
  firmware_flash: 'Requires vendor compatibility checks, signed artifacts, recovery validation, and a hardware adapter.',
  storage_offload: 'Requires a validated DOCA storage integration and supported hardware.',
};

export default function Capabilities() {
  const { snapshot } = useFleet();
  const { data } = useResource<EbpfOverview>('ebpf', 10000);
  if (!snapshot) return null;
  const netra = data?.netra;
  const agents = data?.native?.agents ?? 0;
  const netraText = netra?.configured
    ? `Netra: ${netra.connected ? 'connected' : 'not connected'} to ${netra.url || 'Netra'} · ${netra.nodes} node(s) · last sync ${netra.last_sync ? ago(netra.last_sync) : 'never'}${netra.error ? ` · ${netra.error}` : ''}`
    : 'Netra: not configured (optional).';
  return (
    <div className="grid">
      {Object.entries(snapshot.capabilities).map(([key, value]) => (
        <Section key={key} span={1} eyebrow="ADAPTER STATUS" title={key.replaceAll('_', ' ')}>
          <p>
            <Badge tone={value === 'available' ? 'ok' : value === 'unavailable' ? 'warn' : 'info'}>{value}</Badge>
          </p>
          <p>{COPY[key]}</p>
        </Section>
      ))}
      <Section
        eyebrow="eBPF PROBE"
        title="Kernel capabilities"
        lede={`Source: ${data?.source ?? 'auto'} · native agents reporting: ${agents} · ${netraText}`}
      >
        {data?.devices.length ? (
          <Table heads={['Device / node', 'Provider', 'Kernel', 'BTF', 'Programs attached', 'Drop reasons', 'TCP events', 'Node isolation']} label="eBPF capability probe">
            {data.devices.map((d) => (
              <tr key={d.id}>
                <td>
                  <strong>{d.id}</strong>
                  <small className="dv-sub">{d.node}</small>
                </td>
                <td>
                  <Badge tone={d.stale ? 'warn' : d.provider === 'native' ? 'ok' : 'info'}>{providerLabel(d.provider)}</Badge>
                  {d.stale && <small className="dv-sub">stale</small>}
                  {d.errors?.length ? <small className="dv-sub">{d.errors[0]}</small> : null}
                </td>
                <td className="dv-mono">{d.kernel || 'Unknown'}</td>
                <td>
                  <Badge tone={d.btf ? 'ok' : d.btf === null ? 'idle' : 'warn'}>{d.btf === null ? 'unknown' : d.btf ? 'yes' : 'no'}</Badge>
                </td>
                <td>
                  {d.attached}
                  <small className="dv-sub dv-mono">{d.programs.join(', ')}</small>
                </td>
                <td>{d.drop_info_unavailable ? <small className="dv-sub">{d.drop_info_unavailable}</small> : <Badge tone="ok">reporting</Badge>}</td>
                <td>{d.tcp_unavailable ? <small className="dv-sub">{d.tcp_unavailable}</small> : <Badge tone="ok">reporting</Badge>}</td>
                <td>
                  <Badge tone={d.nodeiso_available ? 'ok' : 'idle'}>{d.nodeiso_available ? 'available' : 'not attached'}</Badge>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No eBPF-backed devices yet.">
            Run <code>duvora-agent --ebpf auto</code> on a host (or enable the Helm agent DaemonSet)
            {netra?.configured ? `; unmatched Netra nodes: ${netra.unmatched.join(', ') || 'none'}` : ''}.
          </Empty>
        )}
      </Section>
    </div>
  );
}

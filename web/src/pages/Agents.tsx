import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Metrics, Section, Table } from '../components/kit';
import { ago, when } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { AgentIdentities, SiemStatus } from '../types';

export default function Agents() {
  const { isAdmin, toast } = useFleet();
  const { data: ids } = useResource<AgentIdentities>(isAdmin ? 'agent-identities' : null, 10000);
  const { data: siem, reload } = useResource<SiemStatus>(isAdmin ? 'siem' : null, 10000);
  const [busy, setBusy] = useState(false);

  if (!isAdmin) return <Empty title="Administrators only.">Agent identities and SIEM export settings are visible to administrators.</Empty>;

  async function test() {
    setBusy(true);
    try {
      const out = await api<SiemStatus & { flushed: number }>('siem/test', 'POST', {});
      toast(`Sent ${out.flushed} event${out.flushed === 1 ? '' : 's'} to the SIEM.`);
      void reload();
    } catch (e) {
      toast((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid">
      <Section
        eyebrow="AGENT IDENTITY"
        title="Who is reporting"
        lede="Host-bound bootstrap keys mint short-lived agent tokens that rotate at half their lifetime. With mutual TLS, the client certificate must name the agent's host."
      >
        {ids && (
          <Metrics
            items={[
              { label: 'agents', value: ids.identities.filter((i) => !i.unknown).length },
              { label: 'mutual TLS', value: ids.mtls },
              { label: 'bootstrap keys', value: ids.bootstrap_only ? 'token minting only' : 'full access' },
              { label: 'token lifetime', value: `${Math.round(ids.token_ttl / 3600)} h` },
            ]}
          />
        )}
        {ids?.identities.length ? (
          <Table heads={['Host', 'Credential', 'Token expires', 'Last rotation', 'Last seen', 'mTLS', 'Rejections (24 h)']} label="Agent identities">
            {ids.identities.map((i) => (
              <tr key={i.host}>
                <td className="dv-mono">
                  {i.host} {i.unknown && <Badge tone="bad">unknown</Badge>}
                  {!i.unknown && !i.known_device && <small className="dv-muted"> (no device yet)</small>}
                </td>
                <td>{i.unknown ? '—' : `${i.static_key ? 'bootstrap key' : 'no static key'}${i.tokens ? ` · ${i.tokens} token${i.tokens === 1 ? '' : 's'}` : ''}`}</td>
                <td>{when(i.token_expires)}</td>
                <td>{i.last_rotation ? ago(i.last_rotation) : 'never'}</td>
                <td>{i.last_seen ? `${ago(i.last_seen)} via ${i.last_via}` : '—'}</td>
                <td>{i.mtls_verified ? <Badge tone="ok">verified</Badge> : i.cert_names.length ? <Badge tone="warn">{i.cert_names.join(', ')}</Badge> : '—'}</td>
                <td>
                  {i.rejections.length ? (
                    <span title={i.rejections.map((r) => r.reason).join('\n')}>
                      <Badge tone="warn">{i.rejections.length}</Badge> <small>{i.rejections[i.rejections.length - 1].reason}</small>
                    </span>
                  ) : (
                    0
                  )}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No agents yet.">Agents appear when they report or mint a token (duvora-agent --ebpf).</Empty>
        )}
      </Section>

      <Section
        eyebrow="SIEM EXPORT"
        title="Send the evidence on"
        lede="Audit events, steering verdicts, AI findings, intel matches and playbook runs, batched to a JSON webhook and/or syslog (RFC 5424 over UDP, TCP or TLS)."
        actions={
          siem?.configured && (
            <button type="button" className="btn-diag" onClick={() => void test()} disabled={busy}>
              Send test event
            </button>
          )
        }
      >
        {siem?.configured ? (
          <Metrics
            items={[
              { label: 'webhook', value: siem.webhook || 'off' },
              { label: 'syslog', value: siem.syslog || 'off' },
              { label: 'verdicts exported', value: siem.verdicts || 'drop' },
              { label: 'queued / sent / dropped', value: `${siem.queued ?? 0} / ${siem.sent ?? 0} / ${siem.dropped ?? 0}`, note: siem.last_error || undefined },
            ]}
          />
        ) : (
          <Empty title="Not configured.">{siem?.note || 'Set DUVORA_SIEM_URL and/or DUVORA_SIEM_SYSLOG.'}</Empty>
        )}
        <p className="dv-fine">Categories: {siem?.categories.join(', ')}. Configure with DUVORA_SIEM_URL, DUVORA_SIEM_KEY, DUVORA_SIEM_SYSLOG, DUVORA_SIEM_VERDICTS (all, drop or none) and DUVORA_SIEM_EVENTS.</p>
      </Section>
    </div>
  );
}

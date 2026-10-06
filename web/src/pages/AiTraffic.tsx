import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Metrics, Notice, Section, Table, severityTone } from '../components/kit';
import { ago, percent } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { AiAssets, AiTraffic as AiTrafficData } from '../types';

const KIND_LABEL = { 'prompt-injection': 'Prompt injection', secret: 'Secret', pii: 'Personal data' } as const;

export default function AiTraffic() {
  const { isAdmin, toast, navigate } = useFleet();
  const { data } = useResource<AiTrafficData>('ai-traffic', 10000);
  const { data: assets, reload: reloadAssets } = useResource<AiAssets>('ai/assets', 15000);
  const [sanction, setSanction] = useState('');

  if (!data) return null;
  const counts = data.counts_24h;
  const findings = counts['prompt-injection'] + counts.secret + counts.pii;

  async function addSanctioned(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api('ai/sanctioned', 'POST', { name: sanction.trim() });
      setSanction('');
      void reloadAssets();
    } catch (err) {
      toast((err as Error).message);
    }
  }

  async function removeSanctioned(id: string) {
    try {
      await api(`ai/sanctioned/${id}`, 'DELETE');
      void reloadAssets();
    } catch (err) {
      toast((err as Error).message);
    }
  }

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">AI TRAFFIC</p>
        <h2 className="card-title">
          {data.endpoints.length
            ? `${data.endpoints.length} LLM endpoint${data.endpoints.length === 1 ? '' : 's'} seen, ${findings} finding${findings === 1 ? '' : 's'} in 24 hours.`
            : 'No LLM traffic inspected yet.'}
        </h2>
        <Metrics
          items={[
            { label: 'prompt injection', value: counts['prompt-injection'], note: '24 h' },
            { label: 'secrets to an LLM', value: counts.secret, note: '24 h' },
            { label: 'personal data', value: counts.pii, note: '24 h' },
            { label: 'inspection coverage', value: percent(data.coverage.overall || 0), note: 'of LLM-bound flows' },
          ]}
        />
        <p className="dv-fine">
          Steering rules with the inspect action sample the start of each flow. The analyzer reads TLS SNI and HTTP requests, classifies LLM providers and self-hosted inference servers, and checks prompts for
          injection, secrets and personal data. Snippets are redacted before they are stored. Inspection never blocks — to block, add a drop rule through a reviewed plan (a playbook can draft one).
        </p>
      </section>

      <Section span={2} eyebrow="ENDPOINTS" title="Where AI traffic goes" lede="Hosted APIs (by SNI or Host) and self-hosted inference servers, per device.">
        {data.endpoints.length ? (
          <Table heads={['Device', 'Endpoint', 'Provider', 'Kind', 'Requests', 'Findings', 'Last seen']} label="LLM endpoints">
            {data.endpoints.map((e) => (
              <tr key={e.device + e.endpoint + e.port}>
                <td className="dv-mono">{e.device}</td>
                <td className="dv-mono">
                  {e.endpoint}
                  {e.port ? `:${e.port}` : ''}
                  {e.serves === 'this node' && <small className="dv-muted"> (served here)</small>}
                </td>
                <td>{e.provider}</td>
                <td>
                  <Badge tone={e.kind === 'hosted' ? 'info' : 'idle'}>{e.kind}</Badge>
                </td>
                <td>{e.requests}</td>
                <td>{e.findings ? <Badge tone="warn">{e.findings}</Badge> : 0}</td>
                <td>{ago(e.last)}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="Nothing inspected.">
            Apply a rule set with inspect rules for LLM ports (443, 8000, 11434) under{' '}
            <button type="button" className="btn-diag" onClick={() => navigate('steering')}>
              Operate → Steering
            </button>
            .
          </Empty>
        )}
      </Section>

      <Section span={1} eyebrow="COVERAGE" title="Inspected share" lede="LLM-bound flows that steering inspects, per device.">
        {Object.entries(data.coverage.devices || {}).length ? (
          <div className="list">
            {Object.entries(data.coverage.devices || {}).map(([id, c]) => (
              <div className="agent wide" key={id}>
                <b className="dv-mono">{id}</b>
                <small>
                  <Badge tone={c >= 0.9 ? 'ok' : c > 0 ? 'warn' : 'bad'}>{percent(c)}</Badge>
                </small>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No devices." />
        )}
      </Section>

      <Section eyebrow="FINDINGS" title="Threats in prompts and payloads" lede="Newest first. A finding opens an incident (llm-prompt-injection, llm-secret-leak, llm-sensitive-data); the llm-threat playbook drafts a block.">
        {data.findings.length ? (
          <Table heads={['When', 'Device', 'Kind', 'Detail', 'Endpoint', 'Snippet (redacted)']} label="AI findings">
            {data.findings.slice(0, 50).map((f) => (
              <tr key={f.id}>
                <td>{ago(f.ts)}</td>
                <td className="dv-mono">{f.device}</td>
                <td>
                  <Badge tone={severityTone(f.severity)}>{KIND_LABEL[f.kind]}</Badge>
                </td>
                <td>{f.detail}</td>
                <td className="dv-mono">{f.endpoint || f.peer || '—'}</td>
                <td className="dv-mono">{f.snippet}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No findings." />
        )}
      </Section>

      <Section
        eyebrow="AI ASSETS"
        title="AI services running on nodes"
        lede="Inference runtimes, vector databases, MCP servers and AI gateways found by the agent in /proc (listening sockets and process names). Add sanctioned names to flag everything else."
      >
        {assets?.assets.length ? (
          <Table heads={['Device', 'Service', 'Kind', 'Port', 'Evidence', 'Last seen', 'Status']} label="AI assets">
            {assets.assets.map((a) => (
              <tr key={a.device + a.name + a.port}>
                <td className="dv-mono">{a.device}</td>
                <td className="dv-mono">{a.name}</td>
                <td>{a.kind}</td>
                <td>{a.port}</td>
                <td>{a.evidence}</td>
                <td>{ago(a.last)}</td>
                <td>{!assets.policy_active ? <span className="dv-muted">no policy</span> : a.sanctioned ? <Badge tone="ok">sanctioned</Badge> : <Badge tone="warn">unsanctioned</Badge>}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No AI services found.">Agents report what they find every five minutes (duvora-agent --ebpf; disable with --no-ai-discovery).</Empty>
        )}
        <div className="dv-fields">
          <p className="dv-fine">
            Sanctioned: {assets?.sanctioned.length ? assets.sanctioned.map((s) => (
              <span key={s.id}>
                <Badge tone="ok">{s.name || s.kind || s.id}</Badge>
                {isAdmin && (
                  <button type="button" className="btn-diag" onClick={() => void removeSanctioned(s.id)} aria-label={`Remove ${s.name || s.id}`}>
                    ✕
                  </button>
                )}{' '}
              </span>
            )) : 'none — the unsanctioned-ai rule stays quiet until you add one.'}
          </p>
          {isAdmin && (
            <form onSubmit={addSanctioned} className="dv-inline">
              <input aria-label="Sanctioned service name" placeholder="vllm" value={sanction} onChange={(e) => setSanction(e.target.value)} />
              <button type="submit" className="btn-diag" disabled={!sanction.trim()}>
                Sanction
              </button>
            </form>
          )}
        </div>
        <Notice>Discovery and inspection run on the host and in the control plane. Duvora does not run on, or offload to, DPU hardware.</Notice>
      </Section>
    </div>
  );
}

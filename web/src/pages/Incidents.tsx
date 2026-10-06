import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Metrics, Section, Table, severityTone } from '../components/kit';
import { ago, when } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { Explanation, Incident } from '../types';

const CONFIDENCE = { high: 'bad', medium: 'warn', low: 'idle' } as const;

function Explain({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, error } = useResource<Explanation>(`incidents/${id}/explain`, 0, [id]);
  return (
    <Section
      eyebrow="EXPLAIN"
      title={data ? data.incident.title : 'Gathering evidence…'}
      lede={data ? (data.narrative_source === 'llm' ? 'Written by the language model from the evidence below. Review before acting.' : 'Assembled from rule-based checks of the evidence.') : undefined}
      actions={
        <button type="button" className="btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      {error && <p className="login-error">{error}</p>}
      {data && (
        <>
          <p>{data.narrative}</p>
          {data.narrative_error && <p className="dv-fine">Language model unavailable ({data.narrative_error}); showing the rule-based explanation.</p>}
          <div className="dv-hyp">
            {data.hypotheses.map((h) => (
              <div key={h.id}>
                <Badge tone={CONFIDENCE[h.confidence]}>{h.confidence}</Badge> <strong>{h.id.replace(/-/g, ' ')}</strong>
                <p>{h.text}</p>
                {h.signals.length > 0 && <small className="dv-sub">{h.signals.join(' · ')}</small>}
              </div>
            ))}
          </div>
          {data.related.length > 0 && (
            <p className="dv-fine">Related within 30 minutes: {data.related.map((r) => r.title).join('; ')}</p>
          )}
          {data.jobs.length > 0 && <p className="dv-fine">Changes nearby: {data.jobs.map((j) => `${j.action}${j.stage ? ` (${j.stage})` : ''} ${j.state} ${ago(j.created)}`).join('; ')}</p>}
        </>
      )}
    </Section>
  );
}

const FILTERS = ['active', 'open', 'acknowledged', 'resolved'] as const;

export default function Incidents() {
  const { isAdmin, toast, refresh } = useFleet();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>('active');
  const [explaining, setExplaining] = useState<string | null>(null);
  const { data, reload } = useResource<Incident[]>(`incidents?state=${filter}`, 5000, [filter]);
  const { data: all } = useResource<Incident[]>('incidents?state=active', 5000);
  const active = all || [];

  async function act(id: string, action: 'ack' | 'resolve') {
    try {
      await api(`incidents/${id}/${action}`, 'POST', {});
      toast(action === 'ack' ? 'Incident acknowledged.' : 'Incident resolved. It reopens if the rule still fires.');
      await Promise.all([reload(), refresh()]);
    } catch (e) {
      toast((e as Error).message);
    }
  }

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">MONITOR</p>
        <h2 className="card-title">{active.length ? `${active.length} incident${active.length === 1 ? '' : 's'} need attention.` : 'No alert rule is firing.'}</h2>
        <Metrics
          items={[
            { label: 'critical', value: active.filter((i) => i.severity === 'critical').length },
            { label: 'warning', value: active.filter((i) => i.severity === 'warning').length },
            { label: 'info', value: active.filter((i) => i.severity === 'info').length },
            { label: 'acknowledged', value: active.filter((i) => i.state === 'acknowledged').length },
          ]}
        />
      </section>
      <Section
        eyebrow="INCIDENTS"
        title="Incident list"
        lede="Rules are evaluated every 5 seconds. An incident resolves automatically once its condition clears."
        actions={
          <div className="chips" role="group" aria-label="Incident filter">
            {FILTERS.map((f) => (
              <button key={f} type="button" className={f === filter ? 'primary' : ''} aria-pressed={f === filter} onClick={() => setFilter(f)}>
                {f}
              </button>
            ))}
          </div>
        }
      >
        {data?.length ? (
          <Table heads={['Severity', 'Incident', 'State', 'Opened', '']} label="Incidents">
            {data.map((i) => (
              <tr key={i.id}>
                <td>
                  <Badge tone={severityTone(i.severity)}>{i.severity}</Badge>
                </td>
                <td>
                  <strong>{i.title}</strong>
                  <small className="dv-sub">{i.detail}</small>
                </td>
                <td>
                  {i.state}
                  <small className="dv-sub">
                    {i.state === 'acknowledged' && `by ${i.acknowledged_by}`}
                    {i.state === 'resolved' && `by ${i.resolved_by} · ${when(i.resolved_at)}`}
                  </small>
                </td>
                <td>
                  {ago(i.opened)}
                  <small className="dv-sub">{when(i.opened)}</small>
                </td>
                <td>
                  <div className="dv-actions">
                  <button type="button" className="btn-secondary" onClick={() => setExplaining(i.id)} aria-pressed={explaining === i.id}>
                    Explain
                  </button>
                  {isAdmin && i.state === 'open' && (
                    <button type="button" className="btn-secondary" onClick={() => act(i.id, 'ack')}>
                      Acknowledge
                    </button>
                  )}
                  {isAdmin && i.state !== 'resolved' && (
                    <button type="button" className="btn-success" onClick={() => act(i.id, 'resolve')}>
                      Resolve
                    </button>
                  )}
                </div>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title={filter === 'active' ? 'All clear.' : `No ${filter} incidents.`}>Incidents appear when an alert rule fires.</Empty>
        )}
      </Section>
      {explaining && <Explain key={explaining} id={explaining} onClose={() => setExplaining(null)} />}
    </div>
  );
}

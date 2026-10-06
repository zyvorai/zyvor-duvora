import { useState } from 'react';
import { download, saveJSON } from '../api';
import { Badge, Empty, Metrics, Section, severityTone } from '../components/kit';
import { eta, metric, percent, when, zLabel } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { Briefing } from '../types';
import { Ring } from './Scorecard';

export default function Report() {
  const { toast } = useFleet();
  const [ai, setAi] = useState(false);
  const { data, reload } = useResource<Briefing>(ai ? 'report?ai=1' : 'report', 0, [ai]);
  if (!data) return null;
  const actions = (
    <>
      <button type="button" className={ai ? 'primary' : 'btn-secondary'} aria-pressed={ai} onClick={() => setAi(!ai)}>
        AI summary
      </button>
      <button type="button" className="btn-secondary" onClick={() => void reload()}>
        Refresh
      </button>
      <button type="button" className="btn-secondary" onClick={() => window.print()}>
        Print
      </button>
      <button type="button" className="btn-secondary" onClick={() => download('report.md', 'duvora-briefing.md').catch((e) => toast(e.message))}>
        Markdown
      </button>
      <button type="button" className="primary" onClick={() => saveJSON(data, 'duvora-briefing.json')}>
        Export JSON
      </button>
    </>
  );
  return (
    <div className="grid dv-report">
      <Section eyebrow={`GENERATED ${when(data.generated).toUpperCase()}`} title="Shift briefing" actions={actions}>
        <div className="dv-score">
          <Ring score={data.scorecard.score} />
          <div>
            <h3>{data.scorecard.grade}</h3>
            <Metrics
              items={[
                { label: 'devices', value: data.fleet.total },
                { label: 'active incidents', value: data.incidents.length },
                { label: 'operations in 24 h', value: data.jobs.length },
                ...Object.entries(data.fleet.by_health).map(([k, v]) => ({ label: k, value: v })),
              ]}
            />
          </div>
        </div>
      </Section>
      {data.summary && (
        <Section eyebrow="SUMMARY" title="At a glance" lede={data.summary_source === 'llm' ? 'Written by the language model from this briefing. Review before acting.' : 'Generated from the briefing data; no language model is configured.'}>
          <p>{data.summary}</p>
        </Section>
      )}
      {(data.anomalies?.length || data.forecasts?.length || data.allowlist_suggestions?.length) ? (
        <Section eyebrow="INSIGHTS" title="Trends and suggestions">
          <ul className="dv-steps">
            {data.anomalies?.map((a) => (
              <li key={`a${a.device}${a.metric}`}>
                {a.metric} on {a.device}: {metric(a.value)} vs baseline {metric(a.baseline)} ({zLabel(a.z)})
              </li>
            ))}
            {data.forecasts?.map((f) => (
              <li key={`f${f.device}${f.metric}`}>
                {f.metric} on {f.device} crosses {f.threshold} in about {eta(f.eta_hours)}
              </li>
            ))}
            {data.allowlist_suggestions?.map((s) => (
              <li key={`s${s.device}`}>
                Shadow allow-list for {s.device}: {s.cidr} {s.ports.length ? `ports ${s.ports.join(', ')}` : 'any port'} covers {percent(s.coverage_bytes)} of observed bytes
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      {data.ai_posture && (
        <Section
          eyebrow="AI SECURITY"
          title={`AI posture: ${data.ai_posture.score} (${data.ai_posture.grade})`}
          lede={`Steering: ${data.ai_posture.steering.shadow} shadow, ${data.ai_posture.steering.enforce} enforce, ${data.ai_posture.steering.bypass} bypassed of ${data.ai_posture.steering.devices} devices. ${data.ai_posture.note}`}
        >
          <div className="list">
            {data.ai_posture.checks.map((c) => (
              <div className="agent wide" key={c.name}>
                <b>
                  <Badge tone={c.status === 'pass' ? 'ok' : c.status === 'warn' ? 'warn' : 'bad'}>{c.status}</Badge> {c.name} · {c.score}/{c.weight}
                </b>
                <small>
                  {c.detail}
                  {c.action ? ` — ${c.action}` : ''}
                </small>
              </div>
            ))}
          </div>
        </Section>
      )}
      <Section span={2} eyebrow="INCIDENTS" title="Active incidents">
        {data.incidents.length ? (
          <div className="list">
            {data.incidents.map((i) => (
              <div className="agent wide" key={i.id}>
                <b>
                  <Badge tone={severityTone(i.severity)}>{i.severity}</Badge> {i.title}
                </b>
                <small>
                  {i.detail} · {i.state}
                </small>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="None." />
        )}
      </Section>
      <Section span={1} eyebrow="PLAYBOOK" title="Suggested next steps" lede="Review only. Nothing on this page applies a change.">
        <ol className="dv-steps">
          {data.playbook.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>
      </Section>
      <Section eyebrow="OPERATIONS" title="Last 24 hours">
        {data.jobs.length ? (
          <div className="list">
            {data.jobs.map((j) => (
              <div className="agent wide" key={j.id}>
                <b>
                  {j.action} · {j.state}
                </b>
                <small>
                  {j.spec.devices.join(', ')} · {when(j.created)} · {j.actor}
                </small>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No operations in the last 24 hours." />
        )}
      </Section>
    </div>
  );
}

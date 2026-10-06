import { Badge, Empty, Metrics, Section, Table } from '../components/kit';
import { ago, bytes, eta, metric, zLabel } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { AiStatus, Insights as InsightsData } from '../types';

export default function Insights() {
  const { inspect } = useFleet();
  const { data } = useResource<InsightsData>('insights', 10000);
  const { data: ai } = useResource<AiStatus>('ai');
  if (!data) return null;
  const due = data.forecasts.filter((f) => f.eta_hours !== null && f.eta_hours <= data.forecast_horizon_hours);
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">INSIGHTS</p>
        <h2 className="card-title">
          {data.anomalies.length || due.length || data.new_destinations.length
            ? `${data.anomalies.length} anomal${data.anomalies.length === 1 ? 'y' : 'ies'}, ${due.length} forecast breach${due.length === 1 ? '' : 'es'}, ${data.new_destinations.length} new destination${data.new_destinations.length === 1 ? '' : 's'}.`
            : 'Everything is within its learned baseline.'}
        </h2>
        <Metrics
          items={[
            { label: 'metrics tracked', value: data.baselines.tracked },
            { label: 'baselines warm', value: data.baselines.warm, note: `after ${data.baselines.warmup} samples` },
            { label: 'forecast horizon', value: `${data.forecast_horizon_hours} h` },
            { label: 'language model', value: ai?.llm ? ai.model || 'configured' : 'off', note: ai?.llm && ai.redact ? 'redacted' : undefined },
          ]}
        />
        <p className="dv-fine">
          Anomalies, forecasts, new destinations and allow-list suggestions are computed on the control plane from recorded samples and flow records; nothing leaves it.
          {ai?.llm ? ` Explanations, the briefing summary and the copilot use ${ai.model} at ${ai.endpoint}.` : ' Set DUVORA_AI_URL and DUVORA_AI_MODEL to enable the copilot and written explanations.'}
        </p>
      </section>
      <Section eyebrow="ANOMALIES" title="Away from baseline" lede="An anomaly fires after three consecutive samples beyond the z-score threshold in the same direction (Monitor → Alert rules → anomaly).">
        {data.anomalies.length ? (
          <Table heads={['Device', 'Metric', 'Now', 'Baseline', 'Deviation']} label="Anomalies">
            {data.anomalies.map((a) => (
              <tr key={a.device + a.metric}>
                <td>
                  <button type="button" className="btn-diag" onClick={() => inspect(a.device)}>
                    {a.device}
                  </button>
                </td>
                <td className="dv-mono">{a.metric}</td>
                <td>{metric(a.value)}</td>
                <td>
                  {metric(a.baseline)} ± {metric(a.std)}
                </td>
                <td>
                  <Badge tone={Math.abs(a.z) >= 8 ? 'bad' : 'warn'}>{zLabel(a.z)}</Badge>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No anomalies.">Baselines learn from every sample; new devices need a few minutes of data first.</Empty>
        )}
      </Section>
      <Section span={2} eyebrow="FORECASTS" title="Trending toward a threshold" lede="Linear fit over the last 24 hours; shown only when it explains at least half the variance (R² ≥ 0.5).">
        {data.forecasts.length ? (
          <Table heads={['Device', 'Metric', 'Now', 'Threshold', 'Trend / h', 'Crosses in', 'R²']} label="Forecasts">
            {data.forecasts.map((f) => (
              <tr key={f.device + f.metric}>
                <td>{f.device}</td>
                <td className="dv-mono">{f.metric}</td>
                <td>{metric(f.current ?? undefined)}</td>
                <td>{f.threshold}</td>
                <td>{f.slope_per_hour === null ? '—' : f.slope_per_hour.toFixed(3)}</td>
                <td>{f.eta_hours !== null && f.eta_hours <= data.forecast_horizon_hours ? <Badge tone="warn">{eta(f.eta_hours)}</Badge> : eta(f.eta_hours)}</td>
                <td>{f.r2 ?? '—'}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No reliable trend yet.">Forecasts need at least 12 five-minute buckets of history.</Empty>
        )}
      </Section>
      <Section span={1} eyebrow="EGRESS" title="New destinations" lede="Peers first seen in the last 15 minutes and not in the previous 24 hours.">
        {data.new_destinations.length ? (
          <div className="list">
            {data.new_destinations.slice(0, 12).map((x) => (
              <div className="agent wide" key={x.device + x.peer + x.port + x.protocol}>
                <b className="dv-mono">
                  {x.peer}:{x.port}/{x.protocol}
                </b>
                <small>
                  {x.device} · {bytes(x.bytes)} · {ago(x.first_seen)}
                </small>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="None new." />
        )}
      </Section>
    </div>
  );
}

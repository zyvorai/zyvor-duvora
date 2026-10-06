import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Metrics, Notice, Section, Table, type Tone } from '../components/kit';
import { ago, bytes, metric } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { RuleSet, SteerAction, SteeringOverview, SteeringSuggestions, Verdict } from '../types';

export const actionTone: Record<SteerAction, Tone> = { bypass: 'idle', allow: 'ok', inspect: 'info', drop: 'bad' };

const TEMPLATE = {
  description: 'Inspect LLM traffic, keep storage on the fast path',
  default: 'bypass',
  rules: [
    { priority: 10, name: 'bypass-rdma', action: 'bypass', protocol: 'udp', dport: 4791 },
    { priority: 20, name: 'inspect-llm', action: 'inspect', direction: 'egress', protocol: 'tcp', dport: 443 },
    { priority: 30, name: 'drop-bad-range', action: 'drop', dst: '203.0.113.0/24' },
  ],
};

export default function Steering() {
  const { isAdmin, openPlanFor, toast, refresh } = useFleet();
  const { data, reload } = useResource<SteeringOverview>('steering', 5000);
  const [filter, setFilter] = useState<SteerAction | ''>('');
  const { data: verdicts } = useResource<Verdict[]>(`verdicts?limit=100${filter ? `&action=${filter}` : ''}`, 5000, [filter]);
  const [editing, setEditing] = useState<{ id: string; text: string } | null>(null);
  const [editError, setEditError] = useState('');
  const [suggestFor, setSuggestFor] = useState('');
  const { data: suggestion } = useResource<SteeringSuggestions>(suggestFor ? `devices/${suggestFor}/steering-suggestions` : null, 0, [suggestFor]);
  const [test, setTest] = useState({ ruleset: '', direction: 'egress', protocol: 'tcp', dst: '185.220.101.4', dport: '443' });
  const [testResult, setTestResult] = useState<string>('');

  if (!data) return null;
  const steered = data.devices.filter((d) => d.steering);
  const bypassed = steered.filter((d) => d.steering?.bypass?.engaged);
  const totals = steered.reduce(
    (acc, d) => {
      const s = d.status?.stats || {};
      acc.inspected += s.inspected || 0;
      acc.drop += (s.dropped || 0) + (s.would_drop || 0);
      return acc;
    },
    { inspected: 0, drop: 0 },
  );

  async function edit(id: string) {
    setEditError('');
    if (!id) {
      setEditing({ id: 'new-ruleset', text: JSON.stringify(TEMPLATE, null, 2) });
      return;
    }
    const rs = await api<RuleSet>(`steering/sets/${id}`);
    setEditing({ id, text: JSON.stringify({ description: rs.description, default: rs.default, rules: rs.rules }, null, 2) });
  }

  async function save() {
    if (!editing) return;
    setEditError('');
    try {
      await api(`steering/sets/${encodeURIComponent(editing.id)}`, 'PUT', JSON.parse(editing.text));
      toast(`Saved rule set ${editing.id}. Apply it to devices through a plan.`);
      setEditing(null);
      void reload();
    } catch (e) {
      setEditError((e as Error).message);
    }
  }

  async function remove(id: string) {
    try {
      await api(`steering/sets/${id}`, 'DELETE');
      void reload();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  async function bypass(device: string, engaged: boolean) {
    const word = engaged ? `BYPASS ${device}` : `RESUME ${device}`;
    const typed = window.prompt(
      engaged ? `Bypass passes all traffic on ${device} uninspected. Type ${word} to confirm.` : `Resume steering on ${device}. Type ${word} to confirm.`,
    );
    if (typed === null) return;
    try {
      await api(`devices/${device}/steering/bypass`, 'POST', { engaged, confirmation: typed, reason: 'operator' });
      toast(engaged ? `Bypass engaged on ${device}.` : `Steering resumed on ${device}.`);
      void reload();
      void refresh();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  async function evaluate(e: React.FormEvent) {
    e.preventDefault();
    try {
      const flow: Record<string, unknown> = { direction: test.direction, protocol: test.protocol, dst: test.dst || undefined };
      if (test.dport) flow.dport = Number(test.dport);
      const out = await api<{ action: SteerAction; rule: string | null; trace?: { rule: string; matched?: boolean; why?: string }[] }>(
        'steering/evaluate',
        'POST',
        { ruleset: test.ruleset || data?.sets[0]?.id, flow },
      );
      setTestResult(`${out.action.toUpperCase()} by ${out.rule || 'the default action'}`);
    } catch (err) {
      setTestResult((err as Error).message);
    }
  }

  async function saveSuggestion() {
    if (!suggestion) return;
    const { id, ...body } = suggestion.ruleset;
    try {
      await api(`steering/sets/${id}`, 'PUT', { description: body.description, default: body.default, rules: body.rules });
      toast(`Saved ${id}. Preview it in shadow before enforcing.`);
      setSuggestFor('');
      void reload();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">TRAFFIC STEERING</p>
        <h2 className="card-title">
          {steered.length ? `${steered.length} device${steered.length === 1 ? '' : 's'} steered, ${bypassed.length} in bypass.` : 'No device is steered yet.'}
        </h2>
        <Metrics
          items={[
            { label: 'rule sets', value: data.sets.length, note: `up to ${data.limits.max_rules} rules each` },
            { label: 'packets inspected', value: metric(totals.inspected) },
            { label: 'dropped / would drop', value: metric(totals.drop) },
            { label: 'enforcement', value: data.kill_switch ? 'kill switch' : data.enforce_allowed ? 'allowed' : 'off', note: 'native agents only' },
          ]}
        />
        <p className="dv-fine">
          Ordered 5-tuple rules decide per packet: bypass, allow, inspect (sample the payload for AI-traffic analysis) or drop. {data.note} Simulated devices evaluate a modeled flow catalog; agent-backed
          devices run duvora_steer on the host&apos;s uplinks in shadow, or in enforce with a lease that falls back to shadow. SSH and the control plane are always exempt.
        </p>
      </section>

      <Section
        span={2}
        eyebrow="RULE SETS"
        title="Policies to steer by"
        lede="First match wins; unmatched traffic takes the default. Saving a rule set changes nothing on a device until a reviewed plan applies it."
        actions={
          isAdmin && (
            <button type="button" className="btn-diag" onClick={() => void edit('')}>
              New rule set
            </button>
          )
        }
      >
        {data.sets.length ? (
          <Table heads={['Rule set', 'Rules', 'Default', 'Applied to', '']} label="Rule sets">
            {data.sets.map((s) => (
              <tr key={s.id}>
                <td>
                  <b className="dv-mono">{s.id}</b>
                  <br />
                  <small className="dv-muted">{s.description}</small>
                </td>
                <td>
                  {s.rule_count}{' '}
                  {(Object.entries(s.actions) as [SteerAction, number][])
                    .filter(([, n]) => n)
                    .map(([a, n]) => (
                      <Badge key={a} tone={actionTone[a]}>
                        {n} {a}
                      </Badge>
                    ))}
                </td>
                <td>{s.default}</td>
                <td className="dv-mono">{s.devices.join(', ') || '—'}</td>
                <td className="actions">
                  <button type="button" className="btn-diag" onClick={() => void edit(s.id)}>
                    {isAdmin ? 'Edit' : 'View'}
                  </button>
                  {isAdmin && !s.devices.length && (
                    <button type="button" className="btn-diag" onClick={() => void remove(s.id)}>
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No rule sets.">Create one, or generate one from observed traffic below.</Empty>
        )}
        {editing && (
          <div className="dv-fields">
            <label className="tokenbox" htmlFor="rs-id">
              Rule set id
              <input id="rs-id" value={editing.id} onChange={(e) => setEditing({ ...editing, id: e.target.value })} disabled={!isAdmin} />
            </label>
            <label className="tokenbox" htmlFor="rs-body">
              Rules (JSON: description, default bypass|drop, rules with priority, name, action, direction, src, dst, protocol, sport, dport)
              <textarea id="rs-body" className="dv-mono" rows={14} value={editing.text} onChange={(e) => setEditing({ ...editing, text: e.target.value })} readOnly={!isAdmin} />
            </label>
            {editError && <p className="login-error">{editError}</p>}
            <div className="dv-dialog-actions">
              <button type="button" className="btn-diag" onClick={() => setEditing(null)}>
                Close
              </button>
              {isAdmin && (
                <button type="button" className="primary" onClick={() => void save()}>
                  Save rule set
                </button>
              )}
            </div>
          </div>
        )}
      </Section>

      <Section span={1} eyebrow="TEST" title="Which rule wins?" lede="Evaluate one flow against a rule set, with the decision trace.">
        <form className="dv-fields" onSubmit={evaluate}>
          <label className="tokenbox" htmlFor="t-rs">
            Rule set
            <select id="t-rs" value={test.ruleset} onChange={(e) => setTest({ ...test, ruleset: e.target.value })}>
              {data.sets.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id}
                </option>
              ))}
            </select>
          </label>
          <label className="tokenbox" htmlFor="t-dir">
            Direction
            <select id="t-dir" value={test.direction} onChange={(e) => setTest({ ...test, direction: e.target.value })}>
              <option value="egress">egress</option>
              <option value="ingress">ingress</option>
            </select>
          </label>
          <label className="tokenbox" htmlFor="t-proto">
            Protocol
            <select id="t-proto" value={test.protocol} onChange={(e) => setTest({ ...test, protocol: e.target.value })}>
              {['tcp', 'udp', 'icmp'].map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </label>
          <label className="tokenbox" htmlFor="t-dst">
            Destination address
            <input id="t-dst" value={test.dst} onChange={(e) => setTest({ ...test, dst: e.target.value })} />
          </label>
          <label className="tokenbox" htmlFor="t-port">
            Destination port
            <input id="t-port" value={test.dport} onChange={(e) => setTest({ ...test, dport: e.target.value })} />
          </label>
          <button type="submit" className="btn-diag" disabled={!data.sets.length}>
            Evaluate
          </button>
          {testResult && <p className="dv-mono">{testResult}</p>}
        </form>
      </Section>

      <Section eyebrow="DEVICES" title="Steering per device" lede="Stage, bypass and counters. Bypass is immediate, audited, and raises an incident if it lasts longer than the steering-bypass rule allows.">
        <Table heads={['Device', 'Provider', 'Rule set', 'Stage', 'Inspected', 'Dropped / would drop', 'Bypass', '']} label="Device steering">
          {data.devices.map((d) => {
            const s = d.steering;
            const st = d.status?.stats || {};
            return (
              <tr key={d.id}>
                <td className="dv-mono">{d.id}</td>
                <td>{d.provider || 'none'}</td>
                <td className="dv-mono">{s?.ruleset || '—'}</td>
                <td>{s ? <Badge tone={s.stage === 'enforce' ? 'warn' : 'info'}>{s.stage}</Badge> : d.steer_available ? 'available' : 'unavailable'}</td>
                <td>{s ? metric(st.inspected) : '—'}</td>
                <td>{s ? `${metric(st.dropped)} / ${metric(st.would_drop)}` : '—'}</td>
                <td>{s?.bypass?.engaged ? <Badge tone="warn">{`on · ${s.bypass.reason || 'manual'}${s.bypass.since ? ` · ${ago(s.bypass.since)}` : ''}`}</Badge> : s ? 'off' : '—'}</td>
                <td className="actions">
                  {isAdmin && d.steer_available && (
                    <>
                      <button type="button" className="btn-diag" onClick={() => openPlanFor('steer', [d.id], { ruleset: s?.ruleset || data.sets[0]?.id })}>
                        {s ? 'Change' : 'Steer'}
                      </button>
                      {s?.stage === 'shadow' && (
                        <button type="button" className="btn-diag" onClick={() => openPlanFor('steer', [d.id], { ruleset: s.ruleset, stage: 'enforce' })}>
                          Promote
                        </button>
                      )}
                      {s && (
                        <button type="button" className="btn-diag" onClick={() => void bypass(d.id, !s.bypass?.engaged)}>
                          {s.bypass?.engaged ? 'Resume' : 'Bypass'}
                        </button>
                      )}
                      {s && (
                        <button type="button" className="btn-diag" onClick={() => openPlanFor('unsteer', [d.id])}>
                          Remove
                        </button>
                      )}
                    </>
                  )}
                  <button type="button" className="btn-diag" onClick={() => setSuggestFor(d.id)}>
                    Suggest
                  </button>
                </td>
              </tr>
            );
          })}
        </Table>
        {suggestFor && suggestion && suggestion.device === suggestFor && (
          <div className="dv-plan">
            <p>
              Suggested rule set <b className="dv-mono">{suggestion.ruleset.id}</b> from traffic on {suggestFor}: {suggestion.ruleset.rules.length} rules, default {suggestion.ruleset.default}.
            </p>
            <Table heads={['Priority', 'Name', 'Action', 'Match', 'Why']} label="Suggested rules">
              {suggestion.ruleset.rules.map((r) => (
                <tr key={r.name}>
                  <td>{r.priority}</td>
                  <td className="dv-mono">{r.name}</td>
                  <td>
                    <Badge tone={actionTone[r.action]}>{r.action}</Badge>
                  </td>
                  <td className="dv-mono">
                    {r.direction} {r.protocol} {r.dst !== 'any' ? r.dst : ''} {r.dport !== 'any' ? `:${r.dport}` : ''}
                  </td>
                  <td>{r.note || ''}</td>
                </tr>
              ))}
            </Table>
            <div className="dv-dialog-actions">
              <button type="button" className="btn-diag" onClick={() => setSuggestFor('')}>
                Dismiss
              </button>
              {isAdmin && (
                <button type="button" className="primary" onClick={() => void saveSuggestion()}>
                  Save as rule set
                </button>
              )}
            </div>
          </div>
        )}
      </Section>

      <Section
        eyebrow="VERDICTS"
        title="What steering decided"
        lede="Sampled flow verdicts (bypass is not logged). Drops are exported to the SIEM by default."
        actions={
          <select aria-label="Filter verdicts" value={filter} onChange={(e) => setFilter(e.target.value as SteerAction | '')}>
            <option value="">All actions</option>
            <option value="drop">drop</option>
            <option value="inspect">inspect</option>
            <option value="allow">allow</option>
          </select>
        }
      >
        {verdicts?.length ? (
          <Table heads={['When', 'Device', 'Flow', 'Action', 'Rule', 'Stage', 'Traffic']} label="Verdicts">
            {verdicts.map((v) => (
              <tr key={v.id}>
                <td>{ago(v.ts)}</td>
                <td className="dv-mono">{v.device}</td>
                <td className="dv-mono">
                  {v.direction === 'egress' ? '→' : '←'} {v.src}
                  {v.sport ? `:${v.sport}` : ''} → {v.dst}
                  {v.dport ? `:${v.dport}` : ''}/{v.protocol}
                </td>
                <td>
                  <Badge tone={actionTone[v.action]}>{v.action}</Badge>
                </td>
                <td className="dv-mono">{v.rule || '(default)'}</td>
                <td>{v.stage}</td>
                <td>
                  {metric(v.packets)} pkts · {bytes(v.bytes)}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No verdicts yet.">Verdicts appear once a steered device sees allow, inspect or drop traffic.</Empty>
        )}
        <Notice>Simulated verdicts come from a modeled flow catalog. Native verdicts are sampled by duvora_steer on the host; neither is DPU offload.</Notice>
      </Section>
    </div>
  );
}

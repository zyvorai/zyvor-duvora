import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { bytes, metric, parsePorts, percent, providerLabel, sourceLabel, when } from '../lib/format';
import { useFleet, useResource, type DialogState, type PlanAction, type PlanPreset } from '../store';
import type { AllowlistSuggestions, Device, History, Job, Plan, ShadowReplay, SteerAction, SteeringOverview, SteeringReplay } from '../types';
import { Badge, Sparkline, Table } from './kit';

const TITLES: Record<PlanAction, string> = {
  isolate: 'Preview isolation.',
  release: 'Preview release.',
  deploy: 'Preview service deployment.',
  upgrade: 'Preview firmware upgrade.',
  steer: 'Preview traffic steering.',
  unsteer: 'Preview steering removal.',
};

const isSteerReplay = (r: ShadowReplay | SteeringReplay): r is SteeringReplay => 'actions' in r;

export default function PlanDialog({
  state,
  onClose,
  onApplied,
}: {
  state: DialogState;
  onClose: () => void;
  onApplied: (job: Job) => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (state && !d.open) d.showModal();
    if (!state && d.open) d.close();
  }, [state]);

  return (
    <dialog ref={ref} className="dv-dialog card" onClose={onClose} aria-labelledby="dialog-title">
      {state?.kind === 'plan' && (
        <PlanForm key={state.action + state.devices.join() + (state.preset?.stage || '')} action={state.action} devices={state.devices} preset={state.preset} onClose={onClose} onApplied={onApplied} />
      )}
      {state?.kind === 'inspect' && <Inspect device={state.device} onClose={onClose} />}
    </dialog>
  );
}

function Head({ eyebrow, title, note, onClose }: { eyebrow: string; title: string; note: string; onClose: () => void }) {
  return (
    <>
      <div className="dv-dialog-head">
        <p className="eyebrow">{eyebrow}</p>
        <button type="button" className="theme-toggle" onClick={onClose} aria-label="Close dialog">
          ✕
        </button>
      </div>
      <h2 id="dialog-title">{title}</h2>
      <p className="dv-muted">{note}</p>
    </>
  );
}

function Inspect({ device: d, onClose }: { device: Device; onClose: () => void }) {
  const { data } = useResource<History>(`devices/${d.id}/history?window=1h`);
  const tp = (data?.points || []).map((p) => p.throughput_gbps).filter((v): v is number => v !== undefined);
  const temp = (data?.points || []).map((p) => p.temperature_c).filter((v): v is number => v !== undefined);
  const rows: [string, string][] = [
    ['Host', d.host],
    ['Site', d.site],
    ['Firmware', d.firmware],
    ['Health', d.health],
    ['Mode', d.mode],
    ['Revision', String(d.version)],
    ['Interfaces', d.interfaces.join(', ') || 'Unknown'],
    ['Services', String(d.services.length)],
    ['Capabilities', d.capabilities.join(', ')],
    ['Last report', when(d.last_seen)],
  ];
  if (d.ebpf) {
    const e = d.ebpf;
    rows.push(
      [`${providerLabel(e.provider)} node`, `${e.node}${e.stale ? ' (agent stale)' : ''}`],
      ['Kernel', `${e.kernel || 'Unknown'} · BTF ${e.btf === null ? 'unknown' : e.btf ? 'yes' : 'no'}`],
      ['eBPF programs', `${e.attached} attached · ${e.programs.join(', ') || 'none reported'}`],
      ['Packets / s', metric(d.metrics.pps)],
      ['TCP retransmits / min', metric(d.metrics.tcp_retransmits_pm)],
      ['TCP resets / min', metric(d.metrics.tcp_resets_pm)],
      ['Top drop reasons', e.drop_reasons.map((r) => `${r.reason} ${r.count}`).join(', ') || e.drop_info_unavailable || 'None'],
      ['Top talkers', e.talkers.slice(0, 3).map((t) => `${t.peer}:${t.port} ${bytes(t.bytes)}`).join(', ') || 'None in window'],
      ['Node isolation', e.isolation ? `${e.isolation.mode} · would block ${e.isolation.would_block_packets} · blocked ${e.isolation.blocked_packets}` : e.nodeiso_available ? 'Available, none set' : 'Not attached'],
    );
  }
  return (
    <div>
      <Head eyebrow="DEVICE" title={d.id} note={`${d.model} · ${sourceLabel(d.source)}`} onClose={onClose} />
      <div className="dv-trends">
        <div>
          <span>Throughput · last hour</span>
          <Sparkline values={tp} width={220} height={40} fill />
          <b>{metric(d.metrics.throughput_gbps, 'Gb/s')}</b>
        </div>
        <div>
          <span>Temperature · last hour</span>
          <Sparkline values={temp} width={220} height={40} />
          <b>{metric(d.metrics.temperature_c, '°C')}</b>
        </div>
      </div>
      <Table heads={['Property', 'Value']}>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <td>{k}</td>
            <td>{v}</td>
          </tr>
        ))}
      </Table>
    </div>
  );
}

function PlanForm({
  action,
  devices,
  preset,
  onClose,
  onApplied,
}: {
  action: PlanAction;
  devices: string[];
  preset?: PlanPreset;
  onClose: () => void;
  onApplied: (job: Job) => void;
}) {
  const { snapshot } = useFleet();
  const netra = devices.some((id) => {
    const d = snapshot?.devices.find((x) => x.id === id);
    return Boolean(d?.ebpf) && d?.source !== 'simulator';
  });
  const [stage, setStage] = useState<'shadow' | 'enforce'>(preset?.stage || 'shadow');
  const [typed, setTyped] = useState('');
  const [fields, setFields] = useState({
    name: preset?.policy?.name || 'tenant-private',
    tenant: preset?.policy?.tenant || 'tenant-a',
    cidr: preset?.policy?.cidr || '10.42.0.0/16',
    ports: preset?.policy ? preset.policy.ports.join(',') : '443,8443',
    service: 'network-observer',
    image: '',
    firmware: 'demo-2.0',
    ruleset: preset?.ruleset || '',
    arm_cores: '',
    memory_gb: '',
  });
  const { data: steering } = useResource<SteeringOverview>(action === 'steer' ? 'steering' : null);
  const ruleset = fields.ruleset || steering?.sets[0]?.id || '';
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { data: suggestions } = useResource<AllowlistSuggestions>(action === 'isolate' && netra && devices.length === 1 ? `devices/${devices[0]}/allowlist-suggestions` : null);

  const set = (key: keyof typeof fields) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setFields({ ...fields, [key]: e.target.value });
    setPlan(null);
  };

  async function preview(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    const spec: Record<string, unknown> = { action, devices };
    if (action === 'isolate') {
      const ports = parsePorts(fields.ports);
      if (!ports) {
        setError('Ports must be comma-separated integers from 1 to 65535.');
        return;
      }
      spec.policy = { name: fields.name, tenant: fields.tenant, cidr: fields.cidr, ports };
      if (netra) spec.stage = stage;
    }
    if (action === 'deploy') {
      Object.assign(spec, { service: fields.service, image: fields.image });
      const resources: Record<string, number> = {};
      if (fields.arm_cores) resources.arm_cores = Number(fields.arm_cores);
      if (fields.memory_gb) resources.memory_gb = Number(fields.memory_gb);
      if (Object.keys(resources).length) spec.resources = resources;
    }
    if (action === 'upgrade') spec.firmware = fields.firmware;
    if (action === 'steer') Object.assign(spec, { ruleset, stage });
    setBusy(true);
    try {
      setPlan(await api<Plan>('plans', 'POST', spec));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    if (!plan) return;
    setBusy(true);
    setError('');
    try {
      onApplied(await api<Job>(`plans/${plan.id}/apply`, 'POST', { confirmation: plan.confirmation }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const input = (id: keyof typeof fields, label: string, placeholder?: string) => (
    <label className="tokenbox" htmlFor={`f-${id}`}>
      {label}
      <input id={`f-${id}`} value={fields[id]} onChange={set(id)} placeholder={placeholder} required={!['ports', 'arm_cores', 'memory_gb'].includes(id)} />
    </label>
  );
  const steerShadow = plan?.shadow && Object.values(plan.shadow).every(isSteerReplay) ? (plan.shadow as Record<string, SteeringReplay>) : null;
  const isoShadow = plan?.shadow && !steerShadow ? (plan.shadow as Record<string, ShadowReplay>) : null;
  const typedConfirm = Boolean(plan && (plan.confirmation.startsWith('ENFORCE') || plan.job_mode === 'steer-native'));
  const applyLabel = !plan
    ? ''
    : plan.job_mode === 'steer-native'
      ? plan.mode.endsWith('-enforce')
        ? 'Enforce steering'
        : plan.mode.startsWith('unsteer')
          ? 'Remove steering'
          : 'Apply steering shadow'
      : plan.netra
        ? plan.mode.endsWith('-enforce')
          ? 'Enforce in kernel'
          : plan.mode.endsWith('-release')
            ? 'Release isolation'
            : 'Apply shadow'
        : 'Apply simulation';

  return (
    <form onSubmit={preview}>
      <Head eyebrow="CHANGE WORKFLOW" title={TITLES[action]} note={`${devices.join(', ')} · all changes require a reviewed plan`} onClose={onClose} />
      <div className="dv-fields">
        {action === 'isolate' && (
          <>
            {suggestions && suggestions.candidates.length > 0 && (
              <label className="tokenbox" htmlFor="f-suggest">
                Suggest allow-list from {suggestions.flows} observed flows
                <select
                  id="f-suggest"
                  defaultValue=""
                  onChange={(e) => {
                    const c = suggestions.candidates[Number(e.target.value)];
                    if (!c) return;
                    setFields({ ...fields, cidr: c.cidr, ports: c.ports.join(',') });
                    setPlan(null);
                  }}
                >
                  <option value="">Choose a suggestion…</option>
                  {suggestions.candidates.map((c, i) => (
                    <option key={c.cidr + c.ports.join()} value={i}>
                      {c.cidr} · {c.ports.length ? `ports ${c.ports.join(', ')}` : 'any port'} · covers {percent(c.coverage_bytes)} of bytes
                    </option>
                  ))}
                </select>
              </label>
            )}
            {input('name', 'Policy name')}
            {input('tenant', 'Tenant')}
            {input('cidr', 'Allowed destination CIDR')}
            {input('ports', 'Allowed ports (comma separated; empty = all)')}
            {netra && (
              <label className="tokenbox" htmlFor="f-stage">
                Stage
                <select
                  id="f-stage"
                  value={stage}
                  onChange={(e) => {
                    setStage(e.target.value as 'shadow' | 'enforce');
                    setPlan(null);
                  }}
                >
                  <option value="shadow">Shadow: count what would be blocked</option>
                  <option value="enforce">Enforce: drop new flows outside the allow-list</option>
                </select>
              </label>
            )}
            {netra && (
              <p className="dv-fine">
                The node&apos;s eBPF provider (native agent or Netra) applies this as node isolation in the kernel. Shadow never drops. Enforce needs a shadow run of the same allow-list, holds a
                renewable lease, and falls back to shadow if Duvora or the controller goes away. SSH (22), ICMP, DHCP, established connections and the control plane stay reachable.
              </p>
            )}
          </>
        )}
        {action === 'deploy' && (
          <>
            {input('service', 'Service name')}
            {input('image', 'Container image pinned to SHA-256', 'registry.example/service@sha256:…')}
            {input('arm_cores', 'Arm cores (optional; checked against the DPU budget)', '4')}
            {input('memory_gb', 'Memory GB (optional)', '8')}
            <p className="dv-fine">
              Simulation records desired state. No image is pulled or container launched. Requests beyond the device&apos;s free capacity (after the platform reservation) and images with a failed artifact scan
              are blocked.
            </p>
          </>
        )}
        {action === 'steer' && (
          <>
            <label className="tokenbox" htmlFor="f-ruleset">
              Rule set
              <select id="f-ruleset" value={ruleset} onChange={set('ruleset')}>
                {(steering?.sets || []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} · {s.rule_count} rules · default {s.default}
                  </option>
                ))}
              </select>
            </label>
            <label className="tokenbox" htmlFor="f-steer-stage">
              Stage
              <select
                id="f-steer-stage"
                value={stage}
                onChange={(e) => {
                  setStage(e.target.value as 'shadow' | 'enforce');
                  setPlan(null);
                }}
              >
                <option value="shadow">Shadow: count what each rule would do; nothing is dropped</option>
                <option value="enforce">Enforce: drop rules drop (needs a shadow run of the same rule set)</option>
              </select>
            </label>
            <p className="dv-fine">
              Simulated devices evaluate the modeled flow catalog. Agent-backed devices run duvora_steer on the host&apos;s uplinks; enforce holds a renewable lease and falls back to shadow when Duvora is
              unreachable. SSH and the control plane are always exempt. This is not DPU offload.
            </p>
          </>
        )}
        {action === 'unsteer' && <p className="dv-fine">Removes steering from the selected devices; their traffic then passes uninspected.</p>}
        {action === 'upgrade' && (
          <>
            {input('firmware', 'Target firmware label')}
            <p className="dv-fine">Simulates drain, update, and verify. No firmware artifact is downloaded or flashed.</p>
          </>
        )}
        {action === 'release' && (
          <p className="dv-fine">{netra ? 'Removes node isolation from the selected devices.' : 'Removes every simulated isolation policy from the selected devices.'}</p>
        )}
      </div>
      {plan && (
        <div className="dv-plan" role="status">
          <Badge tone={plan.blockers.length ? 'bad' : 'info'}>{plan.mode}</Badge>
          <p>{plan.effects}</p>
          <ul>
            {plan.targets.map((t) => (
              <li key={t.id}>
                {t.id} · {t.host} · revision {t.version}
              </li>
            ))}
          </ul>
          {steerShadow && (
            <Table heads={['Device', 'Flows', 'Inspect', 'Drop', 'Allow', 'Bypass', 'Top drops']} label="Steering replay">
              {Object.entries(steerShadow).map(([id, r]) => (
                <tr key={id}>
                  <td>{id}</td>
                  <td>{r.flows}</td>
                  {(['inspect', 'drop', 'allow', 'bypass'] as SteerAction[]).map((a) => (
                    <td key={a}>
                      {r.actions[a].flows} · {bytes(r.actions[a].bytes)}
                    </td>
                  ))}
                  <td className="dv-mono">{(r.top.drop || []).map((t) => `${t.peer}:${t.port ?? '*'}`).join(', ') || 'None'}</td>
                </tr>
              ))}
            </Table>
          )}
          {steerShadow && <p className="dv-fine">{Object.values(steerShadow)[0]?.source}. {Object.values(steerShadow)[0]?.note}</p>}
          {isoShadow && (
            <Table heads={['Device', 'Flows checked', 'Would block', 'Top would-block destinations']} label="Shadow replay">
              {Object.entries(isoShadow).map(([id, r]) => (
                <tr key={id}>
                  <td>{id}</td>
                  <td>{r.flows}</td>
                  <td>
                    {r.would_block_flows} flows · {bytes(r.would_block_bytes)}
                  </td>
                  <td className="dv-mono">{r.top.map((t) => `${t.peer}:${t.port}`).join(', ') || 'None'}</td>
                </tr>
              ))}
            </Table>
          )}
          {isoShadow && <p className="dv-fine">Replayed from the last {Math.round(Object.values(isoShadow)[0].window / 60)} minutes of observed flow records.</p>}
          <p className="dv-fine">Expires {when(plan.expires)}</p>
          {plan.blockers.length ? (
            <p className="login-error">{plan.blockers.join(' · ')}</p>
          ) : plan.netra ? (
            <p className="dv-fine">The kernel isolation on the node will change. Confirm with: {plan.confirmation}</p>
          ) : plan.job_mode === 'steer-native' ? (
            <p className="dv-fine">Steering on the host kernel will change. Confirm with: {plan.confirmation}</p>
          ) : (
            <p className="dv-fine">Only the local simulation model will change.</p>
          )}
          {!plan.blockers.length && typedConfirm && (
            <label className="tokenbox" htmlFor="f-confirm">
              Type {plan.confirmation} to confirm
              <input id="f-confirm" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
            </label>
          )}
        </div>
      )}
      {error && (
        <p className="login-error" role="alert">
          {error}
        </p>
      )}
      <div className="dv-dialog-actions">
        {plan && !plan.blockers.length ? (
          <button type="button" className="primary" onClick={apply} disabled={busy || (typedConfirm && typed !== plan.confirmation)}>
            {applyLabel}
          </button>
        ) : (
          <button type="submit" className="primary" disabled={busy}>
            Preview change
          </button>
        )}
      </div>
    </form>
  );
}

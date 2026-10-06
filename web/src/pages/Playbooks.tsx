import { api } from '../api';
import { Badge, Empty, Notice, Section, Table } from '../components/kit';
import { ago, remaining } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { Job, Playbook, PlaybookRun } from '../types';

export default function Playbooks() {
  const { isAdmin, toast, navigate, refresh } = useFleet();
  const { data: books, reload } = useResource<Playbook[]>('playbooks', 15000);
  const { data: runs, reload: reloadRuns } = useResource<PlaybookRun[]>('playbook-runs?limit=50', 5000);

  async function toggle(pb: Playbook) {
    try {
      await api(`playbooks/${pb.id}`, 'PUT', { name: pb.name, enabled: !pb.enabled, match: pb.match, steps: pb.steps });
      void reload();
    } catch (e) {
      toast((e as Error).message);
    }
  }

  async function applyDraft(plan: PlaybookRun['plans'][number]) {
    const typed = window.prompt(`${plan.effects}\n\nType ${plan.confirmation} to apply this drafted plan.`);
    if (typed === null) return;
    try {
      const job = await api<Job>(`plans/${plan.id}/apply`, 'POST', { confirmation: typed });
      toast(`Job ${job.id.slice(0, 8)} queued from the playbook draft.`);
      void refresh();
      void reloadRuns();
      navigate('operations');
    } catch (e) {
      toast((e as Error).message);
    }
  }

  const now = Date.now() / 1000;
  return (
    <div className="grid">
      <Section
        eyebrow="PLAYBOOKS"
        title="Prepare the response, never apply it"
        lede="When an incident opens, a matching playbook explains it, drafts a shadow steering plan that drops the offending peer, previews bypass, or notifies a webhook. Every draft waits for an administrator to type its confirmation."
      >
        {books?.length ? (
          <Table heads={['Playbook', 'Runs on', 'Steps', 'Enabled']} label="Playbooks">
            {books.map((pb) => (
              <tr key={pb.id}>
                <td>
                  <b>{pb.name}</b>
                  <br />
                  <small className="dv-mono dv-muted">{pb.id}</small>
                </td>
                <td className="dv-mono">
                  {pb.match.rules.join(', ')} · {pb.match.min_severity}+
                </td>
                <td>{pb.steps.map((s) => s.type).join(' → ')}</td>
                <td>
                  {isAdmin ? (
                    <button type="button" className="btn-diag" onClick={() => void toggle(pb)} aria-pressed={pb.enabled}>
                      {pb.enabled ? 'On' : 'Off'}
                    </button>
                  ) : pb.enabled ? (
                    'On'
                  ) : (
                    'Off'
                  )}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No playbooks." />
        )}
        <Notice>Notify steps post to DUVORA_NOTIFY_URL (or the step&apos;s own HTTPS URL) with the incident and drafted plan ids — never credentials or payloads.</Notice>
      </Section>

      <Section eyebrow="RUNS" title="What the playbooks prepared" lede="Drafted plans expire after five minutes like any preview; run the playbook again from the incident to draft a fresh one.">
        {runs?.length ? (
          <Table heads={['When', 'Playbook', 'Incident', 'Steps', 'Drafted plan']} label="Playbook runs">
            {runs.map((r) => (
              <tr key={r.id}>
                <td>{ago(r.created)}</td>
                <td>{r.name}</td>
                <td className="dv-mono">
                  {r.rule} · {r.target}
                </td>
                <td>
                  {r.steps.map((s, i) => (
                    <div key={i}>
                      <Badge tone={s.ok ? 'ok' : 'warn'}>{s.type}</Badge> <small>{s.detail}</small>
                    </div>
                  ))}
                </td>
                <td>
                  {r.plans.map((p) => {
                    const live = p.expires > now;
                    return (
                      <div key={p.id}>
                        <span className="dv-mono">{p.ruleset}</span> · {p.mode} · {live ? `expires in ${remaining(p.expires)}` : 'expired'}
                        {p.blockers.length > 0 && <p className="login-error">{p.blockers.join(' · ')}</p>}
                        {isAdmin && live && !p.blockers.length && (
                          <button type="button" className="btn-diag" onClick={() => void applyDraft(p)}>
                            Review and apply
                          </button>
                        )}
                      </div>
                    );
                  })}
                  {!r.plans.length && <span className="dv-muted">none</span>}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No runs yet.">Playbooks run when a matching incident opens.</Empty>
        )}
      </Section>
    </div>
  );
}

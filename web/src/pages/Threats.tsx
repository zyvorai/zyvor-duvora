import { Fragment, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Metrics, Section, Table, type Tone } from '../components/kit';
import { ago, bytes, when } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { IntelOverview, Scan } from '../types';

const SCAN_TONE: Record<Scan['status'], Tone> = { running: 'info', passed: 'ok', failed: 'bad', error: 'warn' };
const SEV_TONE: Record<string, Tone> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'idle', info: 'idle' };

export default function Threats() {
  const { isAdmin, toast, navigate } = useFleet();
  const { data: intel, reload: reloadIntel } = useResource<IntelOverview>('intel', 15000);
  const { data: scans, reload: reloadScans } = useResource<Scan[]>('scans', 4000);
  const [feed, setFeed] = useState({ id: '', url: '', indicators: '', format: 'plain' });
  const [target, setTarget] = useState('');
  const [open, setOpen] = useState('');

  async function saveFeed(e: React.FormEvent) {
    e.preventDefault();
    const body: Record<string, unknown> = { format: feed.format };
    if (feed.url.trim()) body.url = feed.url.trim();
    else body.indicators = feed.indicators;
    try {
      await api(`intel/feeds/${encodeURIComponent(feed.id.trim())}`, 'PUT', body);
      toast(`Feed ${feed.id} saved.`);
      setFeed({ id: '', url: '', indicators: '', format: 'plain' });
      void reloadIntel();
    } catch (err) {
      toast((err as Error).message);
    }
  }

  async function act(path: string, method: 'POST' | 'DELETE', body?: unknown, done?: string) {
    try {
      await api(path, method, body);
      if (done) toast(done);
      void reloadIntel();
    } catch (err) {
      toast((err as Error).message);
    }
  }

  async function buildRuleset() {
    try {
      const rs = await api<{ id: string; rules: unknown[] }>('intel/ruleset', 'POST', { id: 'intel-block' });
      toast(`Saved rule set ${rs.id} with ${rs.rules.length} rules. Apply it in shadow from Operate → Steering.`);
      navigate('steering');
    } catch (err) {
      toast((err as Error).message);
    }
  }

  async function scan(e: React.FormEvent) {
    e.preventDefault();
    const t = target.trim();
    try {
      await api('scans', 'POST', t.startsWith('http') ? { url: t } : { image: t });
      setTarget('');
      void reloadScans();
    } catch (err) {
      toast((err as Error).message);
    }
  }

  const failed = scans?.filter((s) => s.status === 'failed').length || 0;
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">THREATS</p>
        <h2 className="card-title">
          {intel?.matches.length ? `${intel.matches.length} flow${intel.matches.length === 1 ? '' : 's'} touch a threat-intel indicator.` : 'No traffic matches a threat-intel indicator.'}
        </h2>
        <Metrics
          items={[
            { label: 'feeds', value: intel?.feeds.length ?? '—' },
            { label: 'indicators', value: intel?.feeds.reduce((n, f) => n + (f.count || 0), 0) ?? '—' },
            { label: 'artifact scans', value: scans?.length ?? '—' },
            { label: 'failed scans', value: failed, note: 'block deploys of that image' },
          ]}
        />
        <p className="dv-fine">
          Feeds (plain lists, CSV or STIX bundles) are matched against observed flows and steering verdicts. A match opens an intel-match incident and the intel-match playbook drafts a shadow block plan.
          Artifact scans pull an image by digest (or a model file by URL) and look for unsafe pickles, Keras Lambda layers and embedded secrets.
        </p>
      </section>

      <Section
        span={2}
        eyebrow="THREAT INTEL"
        title="Matches"
        lede="Observed peers inside a feed's networks or domains."
        actions={
          isAdmin && (
            <button type="button" className="btn-diag" onClick={() => void buildRuleset()} disabled={!intel?.feeds.length}>
              Build block rule set
            </button>
          )
        }
      >
        {intel?.matches.length ? (
          <Table heads={['Device', 'Peer', 'Direction', 'Indicator', 'Feed', 'Traffic']} label="Intel matches">
            {intel.matches.map((m) => (
              <tr key={m.device + m.peer + m.port}>
                <td className="dv-mono">{m.device}</td>
                <td className="dv-mono">
                  {m.peer}
                  {m.port ? `:${m.port}` : ''}
                </td>
                <td>{m.direction || '—'}</td>
                <td className="dv-mono">{m.indicator}</td>
                <td>{m.feed}</td>
                <td>{m.bytes !== undefined ? bytes(m.bytes) : '—'}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No matches." />
        )}
      </Section>

      <Section span={1} eyebrow="FEEDS" title="Indicator sources">
        {intel?.feeds.length ? (
          <div className="list">
            {intel.feeds.map((f) => (
              <div className="agent wide" key={f.id}>
                <b className="dv-mono">{f.id}</b>
                <small>
                  {f.count} indicators · {f.url ? `fetched ${f.last_fetch ? ago(f.last_fetch) : 'never'}` : 'inline'}
                  {f.error && <Badge tone="warn">{f.error}</Badge>}
                </small>
                {isAdmin && (
                  <span>
                    {f.url && (
                      <button type="button" className="btn-diag" onClick={() => void act('intel/refresh', 'POST', { feed: f.id }, `Refreshing ${f.id}.`)}>
                        Refresh
                      </button>
                    )}
                    <button type="button" className="btn-diag" onClick={() => void act(`intel/feeds/${f.id}`, 'DELETE')}>
                      Delete
                    </button>
                  </span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No feeds." />
        )}
        {isAdmin && (
          <form className="dv-fields" onSubmit={saveFeed}>
            <label className="tokenbox" htmlFor="feed-id">
              Feed id
              <input id="feed-id" value={feed.id} onChange={(e) => setFeed({ ...feed, id: e.target.value })} required />
            </label>
            <label className="tokenbox" htmlFor="feed-url">
              HTTPS URL (or leave empty and paste indicators)
              <input id="feed-url" value={feed.url} onChange={(e) => setFeed({ ...feed, url: e.target.value })} />
            </label>
            {!feed.url && (
              <label className="tokenbox" htmlFor="feed-ind">
                Indicators, one per line
                <textarea id="feed-ind" className="dv-mono" rows={4} value={feed.indicators} onChange={(e) => setFeed({ ...feed, indicators: e.target.value })} />
              </label>
            )}
            <label className="tokenbox" htmlFor="feed-fmt">
              Format
              <select id="feed-fmt" value={feed.format} onChange={(e) => setFeed({ ...feed, format: e.target.value })}>
                <option value="plain">plain</option>
                <option value="csv">csv</option>
                <option value="stix">stix</option>
              </select>
            </label>
            <button type="submit" className="btn-diag" disabled={!feed.id.trim()}>
              Save feed
            </button>
          </form>
        )}
      </Section>

      <Section eyebrow="ARTIFACT SCANS" title="Images and models before they deploy" lede="A failed scan (high or critical finding) blocks deploy plans for that exact image digest. DUVORA_REQUIRE_SCAN=1 also blocks unscanned images.">
        {isAdmin && (
          <form className="dv-inline" onSubmit={scan}>
            <input aria-label="Image or model URL" placeholder="registry.example/team/model@sha256:…  or  https://…/model.pt" value={target} onChange={(e) => setTarget(e.target.value)} />
            <button type="submit" className="btn-diag" disabled={!target.trim()}>
              Scan
            </button>
          </form>
        )}
        {scans?.length ? (
          <Table heads={['Started', 'Target', 'Status', 'Findings', '']} label="Scans">
            {scans.map((s) => {
              const serious = s.findings.filter((f) => f.severity === 'high' || f.severity === 'critical').length;
              return (
                <Fragment key={s.id}>
                  <tr>
                    <td>{when(s.started)}</td>
                    <td className="dv-mono">{s.target}</td>
                    <td>
                      <Badge tone={SCAN_TONE[s.status]}>{s.status}</Badge>
                    </td>
                    <td>{s.error || `${s.findings.length} (${serious} high or critical)`}</td>
                    <td>
                      {s.findings.length > 0 && (
                        <button type="button" className="btn-diag" onClick={() => setOpen(open === s.id ? '' : s.id)}>
                          {open === s.id ? 'Hide' : 'Details'}
                        </button>
                      )}
                    </td>
                  </tr>
                  {open === s.id &&
                    s.findings.map((f, i) => (
                      <tr key={s.id + i}>
                        <td />
                        <td className="dv-mono">{f.path}</td>
                        <td>
                          <Badge tone={SEV_TONE[f.severity]}>{f.severity}</Badge>
                        </td>
                        <td colSpan={2}>{f.detail}</td>
                      </tr>
                    ))}
                </Fragment>
              );
            })}
          </Table>
        ) : (
          <Empty title="No scans yet." />
        )}
      </Section>
    </div>
  );
}

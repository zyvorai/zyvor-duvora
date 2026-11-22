// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useState } from 'react';
import { download, saveJSON } from '../api';
import { Empty, Section, Table } from '../components/kit';
import { detailText, when } from '../lib/format';
import { useFleet } from '../store';

export default function Audit() {
  const { snapshot, isAdmin, toast } = useFleet();
  const [query, setQuery] = useState('');
  if (!snapshot) return null;
  const q = query.toLowerCase();
  const rows = snapshot.audit.filter((x) => !q || [x.action, x.actor, detailText(x.detail)].some((v) => v.toLowerCase().includes(q)));
  return (
    <div className="grid">
      <Section
        eyebrow="EVIDENCE"
        title="Recent audit events"
        lede="Latest 200 events. Complete history stays in SQLite for the configured retention."
        actions={
          <>
            <button type="button" className="btn-secondary" onClick={() => saveJSON(snapshot, 'duvora-evidence.json')}>
              Export evidence
            </button>
            {isAdmin && (
              <button type="button" className="btn-secondary" onClick={() => download('backup', 'duvora-backup.db').catch((e) => toast(e.message))}>
                Download backup
              </button>
            )}
          </>
        }
      >
        <div className="toolbar">
          <input aria-label="Filter audit" placeholder="Filter by action, principal, or detail" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        {rows.length ? (
          <Table heads={['Sequence', 'Action', 'Principal', 'Time', 'Detail']} label="Audit events">
            {rows.map((x) => (
              <tr key={x.seq}>
                <td>{x.seq}</td>
                <td>
                  <strong>{x.action}</strong>
                </td>
                <td>{x.actor}</td>
                <td>{when(x.time)}</td>
                <td className="dv-mono dv-wrap">{detailText(x.detail)}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty title="No matching events." />
        )}
      </Section>
    </div>
  );
}

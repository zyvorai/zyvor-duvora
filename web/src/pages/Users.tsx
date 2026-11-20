// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, Notice, Section, Table } from '../components/kit';
import { when } from '../lib/format';
import { useFleet, useResource } from '../store';
import type { ApiToken, User } from '../types';

export default function Users({ onPasswordChanged }: { onPasswordChanged: () => void }) {
  const { session, isAdmin } = useFleet();
  const named = session.via !== 'key';
  return (
    <div className="grid">
      {named ? (
        <>
          <ChangePassword onChanged={onPasswordChanged} defaultPassword={session.default_password} />
          <Tokens />
        </>
      ) : (
        <div className="span3">
          <Notice>You are signed in with a configured access key ({session.actor}). Passwords and tokens belong to named users.</Notice>
        </div>
      )}
      {isAdmin && <Team self={session.actor} />}
    </div>
  );
}

function ChangePassword({ onChanged, defaultPassword }: { onChanged: () => void; defaultPassword: boolean }) {
  const { toast } = useFleet();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (next !== confirm) {
      setError('The new passwords do not match.');
      return;
    }
    try {
      await api('me/password', 'POST', { current, new: next });
      setCurrent('');
      setNext('');
      setConfirm('');
      toast('Password changed.');
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <Section span={1} eyebrow="YOUR ACCOUNT" title="Change password" lede={defaultPassword ? 'You are using the default password. Choose a new one.' : undefined}>
      <form className="dv-fields" onSubmit={submit}>
        <label className="tokenbox">
          Current password
          <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </label>
        <label className="tokenbox">
          New password (8+ characters)
          <input type="password" autoComplete="new-password" minLength={8} value={next} onChange={(e) => setNext(e.target.value)} required />
        </label>
        <label className="tokenbox">
          Confirm new password
          <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        </label>
        {error && (
          <p className="login-error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="primary">
          Change password
        </button>
      </form>
    </Section>
  );
}

function Tokens() {
  const { toast } = useFleet();
  const { data, reload } = useResource<ApiToken[]>('tokens');
  const [name, setName] = useState('duvoractl');
  const [secret, setSecret] = useState('');
  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      const t = await api<{ token: string }>('tokens', 'POST', { name });
      setSecret(t.token);
      await reload();
    } catch (err) {
      toast((err as Error).message);
    }
  }
  async function revoke(id: string) {
    try {
      await api(`tokens/${id}`, 'DELETE');
      await reload();
    } catch (err) {
      toast((err as Error).message);
    }
  }
  return (
    <Section span={2} eyebrow="AUTOMATION" title="Personal API tokens" lede="Use a token with duvoractl or scripts. It carries your role and is shown once.">
      <form className="toolbar" onSubmit={create}>
        <input aria-label="Token name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required />
        <button type="submit" className="primary">
          Create token
        </button>
      </form>
      {secret && (
        <div className="dv-notice">
          Copy this token now; it will not be shown again: <code className="dv-mono dv-wrap">{secret}</code>
        </div>
      )}
      {data?.length ? (
        <Table heads={['Name', 'Created', 'Last used', '']}>
          {data.map((t) => (
            <tr key={t.id}>
              <td>
                <strong>{t.name}</strong>
                <small className="dv-sub dv-mono">{t.id}</small>
              </td>
              <td>{when(t.created)}</td>
              <td>{when(t.last_used)}</td>
              <td>
                <button type="button" className="danger" onClick={() => revoke(t.id)}>
                  Revoke
                </button>
              </td>
            </tr>
          ))}
        </Table>
      ) : (
        <Empty title="No tokens yet." />
      )}
    </Section>
  );
}

function Team({ self }: { self: string }) {
  const { toast } = useFleet();
  const { data, reload } = useResource<User[]>('users');
  const [form, setForm] = useState({ username: '', role: 'viewer', password: '' });
  async function run(fn: () => Promise<unknown>, message: string) {
    try {
      await fn();
      toast(message);
      await reload();
    } catch (err) {
      toast((err as Error).message);
    }
  }
  return (
    <Section eyebrow="TEAM" title="Users" lede="Admins plan and apply changes and manage users. Viewers read everything except user management.">
      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          void run(() => api('users', 'POST', form), `User ${form.username} created.`).then(() => setForm({ username: '', role: 'viewer', password: '' }));
        }}
      >
        <label className="tokenbox">
          Username
          <input aria-label="New username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value.toLowerCase() })} required />
        </label>
        <label>
          Role
          <select aria-label="New user role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="viewer">viewer</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <label className="tokenbox">
          Initial password
          <input aria-label="New user password" type="password" minLength={8} autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
        </label>
        <button type="submit" className="primary">
          Add user
        </button>
      </form>
      <Table heads={['User', 'Role', 'Status', 'Created', '']} label="Users">
        {(data || []).map((u) => (
          <tr key={u.username}>
            <td>
              <strong>{u.username}</strong>
              {u.username === self && <small className="dv-sub">You</small>}
            </td>
            <td>
              <select
                aria-label={`${u.username} role`}
                value={u.role}
                onChange={(e) => void run(() => api(`users/${u.username}`, 'PATCH', { role: e.target.value }), `${u.username} is now ${e.target.value}.`)}
              >
                <option value="viewer">viewer</option>
                <option value="admin">admin</option>
              </select>
            </td>
            <td>
              {u.disabled ? <Badge tone="bad">disabled</Badge> : <Badge tone="ok">active</Badge>} {u.default_password && <Badge tone="warn">default password</Badge>}
            </td>
            <td>{when(u.created)}</td>
            <td>
                  <div className="dv-actions">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  const pw = window.prompt(`New password for ${u.username} (8+ characters)`);
                  if (pw) void run(() => api(`users/${u.username}`, 'PATCH', { password: pw }), `Password reset for ${u.username}.`);
                }}
              >
                Reset password
              </button>
              <button
                type="button"
                className={u.disabled ? 'btn-success' : 'btn-warn'}
                onClick={() => void run(() => api(`users/${u.username}`, 'PATCH', { disabled: !u.disabled }), `${u.username} ${u.disabled ? 'enabled' : 'disabled'}.`)}
              >
                {u.disabled ? 'Enable' : 'Disable'}
              </button>
              <button
                type="button"
                className="danger"
                onClick={() => {
                  if (window.confirm(`Delete ${u.username}? Their sessions and tokens are revoked.`)) void run(() => api(`users/${u.username}`, 'DELETE'), `${u.username} deleted.`);
                }}
              >
                Delete
              </button>
            </div>
                </td>
          </tr>
        ))}
      </Table>
    </Section>
  );
}

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { ApiError, signIn } from '../api';

const WRONG = 'Wrong username or password.';

export default function Login({ onLogin, initialError = '' }: { onLogin: () => void; initialError?: string }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  const host = window.location.host || window.location.hostname;

  useEffect(() => {
    if (initialError) setError(initialError);
  }, [initialError]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const user = username.trim();
    if (!user || !password) {
      setError(WRONG);
      return;
    }
    setBusy(true);
    setError('');
    try {
      await signIn(user, password);
      onLogin();
    } catch (err) {
      if (err instanceof ApiError) setError(err.status === 401 ? WRONG : err.message);
      else setError('Could not reach the control plane. Check the URL and try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <div className="login-info">
        <img src="/zyvor-mark.svg" alt="Zyvor" className="login-logo" />
        <p className="eyebrow">Duvora · Zyvor</p>
        <h1>Infrastructure. In your control.</h1>
        <p>
          One workspace for your DPU fleet — inventory, service plans, tenant isolation, telemetry, incidents, and change
          evidence. Preview every change before it applies.
        </p>
        <p className="login-host">
          Connecting to <code>{host}</code>
        </p>
      </div>
      <form className="card login-card" onSubmit={submit} noValidate>
        <h1>Sign in.</h1>
        <label className="tokenbox">
          Username
          <input
            value={username}
            onChange={(e) => {
              setUsername(e.target.value);
              if (error) setError('');
            }}
            autoFocus
            autoComplete="username"
            disabled={busy}
            aria-invalid={Boolean(error)}
          />
        </label>
        <label className="tokenbox">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              if (error) setError('');
            }}
            autoComplete="current-password"
            disabled={busy}
            aria-invalid={Boolean(error)}
          />
        </label>
        {error ? (
          <p className="login-error" role="alert" aria-live="assertive">
            {error}
          </p>
        ) : null}
        <button type="submit" className="primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}

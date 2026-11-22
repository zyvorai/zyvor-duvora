// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// The console session is an HttpOnly cookie set by the control plane. No
// password or bearer is written to localStorage or sessionStorage: those are
// readable by any script on the page.

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export const AUTH_EXPIRED = 'duvora-auth-expired';

/** The control plane answers failures as {"error":"…"}; show the message, not the JSON envelope. */
export function errorMessage(body: string): string {
  const text = body.trim();
  if (text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed?.error === 'string' && parsed.error) return parsed.error;
    } catch {
      /* not JSON after all — fall through to the raw text */
    }
  }
  return text;
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export async function api<T = unknown>(path: string, method: Method = 'GET', body?: unknown): Promise<T> {
  const r = await fetch('/api/v1/' + path.replace(/^\//, ''), {
    method,
    headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) {
    const message = errorMessage(await r.text()) || r.statusText;
    // whoami/session 401s are the normal signed-out answer, not an expired session.
    if (r.status === 401 && !/^(session|whoami)/.test(path)) window.dispatchEvent(new Event(AUTH_EXPIRED));
    throw new ApiError(message, r.status);
  }
  const type = r.headers.get('content-type') || '';
  return (type.includes('application/json') ? r.json() : r.text()) as Promise<T>;
}

export async function signIn(username: string, password: string) {
  return api<{ actor: string; role: string; default_password: boolean }>('session', 'POST', { username, password });
}

export function signOut(): Promise<unknown> {
  return api('session', 'DELETE').catch(() => undefined);
}

/** Download an API resource (Markdown briefing, database backup) through the cookie session. */
export async function download(path: string, filename: string) {
  const r = await fetch('/api/v1/' + path);
  if (!r.ok) throw new ApiError(errorMessage(await r.text()) || r.statusText, r.status);
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function saveJSON(data: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

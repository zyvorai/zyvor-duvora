export const sourceLabel = (s: string) =>
  ({ simulator: 'Simulated', 'linux-pci': 'Linux PCI', 'nvidia-dpf': 'NVIDIA DPF', 'netra-ebpf': 'Netra eBPF', 'duvora-ebpf': 'Native eBPF' })[s] || s;

/** eBPF provider: Duvora's own host agent or a Netra controller. */
export const providerLabel = (p: string | undefined) => (p === 'native' ? 'Native agent' : 'Netra');

/** Policy mode: "native-shadow", "netra-enforce", or "simulation". */
export function policyModeLabel(mode: string): string {
  const m = /^(native|netra)-(.+)$/.exec(mode);
  return m ? `${providerLabel(m[1])} ${m[2]}` : 'Simulated allow-list';
}

export const when = (seconds: number | null | undefined) =>
  seconds ? new Date(seconds * 1000).toLocaleString() : '—';

export function ago(seconds: number, now = Date.now() / 1000): string {
  const d = Math.max(0, Math.round(now - seconds));
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

export function metric(value: number | undefined, unit = ''): string {
  if (value === undefined || value === null || !Number.isFinite(value)) return 'Unknown';
  return `${Number.isInteger(value) ? value : value.toFixed(1)}${unit ? ' ' + unit : ''}`;
}

export function detailText(detail: unknown): string {
  return typeof detail === 'string' ? detail : JSON.stringify(detail);
}

/** Parse "443, 8443" into ports; empty means all ports. Returns null on invalid input. */
export function parsePorts(text: string): number[] | null {
  if (!text.trim()) return [];
  const ports = text.split(',').map((x) => Number(x.trim()));
  return ports.every((p) => Number.isInteger(p) && p >= 1 && p <= 65535) ? ports : null;
}

export function bytes(value: number | undefined): string {
  if (value === undefined || !Number.isFinite(value)) return 'Unknown';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = value;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  return `${i ? v.toFixed(1) : v} ${units[i]}`;
}

/** Coverage ratio 0–1 as a percent with one decimal: 0.9989 → "99.9%". */
export const percent = (ratio: number) => `${(Math.round(ratio * 1000) / 10).toString()}%`;

/** Hours until a forecast threshold, as "45m", "5.5 h" or "3.2 d". */
export function eta(hours: number | null | undefined): string {
  if (hours === null || hours === undefined || !Number.isFinite(hours)) return 'Not trending toward it';
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))}m`;
  if (hours < 48) return `${Math.round(hours * 10) / 10} h`;
  return `${Math.round((hours / 24) * 10) / 10} d`;
}

/** Signed z-score with direction: 5.2 → "5.2σ above", -4 → "4σ below". */
export const zLabel = (z: number) => `${Math.abs(z)}σ ${z >= 0 ? 'above' : 'below'}`;

/** Seconds until an epoch-seconds deadline, as "12m 30s"; "expired" once past. */
export function remaining(until: number | null | undefined, now = Date.now() / 1000): string {
  if (!until) return '—';
  const d = Math.round(until - now);
  if (d <= 0) return 'expired';
  return d >= 60 ? `${Math.floor(d / 60)}m ${d % 60}s` : `${d}s`;
}

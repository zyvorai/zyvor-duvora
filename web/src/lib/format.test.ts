import { describe, expect, it } from 'vitest';
import { errorMessage } from '../api';
import { scoreTone, healthTone, severityTone } from '../components/kit';
import { layout } from '../pages/Topology';
import { ago, bytes, eta, metric, parsePorts, percent, policyModeLabel, providerLabel, remaining, sourceLabel, zLabel } from './format';

describe('insight labels', () => {
  it('formats coverage, forecast ETAs and z-scores', () => {
    expect(percent(0.9989)).toBe('99.9%');
    expect(percent(1)).toBe('100%');
    expect(eta(null)).toBe('Not trending toward it');
    expect(eta(0.25)).toBe('15m');
    expect(eta(5.54)).toBe('5.5 h');
    expect(eta(72)).toBe('3 d');
    expect(zLabel(5.2)).toBe('5.2σ above');
    expect(zLabel(-4)).toBe('4σ below');
  });
});

describe('format', () => {
  it('labels sources', () => {
    expect(sourceLabel('linux-pci')).toBe('Linux PCI');
    expect(sourceLabel('other')).toBe('other');
    expect(sourceLabel('netra-ebpf')).toBe('Netra eBPF');
    expect(sourceLabel('duvora-ebpf')).toBe('Native eBPF');
  });

  it('labels eBPF providers and policy modes', () => {
    expect(providerLabel('native')).toBe('Native agent');
    expect(providerLabel(undefined)).toBe('Netra');
    expect(policyModeLabel('native-enforce')).toBe('Native agent enforce');
    expect(policyModeLabel('netra-shadow')).toBe('Netra shadow');
    expect(policyModeLabel('simulation')).toBe('Simulated allow-list');
  });

  it('keeps missing metrics unknown', () => {
    expect(metric(undefined, 'Gb/s')).toBe('Unknown');
    expect(metric(80, 'Gb/s')).toBe('80 Gb/s');
    expect(metric(43.27, '°C')).toBe('43.3 °C');
  });

  it('formats relative time', () => {
    expect(ago(100, 130)).toBe('30s ago');
    expect(ago(0, 7200)).toBe('2h ago');
  });

  it('formats byte counts and lease time', () => {
    expect(bytes(512)).toBe('512 B');
    expect(bytes(1_500_000)).toBe('1.5 MB');
    expect(remaining(null)).toBe('—');
    expect(remaining(100, 200)).toBe('expired');
    expect(remaining(950, 200)).toBe('12m 30s');
  });

  it('parses ports', () => {
    expect(parsePorts('')).toEqual([]);
    expect(parsePorts('443, 8443')).toEqual([443, 8443]);
    expect(parsePorts('0')).toBeNull();
    expect(parsePorts('http')).toBeNull();
  });
});

describe('tones', () => {
  it('maps scores, health, and severity', () => {
    expect(scoreTone(95)).toBe('ok');
    expect(scoreTone(60)).toBe('warn');
    expect(scoreTone(10)).toBe('bad');
    expect(scoreTone(null)).toBe('idle');
    expect(healthTone('stale')).toBe('bad');
    expect(severityTone('critical')).toBe('bad');
  });
});

describe('api errors', () => {
  it('unwraps the JSON envelope', () => {
    expect(errorMessage('{"error":"Wrong username or password."}')).toBe('Wrong username or password.');
    expect(errorMessage('plain')).toBe('plain');
  });
});

describe('topology layout', () => {
  it('places each kind in its own column', () => {
    const geo = layout({
      nodes: [
        { id: 'site:a', kind: 'site', label: 'a' },
        { id: 'host:a/h', kind: 'host', label: 'h' },
        { id: 'dpu:d', kind: 'dpu', label: 'd' },
      ],
      edges: [],
    });
    expect(geo.pos['site:a'].x).toBeLessThan(geo.pos['host:a/h'].x);
    expect(geo.pos['host:a/h'].x).toBeLessThan(geo.pos['dpu:d'].x);
  });
});

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { api } from './api';
import type { Page } from './lib/navGroups';
import type { Device, Session, Snapshot } from './types';

export type PlanAction = 'isolate' | 'release' | 'deploy' | 'upgrade' | 'steer' | 'unsteer';
export interface PlanPreset {
  stage?: 'shadow' | 'enforce';
  ruleset?: string;
  policy?: { name: string; tenant: string; cidr: string; ports: number[] };
}
export type DialogState = { kind: 'plan'; action: PlanAction; devices: string[]; preset?: PlanPreset } | { kind: 'inspect'; device: Device } | null;

interface Fleet {
  session: Session;
  snapshot: Snapshot | null;
  error: string;
  updated: number;
  refresh: () => Promise<void>;
  selected: Set<string>;
  setSelected: (next: Set<string>) => void;
  toast: (message: string) => void;
  navigate: (page: Page) => void;
  dialog: DialogState;
  closeDialog: () => void;
  openPlan: (action: PlanAction) => void;
  openPlanFor: (action: PlanAction, devices: string[], preset?: PlanPreset) => void;
  inspect: (deviceId: string) => void;
  isAdmin: boolean;
}

const FleetContext = createContext<Fleet | null>(null);

export function useFleet(): Fleet {
  const ctx = useContext(FleetContext);
  if (!ctx) throw new Error('useFleet outside FleetProvider');
  return ctx;
}

const POLL_MS = 3000;

export function FleetProvider({
  session,
  navigate,
  toast,
  children,
}: {
  session: Session;
  navigate: (page: Page) => void;
  toast: (message: string) => void;
  children: ReactNode;
}) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState('');
  const [updated, setUpdated] = useState(0);
  const [selected, setSelectedState] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<DialogState>(null);
  const running = useRef(false);

  const refresh = useCallback(async () => {
    if (running.current) return;
    running.current = true;
    try {
      const snap = await api<Snapshot>('snapshot');
      setSnapshot(snap);
      setSelectedState((cur) => {
        const ids = new Set(snap.devices.map((d) => d.id));
        const kept = [...cur].filter((id) => ids.has(id));
        return kept.length === cur.size ? cur : new Set(kept);
      });
      setError('');
      setUpdated(Date.now());
    } catch (e) {
      setError(`Inventory could not be refreshed: ${(e as Error).message}`);
    } finally {
      running.current = false;
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const value: Fleet = {
    session,
    snapshot,
    error,
    updated,
    refresh,
    selected,
    setSelected: (next) => setSelectedState(new Set(next)),
    toast,
    navigate,
    dialog,
    closeDialog: () => setDialog(null),
    openPlan: (action) => {
      if (!selected.size) {
        toast('Select one or more devices in Fleet → Devices first.');
        navigate('devices');
        return;
      }
      setDialog({ kind: 'plan', action, devices: [...selected] });
    },
    openPlanFor: (action, devices, preset) => setDialog({ kind: 'plan', action, devices, preset }),
    inspect: (id) => {
      const device = snapshot?.devices.find((d) => d.id === id);
      if (device) setDialog({ kind: 'inspect', device });
    },
    isAdmin: session.role === 'admin',
  };
  return <FleetContext.Provider value={value}>{children}</FleetContext.Provider>;
}

/** Fetch an API resource, re-fetching every `pollMs` (0 = once) and when `deps` change. */
export function useResource<T>(path: string | null, pollMs = 0, deps: unknown[] = []) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    if (!path) return;
    try {
      setData(await api<T>(path));
      setError('');
    } catch (e) {
      setError((e as Error).message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);
  useEffect(() => {
    void load();
    if (!pollMs) return;
    const t = setInterval(() => void load(), pollMs);
    return () => clearInterval(t);
  }, [load, pollMs]);
  return { data, error, reload: load };
}

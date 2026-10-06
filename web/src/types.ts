export type Role = 'admin' | 'viewer' | 'agent';

export interface Session {
  actor: string;
  role: Role;
  via: 'session' | 'token' | 'key';
  demo: boolean;
  version: string;
  default_password: boolean;
}

export interface Metrics {
  throughput_gbps?: number;
  drops?: number;
  temperature_c?: number;
  link_gbps?: number;
  pps?: number;
  blocked_pps?: number;
  tcp_retransmits_pm?: number;
  tcp_resets_pm?: number;
}

export interface IsolationDest {
  address?: string;
  peer?: string;
  protocol?: string;
  port?: number;
  packets?: number;
  bytes?: number;
}

/** Where eBPF observations and node isolation come from: Duvora's own agent or a Netra controller. */
export type EbpfProvider = 'native' | 'netra';

/** The node's view of its isolation (kernel counters, effective mode), from the agent or Netra. */
export interface NetraIsolationStatus {
  policy_id: string;
  mode: 'shadow' | 'enforce' | 'off' | string;
  requested_mode?: string;
  revision?: number;
  applied_revision?: number;
  /** ISO time from Netra, epoch seconds from the native agent. */
  lease_until?: string | number | null;
  demoted?: string;
  agent_stale?: boolean;
  unavailable?: string;
  allowed_packets: number;
  exempt_packets?: number;
  would_block_packets: number;
  would_block_bytes: number;
  blocked_packets: number;
  blocked_bytes: number;
  would_block_delta?: number;
  blocked_delta?: number;
  top: IsolationDest[];
}

/** What Duvora asked the provider for. */
export interface DuvoraIsolation {
  node: string;
  provider?: EbpfProvider;
  policy_id: string;
  job: string;
  stage: 'shadow' | 'enforce';
  policy: { name: string; tenant: string; cidr: string; ports: number[] };
  lease_until: number | null;
  revision?: number;
  updated: number;
}

export interface Talker {
  peer: string;
  port: number;
  protocol: string;
  packets: number;
  bytes: number;
  blocked?: number;
}

export interface DeviceEbpf {
  provider?: EbpfProvider;
  errors?: string[];
  node: string;
  stale: boolean;
  age: number;
  kernel: string;
  btf: boolean | null;
  programs: string[];
  program_count: number;
  attached: number;
  mode: string;
  interfaces: string[];
  drop_reasons: { reason: string; count: number }[];
  drop_info_unavailable?: string | null;
  tcp_unavailable?: string | null;
  talkers: Talker[];
  nodeiso_available: boolean;
  isolation: NetraIsolationStatus | null;
  updated: number;
}

export interface Service {
  name: string;
  image: string;
  state: string;
}

export interface Device {
  id: string;
  model: string;
  host: string;
  site: string;
  source: 'simulator' | 'linux-pci' | 'nvidia-dpf' | 'netra-ebpf' | 'duvora-ebpf';
  health: string;
  last_seen: number;
  version: number;
  firmware: string;
  mode: string;
  services: Service[];
  policy_ids: string[];
  metrics: Metrics;
  capabilities: string[];
  interfaces: string[];
  metrics_source?: string;
  ebpf?: DeviceEbpf;
  netra_isolation?: DuvoraIsolation;
  steering?: DeviceSteering | null;
  steering_status?: SteeringStatus | null;
}

export type SteerAction = 'bypass' | 'allow' | 'inspect' | 'drop';

export interface SteeringRule {
  priority: number;
  name: string;
  direction: 'egress' | 'ingress' | 'both';
  src: string;
  dst: string;
  protocol: string;
  sport: string;
  dport: string;
  action: SteerAction;
  note?: string;
}

export interface RuleSet {
  id: string;
  description: string;
  default: 'bypass' | 'drop';
  rules: SteeringRule[];
  digest: string;
  updated?: number;
  updated_by?: string;
}

export interface RuleSetSummary extends Omit<RuleSet, 'rules'> {
  rule_count: number;
  actions: Record<SteerAction, number>;
  devices: string[];
}

export interface DeviceSteering {
  ruleset: string;
  digest: string;
  stage: 'shadow' | 'enforce';
  mode: 'simulation' | 'native';
  default: 'bypass' | 'drop';
  rule_count: number;
  job?: string;
  updated?: number;
  bypass?: { engaged: boolean; reason?: string; since?: number; by?: string };
  node?: string;
  lease_until?: number | null;
}

export interface SteeringStatus {
  mode: string;
  attached?: boolean;
  unavailable?: string;
  effective_mode?: string;
  demoted?: string;
  stats: Partial<Record<'matched' | 'allowed' | 'dropped' | 'would_drop' | 'inspected' | 'bypassed' | 'exempt' | 'dropped_bytes' | 'would_drop_bytes', number>>;
  stats_delta?: Record<string, number>;
  rules?: Record<string, { packets: number; bytes: number }>;
  updated?: number;
}

export interface SteeringOverview {
  sets: RuleSetSummary[];
  limits: { max_rules: number; actions: SteerAction[]; defaults: string[] };
  enforce_allowed: boolean;
  kill_switch: boolean;
  note: string;
  devices: { id: string; host: string; source: string; provider: string; steer_available: boolean; steering: DeviceSteering | null; status: SteeringStatus | null }[];
}

export interface Verdict {
  id: number;
  ts: number;
  device: string;
  direction: 'egress' | 'ingress';
  src: string;
  dst: string;
  protocol: string;
  sport: number | null;
  dport: number | null;
  action: SteerAction;
  rule: string | null;
  stage: string;
  packets: number;
  bytes: number;
  source: string;
}

export interface SteeringReplay {
  flows: number;
  unresolved: number;
  actions: Record<SteerAction, { flows: number; packets: number; bytes: number }>;
  rules: Record<string, { flows: number; bytes: number; action: SteerAction }>;
  top: Partial<Record<SteerAction, { peer: string; port: number | null; bytes: number; rule: string | null; direction: string }[]>>;
  source?: string;
  note?: string;
}

export interface SteeringSuggestions {
  device: string;
  ruleset: Omit<RuleSet, 'digest'>;
  reasons?: { rule: string; why: string }[];
  narrative?: string;
}

export interface LlmEndpoint {
  device: string;
  endpoint: string;
  peer: string | null;
  port: number | null;
  provider: string;
  kind: 'hosted' | 'self-hosted' | 'mcp';
  serves: string;
  first: number;
  last: number;
  requests: number;
  findings: number;
  source: string;
  clients: string[];
}

export interface AiFinding {
  id: number;
  ts: number;
  device: string;
  kind: 'prompt-injection' | 'secret' | 'pii';
  detail: string;
  severity: 'info' | 'warning' | 'critical';
  snippet: string;
  endpoint?: string;
  direction?: string;
  peer?: string | null;
  client?: string | null;
  source?: string;
}

export interface AiAsset {
  device: string;
  host: string;
  name: string;
  kind: string;
  port: number;
  first: number;
  last: number;
  source: string;
  evidence: string;
  process?: string;
  sanctioned?: boolean;
}

export interface AiAssets {
  assets: AiAsset[];
  sanctioned: { id: string; name?: string; kind?: string; device?: string; note?: string }[];
  policy_active: boolean;
  unsanctioned: number;
}

export interface AiTraffic {
  generated: number;
  endpoints: LlmEndpoint[];
  findings: AiFinding[];
  counts_24h: Record<'prompt-injection' | 'secret' | 'pii', number>;
  coverage: { overall: number; devices?: Record<string, number> } & Record<string, unknown>;
  assets?: AiAssets;
}

export interface ScanFinding {
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  kind: string;
  detail: string;
  path: string;
}

export interface Scan {
  id: string;
  kind: 'image' | 'url';
  target: string;
  status: 'running' | 'passed' | 'failed' | 'error';
  actor: string;
  started: number;
  finished: number | null;
  findings: ScanFinding[];
  error: string | null;
}

export interface IntelFeed {
  id: string;
  description?: string;
  url?: string;
  format: string;
  count: number;
  networks?: number;
  domains: number;
  error: string | null;
  last_fetch?: number | null;
  refresh_minutes?: number;
  enabled?: boolean;
}

export interface IntelOverview {
  feeds: IntelFeed[];
  matches: { device: string; peer: string; port: number | null; feed: string; indicator: string; direction?: string; bytes?: number; last?: number }[];
  [key: string]: unknown;
}

export interface Playbook {
  id: string;
  name: string;
  enabled: boolean;
  match: { rules: string[]; min_severity: string };
  steps: { type: string; url?: string }[];
}

export interface PlaybookRun {
  id: string;
  playbook: string;
  name: string;
  incident: string;
  rule: string;
  target: string;
  created: number;
  requested_by: string | null;
  steps: { type: string; ok: boolean; detail: string; confirmation?: string }[];
  plans: { id: string; mode: string; confirmation: string; blockers: string[]; expires: number; effects: string; ruleset: string }[];
}

export interface SiemStatus {
  configured: boolean;
  webhook?: string | null;
  syslog?: string | null;
  verdicts?: string;
  categories: string[];
  queued?: number;
  sent?: number;
  dropped?: number;
  failed?: number;
  last_error?: string | null;
  note?: string;
}

export interface AgentIdentity {
  host: string;
  static_key: boolean;
  tokens: number;
  token_expires: number | null;
  last_rotation: number | null;
  last_seen: number | null;
  last_via: string | null;
  mtls_verified: boolean;
  cert_names: string[];
  known_device: boolean;
  unknown: boolean;
  rejections: { time: number; reason: string }[];
}

export interface AgentIdentities {
  identities: AgentIdentity[];
  mtls: 'off' | 'optional' | 'require';
  bootstrap_only: boolean;
  token_ttl: number;
}

export type Resources = Partial<Record<'arm_cores' | 'memory_gb' | 'storage_gb', number>>;

export interface Budget {
  device: string;
  model: string;
  capacity: Resources;
  reserved: Resources;
  used: Resources;
  free: Resources;
  services: { name: string; resources?: Resources }[];
  [key: string]: unknown;
}

export interface KillSwitch {
  engaged: boolean;
  by?: string;
  at?: number;
}

export interface EbpfOverview {
  netra: {
    configured: boolean;
    connected: boolean;
    url?: string;
    last_sync: number | null;
    error: string | null;
    unmatched: string[];
    isolation_supported: boolean;
    enforce_allowed: boolean;
    nodes: number;
    kill_switch: KillSwitch;
  };
  /** DUVORA_EBPF_SOURCE: which provider the server accepts. */
  source?: 'native' | 'netra' | 'auto';
  native?: { agents: number };
  devices: (Pick<DeviceEbpf, 'node' | 'stale' | 'kernel' | 'btf' | 'programs' | 'attached' | 'mode' | 'nodeiso_available' | 'drop_info_unavailable' | 'tcp_unavailable' | 'isolation' | 'updated'> & {
    id: string;
    host: string;
    source: string;
    provider?: EbpfProvider;
    errors?: string[];
    metrics_source?: string;
    netra_isolation?: DuvoraIsolation | null;
  })[];
}

export interface ShadowReplay {
  flows: number;
  would_block_flows: number;
  would_block_packets: number;
  would_block_bytes: number;
  unresolved: number;
  top: { peer: string; port: number; packets: number; bytes: number }[];
  source: string;
  window: number;
}

export interface Policy {
  id: string;
  name: string;
  tenant: string;
  cidr: string;
  ports: number[];
  devices: string[];
  mode: string;
  created: number;
}

export interface JobEvent {
  time: number;
  step: string;
  message: string;
}

export interface Job {
  id: string;
  plan_id: string;
  mode?: 'simulation' | 'netra';
  state: string;
  step: number;
  action: string;
  spec: { action: string; devices: string[]; [key: string]: unknown };
  created: number;
  actor: string;
  events: JobEvent[];
}

export interface AuditEvent {
  seq: number;
  time: number;
  actor: string;
  action: string;
  detail: unknown;
}

export interface Snapshot {
  version: string;
  demo: boolean;
  devices: Device[];
  policies: Policy[];
  jobs: Job[];
  audit: AuditEvent[];
  open_incidents: number;
  capabilities: Record<string, string>;
}

export interface Plan {
  id: string;
  mode: string;
  confirmation: string;
  netra?: boolean;
  job_mode?: 'steer-native' | 'simulation';
  shadow?: Record<string, ShadowReplay | SteeringReplay>;
  effects: string;
  expires: number;
  blockers: string[];
  targets: { id: string; host: string; version: number }[];
}

export interface Incident {
  id: string;
  rule: string;
  target: string;
  severity: 'info' | 'warning' | 'critical';
  title: string;
  detail: string;
  state: 'open' | 'acknowledged' | 'resolved';
  opened: number;
  updated: number;
  acknowledged_by: string | null;
  resolved_at: number | null;
  resolved_by: string | null;
}

export interface AlertRule {
  id: string;
  name: string;
  kind: string;
  metric?: string;
  threshold?: number;
  severity: 'info' | 'warning' | 'critical';
  enabled: boolean;
}

export interface ScorePart {
  name: string;
  weight: number;
  score: number;
  detail: string;
}

export interface Scorecard {
  score: number | null;
  grade: string;
  parts: ScorePart[];
  devices: number;
  generated: number;
}

export interface Briefing {
  generated: number;
  scorecard: Scorecard;
  fleet: { total: number; by_health: Record<string, number>; by_source: Record<string, number>; by_site: Record<string, number> };
  incidents: Incident[];
  jobs: Job[];
  playbook: string[];
  markdown: string;
  anomalies?: Anomaly[];
  forecasts?: (Forecast & { device: string })[];
  new_destinations?: NewDestination[];
  allowlist_suggestions?: { device: string; cidr: string; ports: number[]; coverage_bytes: number }[];
  summary?: string | null;
  summary_source?: 'llm' | 'template' | null;
  ai_posture?: AiPosture;
}

export interface AiPostureCheck {
  name: string;
  weight: number;
  score: number;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
  action: string;
}

export interface AiPosture {
  generated: number;
  score: number;
  grade: string;
  checks: AiPostureCheck[];
  steering: { shadow: number; enforce: number; bypass: number; devices: number };
  note: string;
}

export interface AiStatus {
  llm: boolean;
  model: string | null;
  endpoint: string | null;
  redact: boolean;
  local: string[];
}

export interface Anomaly {
  device: string;
  metric: string;
  value: number;
  baseline: number;
  std: number;
  z: number;
  samples: number;
}

export interface Forecast {
  metric: string;
  threshold: number;
  points: number;
  current: number | null;
  slope_per_hour: number | null;
  r2: number | null;
  eta_hours: number | null;
  reliable: boolean;
}

export interface NewDestination {
  device: string;
  peer: string;
  port: number;
  protocol: string;
  first_seen: number;
  bytes: number;
}

export interface Insights {
  generated: number;
  anomalies: Anomaly[];
  new_destinations: NewDestination[];
  forecasts: (Forecast & { device: string })[];
  forecast_horizon_hours: number;
  baselines: { tracked: number; warm: number; warmup: number };
}

export interface AllowlistCandidate {
  cidr: string;
  ports: number[];
  coverage_bytes: number;
  coverage_flows: number;
  addresses: number;
  would_block_top: { peer: string; port: number; packets: number; bytes: number }[];
  policy: { name: string; tenant: string; cidr: string; ports: number[] };
}

export interface AllowlistSuggestions {
  device: string;
  source: string;
  note: string;
  flows: number;
  bytes: number;
  candidates: AllowlistCandidate[];
}

export interface Hypothesis {
  id: string;
  confidence: 'high' | 'medium' | 'low';
  text: string;
  signals: string[];
}

export interface Explanation {
  incident: Incident;
  hypotheses: Hypothesis[];
  narrative: string;
  narrative_source: 'llm' | 'template';
  narrative_error?: string;
  related: { id: string; rule: string; target: string; title: string; severity: string; state: string; opened: number }[];
  jobs: { id: string; action: string; state: string; created: number; stage?: string }[];
  anomalies: Anomaly[];
}

export interface CopilotMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface CopilotPlan {
  id: string;
  spec: { action: string; devices: string[]; stage?: 'shadow' | 'enforce'; policy?: { name: string; tenant: string; cidr: string; ports: number[] } };
  mode: string;
  blockers: string[];
  confirmation: string;
  effects: string;
}

export interface CopilotReply {
  reply: string;
  tools: { name: string; ok: boolean }[];
  plans: CopilotPlan[];
  model: string;
}

export interface TopologyNode {
  id: string;
  kind: 'site' | 'host' | 'dpu' | 'policy';
  label: string;
  health?: string;
  mode?: string;
  source?: string;
  site?: string;
  tenant?: string;
}

export interface Topology {
  nodes: TopologyNode[];
  edges: { from: string; to: string; kind: string }[];
}

export interface HistoryPoint extends Metrics {
  ts: number;
}

export interface History {
  device: string;
  window: string;
  bucket_seconds: number;
  points: HistoryPoint[];
}

export interface User {
  username: string;
  role: 'admin' | 'viewer';
  created: number;
  disabled: boolean;
  default_password: boolean;
}

export interface ApiToken {
  id: string;
  name: string;
  created: number;
  last_used: number | null;
}

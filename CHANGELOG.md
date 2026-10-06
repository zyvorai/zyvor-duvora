# Changelog

## Unreleased

- Traffic steering ([docs/STEERING.md](docs/STEERING.md)): ordered 5-tuple rule sets (bypass, allow, inspect, drop; up to 1,000 rules; default bypass or drop), `steer` and `unsteer` plans with flow-replay previews, shadow before leased enforce, kill switch, rollback to the previous rule set in shadow. Runs in the host kernel through the new `duvora_steer` TCX program (generation-swapped rules, per-rule counters, flow samples, 256-byte payload capture for `inspect`) or in simulation. Not DPU offload.
- Bypass: manual with `BYPASS <device>` / `RESUME <device>`, automatic during upgrades; `steering-bypass`, `steering-drop` and `steering-would-drop` alerts; verdict history (`/api/v1/verdicts`).
- AI security ([docs/AI.md](docs/AI.md)):
  - LLM traffic inspection: endpoint and provider, prompt injection, secrets and personal data, with masked snippets. Alerts: `llm-prompt-injection`, `llm-secret-leak`, `llm-sensitive-data`, `llm-new-endpoint`.
  - AI asset discovery from `/proc` on agent nodes, with a sanctioned list and the `unsanctioned-ai` alert.
  - Image and model artifact scanning with deploy blockers (`DUVORA_REQUIRE_SCAN`) and the `scan-failed` alert; `duvoractl scan --file` works offline.
  - Threat-intel feeds (plain, CSV, STIX 2) matched against flows, the `intel-match` alert, and intel rule sets.
  - Draft-only playbooks (`llm-threat`, `intel-match`, `steering-drops`).
  - AI posture score in the scorecard, report and briefing.
- Resource budgets: device capacity and platform reservations; deploy plans with `resources` are blocked when they do not fit. The Services page gains a headroom panel.
- Agent identity: rotating short-lived `dva_` tokens (`/api/v1/agent/token`), optional mTLS (`DUVORA_AGENT_MTLS`, `DUVORA_AGENT_CA`), and the `agent-identity-stale` and `agent-identity-unknown` alerts.
- SIEM export of audit events, verdicts, AI findings, intel matches and playbook runs, over a webhook and/or syslog, with a bounded queue.
- Console: Steering, AI traffic, Threats, Playbooks, and Agents & SIEM pages; steer and unsteer in the plan dialog; deploy resources; AI posture on the Report.
- Copilot tools: `steering_state`, `list_verdicts`, `explain_verdict`, `suggest_steering`, `ai_traffic`, `ai_assets`, `scan_results`, `intel_matches`, `posture`; `draft_plan` covers steer and unsteer.
- CLI: `steering`, `steer`, `unsteer`, `bypass`, `verdicts`, `flow`, `steer-suggest`, `budget`, `ai-traffic`, `ai-findings`, `assets`, `scan`, `intel`, `playbooks`, `siem`, `agents`.
- Helm: `agent.steering`, `agent.aiDiscovery`, `agent.tokenRotation`, `siem.*`, `agentIdentity.*`, `scan.*`, `intel.*`, `notify.*`, `integrationsSecret`. `deploy-remote.sh` passes the SIEM, notify and require-scan variables, and when the agent rollout stalls it re-imports an image that kubelet garbage collection removed, then retries once.
- Fix: the steering exemption for the control plane is per address and port, so a control plane on the agent's own host no longer exempts the host's other traffic.
- Validated live on Linux 7.0 (k3s, existing TCX programs on the uplink): a shadow steer plan applied by the agent, would-drop and inspect verdicts, a prompt injection detected in real traffic with incidents opened, the enforce gate, bypass and resume, and token rotation.

## 0.5.0

- AI features, two layers ([docs/AI.md](docs/AI.md)). Local analytics need no configuration and make no external calls:
  - Anomaly detection: EWMA baselines per device and metric (pps, drops, TCP retransmits and resets, throughput, temperature), alert rule `anomaly` with a z-score threshold, warm-up and a three-sample streak.
  - New egress destinations from native or Netra flow records, alert rule `new-destination`.
  - Forecasts: linear fits of temperature and throughput against their thresholds, alert rule `forecast-breach` (hours), shown only when R² ≥ 0.5.
  - Allow-list suggestions: single CIDR plus ports candidates ranked by replayed coverage of observed egress; a picker in the plan dialog.
  - Incident evidence with rule-based hypotheses (isolation blocking, allow-list gaps, closed ports, congestion, path loss, agent restarts, thermal, failed jobs).
- Optional language model over any OpenAI-compatible API (`DUVORA_AI_URL`, `DUVORA_AI_MODEL`, `DUVORA_AI_KEY`, `DUVORA_AI_REDACT`): written incident explanations, an AI briefing summary (`/report?ai=1`), and an ops copilot (`POST /api/v1/copilot`) with read-only tools and an admin-only `draft_plan` that creates a preview but never applies. Telemetry is passed as delimited data, optional redaction tokenizes IPs and host names, 20 questions per minute per principal, audited.
- Console: Insights page, copilot drawer with "Review plan", Explain on incidents, AI summary and insights on the Report.
- `duvoractl insights`, `forecast`, `suggest`, `explain`, `ask`. Helm `ai.*` values; `deploy-remote.sh` passes `DUVORA_AI_*`.
- Prometheus `duvora_anomalies`. The shift briefing gains insights and suggested allow-lists for devices in shadow, and its wording covers native eBPF.
- Validated live on the 0.4.0 test node with the native agent and no language model: insights tracking agent metrics, allow-list suggestions from observed egress flows, rule-based explanations of TCP incidents with native eBPF evidence, and the template briefing summary.

## 0.4.0

- Native eBPF, no sidecar: `duvora-agent --ebpf auto|required` loads Duvora's own programs through the system libbpf (Python ctypes, libbpf 1.3 or later). New Apache-2.0 BPF sources in `bpf/`, compiled by `make bpf` and shipped in `duvora/bpf/obj/`:
  - `duvora_iface`: TCX ingress and egress counters and an egress flow table for top talkers, attached at the head of the chain (works beside Cilium).
  - `duvora_drops`: kernel drop reasons from `tp_btf/kfree_skb`, named from the tracepoint format.
  - `duvora_tcp`: TCP retransmits, resets sent and received.
  - `duvora_nodeiso`: allow-only egress node isolation (off, shadow, enforce) with generation-swapped rules.
- The agent reports to `POST /api/v1/agent/ebpf` and pulls desired isolation from `GET /api/v1/agent/isolation` (both host-bound agent keys). Native hosts appear as `ebpf-<host>` devices (source `duvora-ebpf`) or merge into an existing device for the host.
- Agent-side safety: enforce falls back to shadow when the lease lapses or the control plane is unreachable for `DUVORA_EBPF_FAILSAFE` seconds (60); an override file (`/run/duvora/isolation-off`) turns isolation off locally.
- `DUVORA_EBPF_SOURCE=native|netra|auto` (default `auto`, native wins). Netra stays as an optional provider; plans, gates, confirmations, leases, kill switch and rollback work the same for both. `DUVORA_EBPF_ENFORCE=1` enables enforcement (`DUVORA_NETRA_ENFORCE=1` still works).
- Console and `GET /api/v1/ebpf` show each device's provider (native agent or Netra); policy and plan modes are `native-*` or `netra-*`.
- `DUVORA_AGENT_KEYS` (host to token) for fleets of agents; `DUVORA_CONTROLLER_ADDRESSES` for addresses agents always allow.
- Packaging: `Dockerfile.agent` (clang build stage, `python:3.12-slim` with `libbpf1`), Helm `agent.*` DaemonSet (disabled by default), `deploy-remote.sh` `DUVORA_AGENT=1`.
- Tests: rule encoding, map decoding, drop-reason parsing, native ingest and isolation backend, agent fail-safe; Linux kernel tests (`make bpf-test`) for loading, BPF_PROG_TEST_RUN verdicts, generation swap and real UDP over a veth pair; a `bpf` CI job (ubuntu-24.04) and an agent image build in CI.
- Validated live on Linux 7.0 with k3s and Cilium (libbpf 1.6): native telemetry, then shadow, enforce, kill switch, release, rollback and the local override, with SSH, DNS, HTTPS and the controller reachable throughout.

## 0.3.0

- Netra bridge (`DUVORA_NETRA_URL`, `DUVORA_NETRA_API_KEY`): kernel-measured throughput, packets per second, drops with kernel drop reasons, TCP retransmits and resets, and top talkers, merged into devices and telemetry history. Devices map to Netra nodes by `DUVORA_NETRA_NODE_MAP`, host name, or discovery (`DUVORA_NETRA_DISCOVER=1`).
- eBPF capability probe per node: kernel, BTF, attached programs, drop-reason and TCP event availability, node isolation.
- Isolation stages on Netra nodes. Previews replay recent flow records against the allow-list; shadow counts what the kernel would block; enforce drops new egress flows outside the allow-list. Enforce requires a shadow run of the same allow-list, one device, `DUVORA_NETRA_ENFORCE=1`, and a typed `ENFORCE ON <device>` confirmation. Enforce leases (`DUVORA_NETRA_LEASE`, default 900 s) are renewed while Duvora runs; Netra falls back to shadow without them.
- Kill switch (`POST /api/v1/ebpf/kill-switch`, console, `duvoractl kill-switch`) demotes every enforced node to shadow and blocks enforcement until released. Rollback of a Netra job never re-enforces. Changes made on Netra (lease lapse, deletion, another policy) are detected and recorded.
- New alert rules: `tcp-retransmits`, `tcp-resets`, `ebpf-detached`, `isolation-would-block`, `isolation-blocked`. The shift briefing gains kernel observations.
- Console: kernel observations on Telemetry, node isolation with promote / back to shadow / release and the kill switch on Isolation, eBPF probe on Capabilities, eBPF details in device inspect, shadow replay and stage in the plan dialog.
- `duvoractl ebpf`, `shadow`, `enforce`, `kill-switch`.
- Helm `netra.*` values; `deploy-remote.sh` connects to a Netra running in the same cluster (`DUVORA_NETRA=off` to skip).
- Requires Netra with node isolation (`/api/v1/ebpf/node-isolation`, `netra_nodeiso`) for shadow and enforce; older Netra builds give telemetry only.

## 0.2.0

- Sign in with a username and password (default `admin` / `Admin@321`, or `DUVORA_ADMIN_PASSWORD`). Passwords are scrypt-hashed; sessions are server-side, revocable, and carried in an HttpOnly `SameSite=Strict` cookie. Failed sign-ins are rate-limited.
- Named users with admin/viewer roles, password changes, and personal `dvr_` API tokens. Static `DUVORA_KEYS` access and agent keys still work.
- New console in React + Vite + TypeScript, using the Netra design language: login screen, mega-menu navigation, page heroes, dark mode.
- New pages: Topology, Telemetry history, Incidents, Alert rules, Scorecard, Shift briefing, Users.
- Telemetry history (1h/24h/7d), alert rules with automatic incidents, fleet scorecard, Markdown shift briefing, topology graph.
- Housekeeping of expired plans, old audit events (`DUVORA_AUDIT_RETENTION_DAYS`), samples, resolved incidents and sessions; online SQLite backup endpoint.
- `duvoractl login/logout/whoami/incidents/ack/resolve/rules/scorecard/report/topology/history/users/passwd/backup`; settings saved in `~/.duvora/env`; `DUVORA_CA_FILE` pins a self-signed certificate.
- Optional native TLS (`--tls-cert/--tls-key`). Unknown API paths return 404 and wrong methods 405.
- Deploy: multi-stage `Dockerfile`, `Dockerfile.runtime`, `helm/duvora` chart (NodePort 30880), `scripts/deploy-remote.sh` (`--k3s`, `--k8s`, `--docker`, `--quick`, `--dry-run`, `--verify-only`) and `scripts/deploy-container.sh`.
- CI: web typecheck/tests/build, Helm lint, browser workflow with password sign-in, container smoke test.

## 0.1.0

- Renamed project, Python module, console, CLI, environment variables, deployment resources, and source archives to Duvora.

- Standalone DPU control plane, CLI, console, and read-only inventory agents.
- Persistent simulation workflows for services, isolation, release, firmware upgrade, and rollback.
- Actor-bound expiring previews, revision checks, idempotent apply, and device operation locking.
- Admin/viewer/host-bound agent access keys; Prometheus metrics and JSON evidence export.
- Container and single-replica Kubernetes deployment templates, CI, and acceptance roadmap.

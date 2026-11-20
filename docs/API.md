# HTTP API

Base path: `/api/v1`. API version is `v1`; payload version is `0.5.0`. Except `/healthz`, `POST /api/v1/session` and the console's static files, every request must authenticate with one of:

- the `duvora_session` cookie set by signing in (HttpOnly, `SameSite=Strict`, `Secure` over HTTPS, 12-hour lifetime, revocable server-side);
- `Authorization: Bearer dvr_…` — a personal API token created by a named user (`duvoractl login` creates one);
- `Authorization: Bearer KEY` — a static access or agent key from `DUVORA_KEYS`.

Request bodies (POST, PUT, PATCH) must be a JSON object with `Content-Type: application/json`, at most 64 KiB. No CORS is enabled. An unknown path returns 404; a known path with another method returns 405.

## Session

| Method | Endpoint | Access | Result |
|---|---|---|---|
| POST | `/api/v1/session` | Public | `{"username","password"}` → user; sets the cookie. 401 on bad credentials, 429 after 10 failures in 5 minutes from one client |
| DELETE | `/api/v1/session` | Any | Revokes the session and clears the cookie |
| GET | `/api/v1/session` | Any credential | Principal, role, demo flag |
| GET | `/api/v1/whoami` | Any credential | Principal, role, `via` (`session`, `token`, `key`), `default_password` flag |

## Fleet and changes

| Method | Endpoint | Role | Result |
|---|---|---|---|
| GET | `/healthz` | Public | Process health |
| GET | `/api/v1/snapshot` | Viewer | Fleet, jobs, policies, last 200 audit events, version, open incident count |
| GET | `/api/v1/export` | Viewer | Same evidence snapshot as JSON |
| GET | `/api/v1/metrics` | Viewer | Prometheus text: device/source counts, jobs, `duvora_open_incidents` |
| GET | `/api/v1/devices/{id}/history?window=1h\|24h\|7d` | Viewer | Telemetry points (raw for 1h, 5-minute buckets for 24h, hourly for 7d) |
| GET | `/api/v1/topology` | Viewer | Nodes (site, host, dpu, policy) and edges (contains, hosts, isolates) |
| POST | `/api/v1/reports` | Host-bound agent key | Accepted observed inventory |
| POST | `/api/v1/plans` | Admin | Preview with mode, blockers, expiry, target revisions, the `confirmation` phrase, and (for isolate) a `shadow` replay of observed flow records |
| POST | `/api/v1/plans/{id}/apply` | Plan's admin principal | Idempotent queued job (`mode` `simulation`, or `netra` for any eBPF isolation job, native or Netra) |
| POST | `/api/v1/jobs/{id}/rollback` | Admin | Eligible rollback; an eBPF isolation rollback restores the previous allow-list in shadow and never re-enforces |
| POST | `/api/v1/evaluate` | Admin | Model-only allow/deny verdict |

## eBPF (native agent or Netra)

| Method | Endpoint | Role | Result |
|---|---|---|---|
| POST | `/api/v1/agent/ebpf` | Host-bound agent key | `{"host", "summary"}` from `duvora-agent --ebpf`: interface counters, drops, drop reasons, TCP totals, egress flow deltas, attached programs, node isolation status. Returns the device it merged into. 409 when `DUVORA_EBPF_SOURCE=netra` |
| GET | `/api/v1/agent/isolation` | Host-bound agent key | Desired isolation for the caller's host: `isolation` (`policyId`, `mode`, `rules`, `revision`, `leaseUntil`) or `null`, plus `controller` addresses to always allow |
| GET | `/api/v1/ebpf` | Viewer | `source` (`DUVORA_EBPF_SOURCE`), `native.agents` (fresh native agents), Netra connection (`connected`, `isolation_supported`, `enforce_allowed`, `kill_switch`, `unmatched` nodes) and per-device probe: `provider` (`native` or `netra`), kernel, BTF, attached programs, node isolation status, Duvora's requested isolation |
| GET | `/api/v1/devices/{id}/ebpf` | Viewer | One device: provider, measured metrics, drop reasons, TCP availability, top talkers, node isolation counters |
| POST | `/api/v1/ebpf/kill-switch` | Admin | `{"engaged":true\|false}`. Engaging demotes every enforced node to shadow now and refuses enforce plans until released; returns `demoted` and `errors` |

See [EBPF.md](EBPF.md) for the stages, gates and failure behavior.

## Traffic steering

Host-kernel eBPF on agent nodes, or simulation; never DPU offload. See [STEERING.md](STEERING.md).

| Method | Endpoint | Role | Result |
|---|---|---|---|
| GET | `/api/v1/agent/steering` | Agent | Desired steering for the caller's host (`rulesetId`, `mode`, `rules`, `default`, `bypass`, `revision`, `leaseUntil`) or `null`, plus `controller` addresses |
| GET | `/api/v1/steering` | Viewer | Rule sets (with rule counts by action and the devices using each), limits, `enforce_allowed`, kill switch, and each device's provider, `steer_available`, steering and status |
| GET, PUT, DELETE | `/api/v1/steering/sets/{id}` | Viewer / admin | One rule set; PUT `{"description","default","rules"}` creates or replaces it; DELETE returns 409 while a device uses it |
| POST | `/api/v1/steering/evaluate` | Viewer | `{"ruleset" or "device", "flow":{direction,src,dst,protocol,sport,dport}}` → matching rule, action, priority and a trace |
| POST | `/api/v1/steering/explain[?llm=0]` | Viewer | The evaluation plus a written `narrative` |
| GET | `/api/v1/devices/{id}/steering` | Viewer | The device's steering, kernel status (stats, rule hits), applied rules and the last 50 verdicts |
| POST | `/api/v1/devices/{id}/steering/bypass` | Admin | `{"engaged":true,"confirmation":"BYPASS <id>"}` or `{"engaged":false,"confirmation":"RESUME <id>"}`, optional `reason` |
| GET | `/api/v1/devices/{id}/steering-suggestions` | Viewer | Rule candidates: inspect LLM and inference endpoints, bypass bulk storage and RDMA, drop intel matches |
| GET | `/api/v1/verdicts?device=&action=&rule=&limit=` | Viewer | Flow verdicts, newest first (7 days) |
| GET | `/api/v1/devices/{id}/budget` | Viewer | `capacity`, `reserved`, `used`, `free` (`arm_cores`, `memory_gb`, `storage_gb`), services and the capacity source |

## AI security

| Method | Endpoint | Role | Result |
|---|---|---|---|
| GET | `/api/v1/ai-traffic` | Viewer | LLM endpoints, findings (24 h), counts by kind, inspection coverage, assets |
| GET | `/api/v1/ai/findings?device=&kind=&limit=` | Viewer | Inspection findings: `prompt-injection`, `secret`, `pii` |
| GET | `/api/v1/ai/assets` | Viewer | Discovered AI services and LLM endpoints with `sanctioned`, the sanctioned list, `unsanctioned` count |
| POST | `/api/v1/ai/sanctioned` | Admin | `{"kind","name","device","note"}` (globs allowed; at least one of kind, name, device) |
| DELETE | `/api/v1/ai/sanctioned/{id}` | Admin | Removes a sanctioned entry |
| GET | `/api/v1/ai/posture` | Viewer | Posture `score`, `grade`, `checks` (`name`, `weight`, `score`, `status`, `detail`, `action`) and steering counts |
| GET, POST | `/api/v1/scans` | Viewer / admin | Scans, or start one: `{"image":"registry/repo@sha256:…"}` or `{"url":"https://…/model.pt"}` |
| GET | `/api/v1/scans/{id}` | Viewer | One scan with findings |
| GET | `/api/v1/intel` | Viewer | Feeds and matching flows |
| PUT, DELETE | `/api/v1/intel/feeds/{id}` | Admin | `{"url" or "indicators","format":"plain\|csv\|stix","refresh_minutes","enabled","description"}` |
| POST | `/api/v1/intel/refresh` | Admin | `{"feed"}` optional; fetches now |
| POST | `/api/v1/intel/ruleset` | Admin | `{"id","base"}` → a steering rule set dropping every indicator |
| GET | `/api/v1/playbooks` | Viewer | Playbooks (trigger rules, minimum severity, steps) |
| PUT, DELETE | `/api/v1/playbooks/{id}` | Admin | Create, replace or delete a playbook |
| POST | `/api/v1/playbooks/{id}/run` | Admin | `{"incident"}`; runs the playbook now (drafts only) |
| GET | `/api/v1/playbook-runs?incident=&limit=` | Viewer | Runs with each step's outcome and drafted plan ids |

## Agent identity and SIEM

| Method | Endpoint | Role | Result |
|---|---|---|---|
| POST | `/api/v1/agent/token` | Agent | A short-lived `dva_…` token for the caller's host (`DUVORA_AGENT_TOKEN_TTL`, default 24 h); at most three live per host |
| GET | `/api/v1/agent-identities` | Admin | Per host: static key, live tokens, expiry, last rotation, last credential type, mTLS verification, certificate names, recent rejections; `mtls` mode |
| GET | `/api/v1/siem` | Admin | Export configuration, queued, sent and dropped counts, last error |
| POST | `/api/v1/siem/test` | Admin | Sends a test event and flushes |

With `DUVORA_AGENT_MTLS=optional|require` and `DUVORA_AGENT_CA`, agent requests are checked against the client certificate's DNS names or CN: it must name the agent's host. `require` rejects agent requests without a certificate.

## AI and insights

| Method | Endpoint | Role | Result |
|---|---|---|---|
| GET | `/api/v1/ai` | Viewer | `llm` (configured), `model`, `endpoint` host, `redact`, and the local features |
| GET | `/api/v1/insights` | Viewer | `anomalies` (device, metric, value, baseline, std, z), `forecasts` (reliable fits with `eta_hours`), `new_destinations`, `forecast_horizon_hours`, baseline warm-up counts |
| GET | `/api/v1/devices/{id}/forecast` | Viewer | Temperature and throughput fits: `slope_per_hour`, `r2`, `eta_hours`, `reliable` |
| GET | `/api/v1/devices/{id}/allowlist-suggestions` | Viewer | Up to 5 candidates `{cidr, ports, coverage_bytes, coverage_flows, addresses, would_block_top, policy}` from observed egress |
| GET | `/api/v1/incidents/{id}/explain[?llm=0]` | Viewer | Evidence (device, eBPF, samples, jobs, audit, related incidents, anomalies), `hypotheses` (`id`, `confidence`, `text`, `signals`), `narrative` and `narrative_source` (`llm` or `template`); `narrative_error` when the model failed |
| GET | `/api/v1/report?ai=1` | Viewer | The briefing with `summary` and `summary_source` |
| POST | `/api/v1/copilot` | Viewer (`draft_plan` needs admin) | `{"messages":[{"role":"user","content":"…"}]}` (1–20 messages, 4,000 characters each) → `{"reply","tools","plans","model"}`. 503 without `DUVORA_AI_URL`, 429 above 20 per minute per principal. Never applies a plan |

Details, data sent to the model, and limits: [AI.md](AI.md).

## Monitoring and reports

| Method | Endpoint | Role | Result |
|---|---|---|---|
| GET | `/api/v1/incidents?state=open\|acknowledged\|resolved\|active` | Viewer | Incidents, newest first (`active` = open or acknowledged) |
| POST | `/api/v1/incidents/{id}/ack` | Admin | Acknowledge an open incident |
| POST | `/api/v1/incidents/{id}/resolve` | Admin | Resolve an incident |
| GET | `/api/v1/alert-rules` | Viewer | Rules: temperature-high, packet-drops, health-degraded, device-stale, job-failed, tcp-retransmits, tcp-resets, ebpf-detached, isolation-would-block, isolation-blocked, anomaly (threshold = z-score), new-destination, forecast-breach (threshold = hours), steering-bypass (minutes), steering-drop, steering-would-drop, llm-prompt-injection, llm-secret-leak, llm-sensitive-data, llm-new-endpoint, unsanctioned-ai, intel-match, scan-failed, agent-identity-stale (hours), agent-identity-unknown |
| PUT | `/api/v1/alert-rules/{id}` | Admin | `{"enabled","threshold","severity"}` (any subset) |
| GET | `/api/v1/scorecard` | Viewer | Fleet score 0–100 (or null with no devices), grade, weighted parts, and `ai_posture` (score, grade) |
| GET | `/api/v1/report` | Viewer | Shift briefing as JSON, including `markdown` |
| GET | `/api/v1/report.md` | Viewer | Shift briefing as a Markdown download |

## Users, tokens and backup

| Method | Endpoint | Role | Result |
|---|---|---|---|
| GET | `/api/v1/users` | Admin | Users (no password hashes) |
| POST | `/api/v1/users` | Admin | `{"username","role":"admin\|viewer","password"}` |
| PATCH | `/api/v1/users/{name}` | Admin | `{"role","password","disabled"}`; revokes the user's sessions; the last enabled admin is protected |
| DELETE | `/api/v1/users/{name}` | Admin | Deletes the user, their sessions and tokens |
| POST | `/api/v1/me/password` | Named user | `{"current","new"}`; passwords need at least 8 characters |
| GET | `/api/v1/tokens` | Named user | Your tokens (name, created, last used; never the secret) |
| POST | `/api/v1/tokens` | Named user | `{"name"}` → `{"id","name","token"}`; the secret is shown once |
| DELETE | `/api/v1/tokens/{id}` | Named user | Revokes one of your tokens |
| GET | `/api/v1/backup` | Admin | Consistent SQLite snapshot (`application/vnd.sqlite3`) |

"Named user" means a session or personal token, not a static `DUVORA_KEYS` key.

## Bodies

Plan examples are in `examples/`. Supported actions: `isolate`, `release`, `deploy`, `upgrade`, `steer`, `unsteer`. Unknown fields are rejected. Targets are explicit IDs; selectors cannot silently expand after preview.

Apply with the plan's `confirmation` phrase: `APPLY SIMULATION` for simulation plans, `APPLY SHADOW` or `APPLY RELEASE` for eBPF isolation plans, `ENFORCE ON <device>` to enforce isolation, `APPLY STEERING SHADOW` or `APPLY STEERING RELEASE` for native steering, and `ENFORCE STEERING ON <device>` to enforce steering. Plans drafted by a playbook can be applied by any admin.

Steering plan (`stage` is `shadow` by default; the preview's `shadow` field replays observed flows against the rule set):

```json
{"action":"steer","devices":["ebpf-node-1"],"ruleset":"ai-gateway","stage":"shadow"}
```

Deploy with a resource request, checked against the device budget, and blocked when the image's latest artifact scan failed:

```json
{"action":"deploy","devices":["bf3-01"],"service":"fw","image":"r.io/fw@sha256:…","resources":{"arm_cores":2,"memory_gb":4}}
```

```json
{"confirmation":"APPLY SIMULATION"}
```

eBPF isolation plan, for a device fed by the native agent or Netra (`stage` is `shadow` by default; `enforce` needs the same allow-list already in shadow, one device, `DUVORA_EBPF_ENFORCE=1` or `DUVORA_NETRA_ENFORCE=1`, and the kill switch released). The plan `mode` is `native-shadow`, `netra-enforce` and so on:

```json
{"action":"isolate","devices":["ebpf-node-1"],"stage":"shadow","policy":{"name":"egress","tenant":"ops","cidr":"10.0.0.0/8","ports":[443]}}
```

```json
{"device":"bf3-01","address":"10.42.0.20","port":443}
```

Report shape:

```json
{"id":"pci-example","host":"gpu-01","site":"pune","source":"linux-pci","model":"BlueField-3","firmware":"unknown","health":"unknown","metrics":{},"interfaces":["p0"]}
```

Supported observed metric keys: `throughput_gbps`, `drops`, `temperature_c`, `link_gbps`; values must be nonnegative finite numbers. Agent values are trusted reports, not independent measurements verified by the controller. Source must be `linux-pci` or `nvidia-dpf`; agents cannot set simulator capabilities or desired enforcement state. Every accepted report is also recorded as a telemetry sample.

Native eBPF report shape (abridged; every field is type-checked and bounded, unknown fields are dropped):

```json
{"host":"gpu-01","summary":{"kernel":"6.8.0","btf":true,"programs":["duvora_iface_egress","duvora_kfree_skb"],"attached":6,
 "interfaces":{"eth0":{"packets":1200,"bytes":980000,"blocked":0}},"drops":3,"drop_reasons":[{"reason":"NO_SOCKET","count":4}],
 "tcp":{"retransmits":2,"resets":24},"flows":[{"peer":"1.1.1.1","port":443,"protocol":"tcp","packets":4,"bytes":272,"observedAt":"2026-10-01T17:01:19Z"}],
 "nodeiso_available":true,"isolation":{"policyId":"duvora-abc","mode":"enforce","effectiveMode":"shadow","demoted":"lease expired","revision":3,"appliedRevision":3,
 "wouldBlockPackets":12,"blockedPackets":0,"top":[{"address":"8.8.8.8","port":53,"protocol":"udp","packets":12,"bytes":900}]}}}
```

## Errors

Errors return `{"error":"message"}` with 400 (validation), 401 (authentication), 403 (role/identity), 404 (missing object or path), 405 (method), 409 (stale/expired/blocked/conflicting state), 413 (body size), 415 (content type), or 429 (sign-in rate limit).

Apply retries return the same job. Poll the snapshot for job progress. Plans expire after 300 seconds. Jobs serialize changes per selected device. A rollback is blocked after later revisions; rollback is not a general history stack or a physical recovery mechanism. Full audit history remains in SQLite (subject to retention); snapshot/export expose only the latest 200 events.

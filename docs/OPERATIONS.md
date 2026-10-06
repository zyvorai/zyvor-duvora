# Operations

## Sign-in and users

On first start Duvora creates the user `admin`. Its password comes from `DUVORA_ADMIN_PASSWORD`; without it the password is `Admin@321` and the console shows a banner until it is changed. The variable only applies when the database is created — afterwards, change passwords in **Govern → Users** or with `duvoractl passwd`.

- Roles: `admin` (all changes) and `viewer` (read-only). The last enabled admin cannot be demoted, disabled, or deleted.
- Passwords are stored as scrypt hashes and need 8–256 characters.
- Sessions live 12 hours, are stored server-side (hashed), and are revoked on sign-out, password reset, role change, or disable.
- After 10 failed sign-ins within 5 minutes, a client address receives 429 until the window passes.
- Behind an HTTPS proxy, forward `X-Forwarded-Proto: https` so the cookie is marked `Secure`.

Binding to a non-loopback address requires `DUVORA_ADMIN_PASSWORD` or `DUVORA_KEYS`, so a network-exposed server never relies on the published default.

## CLI

```bash
duvoractl --url https://duvora.example:30880 login     # prompts for username and password
duvoractl whoami
duvoractl incidents && duvoractl ack INCIDENT_ID
duvoractl users add alice --role viewer                # prompts for alice's password
duvoractl backup duvora-$(date +%F).db
duvoractl logout                                       # revokes the saved token
```

`login` creates a personal API token and saves `DUVORA_URL`, `DUVORA_TOKEN` and `DUVORA_CA_FILE` in `~/.duvora/env` (mode 600). Environment variables override the file. Remote URLs must be HTTPS; for a self-signed deployment set `DUVORA_CA_FILE` to its certificate — verification is never disabled.

## Static access and agent keys

Agents, the DPF bridge and automation can use static keys. Generate one token per principal using `python -c "import secrets; print(secrets.token_urlsafe(32))"` and configure them as JSON:

```bash
export DUVORA_KEYS='{
  "operator":{"role":"admin","token":"REPLACE_WITH_RANDOM_ADMIN_TOKEN"},
  "auditor":{"role":"viewer","token":"REPLACE_WITH_RANDOM_VIEWER_TOKEN"},
  "agent:gpu-01":{"role":"agent","token":"REPLACE_WITH_RANDOM_AGENT_TOKEN"}
}'
python3 -m duvora.server --demo
```

Example strings are placeholders. Each token needs at least 24 characters and must be unique. Restart to rotate configured keys. An agent principal must be `agent:<report-host>`. Do not commit environment values or key files.

## TLS

Pass `--tls-cert` and `--tls-key` (or `DUVORA_TLS_CERT` / `DUVORA_TLS_KEY`) to serve HTTPS directly; otherwise terminate TLS in a proxy. The provided HTTP server is an evaluation service, not an Internet-facing security boundary; restrict ingress for wider deployments.

## Remote deploy (k3s + Helm)

```bash
./scripts/deploy-remote.sh user@10.0.1.5            # or: make deploy HOST=user@10.0.1.5
```

The script syncs the repository to `~/.deployments/duvora`, installs k3s and Helm if missing, generates a self-signed certificate in `~/.duvora/tls`, builds the image with podman or docker (the console is built on the host when npm is present, otherwise inside the multi-stage Dockerfile), imports it into k3s, installs `helm/duvora`, forces a rollout restart, and waits for the rollout. It then writes `~/.duvora/env`, installs a `duvoractl` wrapper in `~/.local/bin`, and prints `https://<host>:30880`.

| Flag | Behavior |
|---|---|
| `--k3s` (default) | Install k3s if needed, build, import, Helm |
| `--k8s` | Use the host's existing kubeconfig |
| `--docker` | One container with podman/docker, no Kubernetes (`scripts/deploy-container.sh`) |
| `--quick` | Sync and Helm only; the image must already be imported |
| `--dry-run` | Print the remote script without connecting |
| `--verify-only` | Show pods/containers and check `/healthz` |

Set `DUVORA_ADMIN_PASSWORD` (default `Admin@321`), `DUVORA_KEYS`, or `DUVORA_DEMO=0` before running. The deploy refuses to run above `DUVORA_DEPLOY_MAX_DISK_PCT` (95%) root-disk usage and re-imports the image if kubelet's image garbage collection removed it.

## Native eBPF agent

`duvora-agent --ebpf auto` on a Linux host (6.6 or later, BTF, libbpf 1.3 or later, root or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`) loads Duvora's eBPF programs on the uplinks and reports to `POST /api/v1/agent/ebpf` with a host-bound agent key. The device appears as `ebpf-<host>` unless a device for that host already exists. Details: [EBPF.md](EBPF.md).

Server settings:

| Variable | Default | Meaning |
|---|---|---|
| `DUVORA_EBPF_SOURCE` | `auto` | `native`, `netra`, or `auto` (a fresh native report wins) |
| `DUVORA_EBPF_ENFORCE` | off | `1` allows promoting shadow isolation to enforce (`DUVORA_NETRA_ENFORCE=1` does the same) |
| `DUVORA_NETRA_LEASE` | 900 | Enforce lease in seconds (60–3600), for both providers |
| `DUVORA_AGENT_KEYS` | — | JSON object of host to token; each becomes an `agent:<host>` key (added to `DUVORA_KEYS`) |
| `DUVORA_CONTROLLER_ADDRESSES` | — | Comma-separated addresses every agent always allows under isolation |

Agent settings: `DUVORA_TOKEN` (or `DUVORA_AGENT_KEYS_FILE`, the same JSON, from which the agent takes its own host's token), `DUVORA_EBPF` (`off`, `auto`, `required`), `DUVORA_EBPF_INTERFACES`, `DUVORA_EBPF_ISOLATION=off`, `DUVORA_EBPF_FAILSAFE` (60 s), `DUVORA_EBPF_OVERRIDE` (`/run/duvora/isolation-off`), `DUVORA_CA_FILE`.

To stop isolation on a host without the control plane, create the override file: `sudo mkdir -p /run/duvora && sudo touch /run/duvora/isolation-off`. The agent turns isolation off at its next interval (15 s by default). Remove the file to resume.

With Helm, enable the agent DaemonSet:

```bash
helm upgrade --install duvora ./helm/duvora -n duvora \
  --set agent.enabled=true --set ebpf.enforce=true \
  --set-json 'agent.keys={"node-1":"<random 32+ chars>","node-2":"<random 32+ chars>"}'
```

The DaemonSet runs `duvora-agent --ebpf auto` with `hostNetwork`, the capabilities `BPF`, `NET_ADMIN`, `PERFMON` and `SYS_RESOURCE`, and mounts `/sys/fs/bpf`, `/sys/kernel/btf`, `/sys/kernel/tracing` and `/run/duvora` from the host. Each pod reports as its node name and uses that node's key from `agent.keys`. `deploy-remote.sh` builds the agent image and enables it with `DUVORA_AGENT=1`, generating a key for the host:

```bash
DUVORA_AGENT=1 DUVORA_EBPF_ENFORCE=1 ./scripts/deploy-remote.sh user@10.0.1.5
```

The TCX programs attach at the head of each uplink's chain, ahead of Cilium's `cil_from_netdev`/`cil_to_netdev`, which end the chain. Check with `sudo bpftool net show dev <uplink>`: `duvora_iface_ingress`, `duvora_iface_egress` and `duvora_nodeiso_egress` should be listed before the Cilium programs.

If Netra also runs on the node, turn its node isolation off so only one egress filter is active: set `agent.nodeIsolation=off` in Netra's Helm values (or `kubectl -n netra-system set env ds/netra-agent NETRA_NODE_ISOLATION=off`, which the next Netra `helm upgrade` reverts). Netra telemetry can stay on; with `DUVORA_EBPF_SOURCE=auto` a fresh native report wins for that host.

Before the first enforce on a remote host, arm a fallback that does not depend on the control plane, for example `sudo systemd-run --on-active=420 /bin/sh -c 'mkdir -p /run/duvora && touch /run/duvora/isolation-off'`, and stop the timer (`sudo systemctl stop <unit>.timer`) once you are done. SSH (local port 22), established TCP, ICMP, DHCP and the controller addresses are always allowed.

## AI features

Anomaly detection, forecasts, new-destination alerts, allow-list suggestions and incident evidence always run on the control plane with no configuration. Tune them as alert rules: `duvoractl rules anomaly --threshold 5` (z-score), `duvoractl rules forecast-breach --threshold 12` (hours), `duvoractl rules new-destination --disable`.

To enable the copilot, written explanations and the AI briefing summary, point Duvora at an OpenAI-compatible endpoint:

```bash
# Local Ollama on the controller host
DUVORA_AI_URL=http://127.0.0.1:11434/v1 DUVORA_AI_MODEL=llama3.1:8b python3 -m duvora.server
# Helm, in-cluster Ollama
helm upgrade duvora ./helm/duvora -n duvora --reuse-values \
  --set ai.url=http://ollama.ai.svc:11434/v1 --set ai.model=llama3.1:8b --set ai.allowHttp=true --set ai.redact=true
```

`GET /api/v1/ai` (or the Insights page) shows whether a model is configured. A model that is down or slow does not break anything: explanations and summaries fall back to templates, and the copilot returns 503. Data sent, redaction and limits: [AI.md](AI.md).

## Traffic steering and AI security

The agent loads `duvora_steer` beside isolation unless `--no-steering` (Helm `agent.steering=false`) is set. Check with `sudo bpftool net show dev <uplink>`: `duvora_steer_ingress` and `duvora_steer_egress` should head the TCX chains. `/run/duvora/steering-off` on the host turns steering off locally. Shadow never drops traffic. Enforce needs `DUVORA_EBPF_ENFORCE=1`, a shadow run of the same rule set, and a typed confirmation, and it is leased like isolation.

Before the first steering enforce on a remote host, arm the same kind of fallback as for isolation, with `steering-off` instead of `isolation-off`. SSH and the control-plane endpoint are always exempt. Workflow and limits: [STEERING.md](STEERING.md).

| Variable | Default | Meaning |
|---|---|---|
| `DUVORA_SIEM_URL` / `DUVORA_SIEM_KEY` | — | HTTPS webhook receiving JSON batches of `audit`, `verdict`, `ai-finding`, `intel` and `playbook` events, with a bearer key |
| `DUVORA_SIEM_SYSLOG` | — | `udp://host:514` or `tcp://host:601`, RFC 5424 |
| `DUVORA_SIEM_EVENTS` | all | Comma-separated categories to export |
| `DUVORA_SIEM_VERDICTS` | `drop` | Steering verdicts to export: `drop`, `all` or `none` |
| `DUVORA_SIEM_CA_FILE`, `DUVORA_SIEM_ALLOW_HTTP` | — | Pin a private CA; allow plain HTTP to a non-loopback receiver |
| `DUVORA_AGENT_TOKEN_TTL` | 86400 | Rotating agent token lifetime in seconds (600 to 30 days); agents rotate at half-life |
| `DUVORA_AGENT_BOOTSTRAP_ONLY` | off | `1`: static agent keys may only mint tokens, not report |
| `DUVORA_AGENT_MTLS` / `DUVORA_AGENT_CA` | `off` | `optional` or `require` client certificates naming the agent's host; needs TLS and the CA file. Agents send `DUVORA_CLIENT_CERT` / `DUVORA_CLIENT_KEY` |
| `DUVORA_REQUIRE_SCAN` | off | `1` blocks deploys of images without a passed artifact scan |
| `DUVORA_SCAN_MAX_MB`, `DUVORA_REGISTRY_TOKEN`, `DUVORA_SCAN_CA_FILE` | 512, —, — | Scan size cap, private registry bearer token, private CA |
| `DUVORA_INTEL_CA_FILE`, `DUVORA_INTEL_ALLOW_HTTP` | — | Threat-intel feed fetching |
| `DUVORA_NOTIFY_URL`, `DUVORA_NOTIFY_KEY`, `DUVORA_NOTIFY_CA_FILE` | — | Webhook for playbook `notify` steps |

In Helm, the same settings are under `siem.*`, `agentIdentity.*`, `scan.*`, `intel.*` and `notify.*`. Keys and CA files go into a `<release>-integrations` Secret, or into your own Secret named by `integrationsSecret`. `deploy-remote.sh` passes `DUVORA_SIEM_URL`, `DUVORA_SIEM_KEY`, `DUVORA_SIEM_SYSLOG`, `DUVORA_NOTIFY_URL`, `DUVORA_NOTIFY_KEY` and `DUVORA_REQUIRE_SCAN`.

## Netra eBPF (optional)

Set `DUVORA_NETRA_URL` (HTTPS unless loopback) and `DUVORA_NETRA_API_KEY` to connect a [Netra](https://github.com/zyvorai/zyvor-netra) controller; `DUVORA_NETRA_CA_FILE` pins a self-signed certificate. Devices map to Netra nodes by `DUVORA_NETRA_NODE_MAP` (JSON of device id or host to node), by host name, or, with `DUVORA_NETRA_DISCOVER=1`, as new `netra-<node>` devices. `DUVORA_NETRA_INTERVAL` (default 15 s) sets the polling period.

Node isolation needs a Netra admin key and a Netra build with `/api/v1/ebpf/node-isolation`. Enforcement is off unless `DUVORA_NETRA_ENFORCE=1`; enforce leases last `DUVORA_NETRA_LEASE` seconds (default 900) and are renewed while Duvora runs. Engage the kill switch (console **Operate → Isolation**, or `duvoractl kill-switch on`) to send every node back to shadow. Details: [EBPF.md](EBPF.md).

`deploy-remote.sh` connects automatically when the host runs Netra in the same k3s cluster (`netra-system/netra` and `~/.netra/api-key`); `DUVORA_NETRA=off` skips it and `DUVORA_NETRA_ENFORCE=1` allows enforcement.

## Helm chart

```bash
helm upgrade --install duvora ./helm/duvora -n duvora --create-namespace \
  --set auth.adminPassword='CHANGE-ME' \
  --set tls.enabled=true --set-file tls.cert=tls.crt --set-file tls.key=tls.key
```

One replica with the `Recreate` strategy (SQLite has a single writer), a kept PVC, a Secret for the admin password and optional keys, NodePort 30880 by default, non-root UID 10001, read-only root filesystem, dropped capabilities, and no service-account token. `deploy/kubernetes.yaml` remains as a plain-manifest alternative.

## Container

```bash
DUVORA_ADMIN_PASSWORD='CHANGE-ME' docker compose up --build
```

Compose exposes loopback only, runs as a non-root user, drops capabilities, and persists `/data`. `DUVORA_DEMO=0` starts without simulation. Do not mix customer hardware observations with a sales-demo database.

## State, housekeeping and recovery

SQLite stores users, sessions, tokens, devices, plans, jobs, policies, samples, incidents, and audit history. Writes use one transaction lock and SQLite immediate transactions. Jobs progress once per second in simulation mode and resume after restart.

Every minute the server deletes unused plans expired for over an hour, audit events older than `DUVORA_AUDIT_RETENTION_DAYS` (default 90), telemetry samples older than 7 days, resolved incidents older than 30 days, and expired sessions.

Back up online with `duvoractl backup FILE` or `GET /api/v1/backup` (admin), which uses SQLite's backup API — never copy only the main file while WAL is active. Stop the service before restoring. Protect backups: they contain password hashes and inventory.

Rollback restores eligible simulated desired state and preserves monotonic device revisions. It refuses to overwrite later changes. There is no physical firmware rollback in this release.

## Observability

`/healthz` is public liveness. `/api/v1/metrics` (viewer) reports device/source counts, job count, `duvora_open_incidents`, `duvora_steering_devices{stage}`, `duvora_steering_bypass`, `duvora_siem_queued` and `duvora_siem_dropped`. Alert rules raise incidents for high temperature, packet drops, degraded health, stale observations, and failed jobs; incidents resolve automatically when the condition clears. Hardware observations older than 120 seconds are stale.

## Evaluation limits

- Single process, single SQLite backend; no HA or distributed worker coordination.
- No SSO/OIDC or tenant-scoped RBAC; admins have fleet-wide authority.
- No hardware execution, retries against vendor services, real container readiness, or storage acceleration.
- Audit history is not tamper-resistant; database access can alter it.
- Simulator telemetry is a random walk, not benchmark data.

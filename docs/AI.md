# AI features

Duvora's AI features come in two layers:

- **Local analytics.** These always run on the control plane, use only the Python standard library, and never call out: anomaly detection, new-destination detection, forecasts, allow-list suggestions, and incident evidence with rule-based hypotheses.
- **An optional language model.** It writes incident explanations and the briefing summary, and powers the ops copilot. It uses any OpenAI-compatible chat completions API: Ollama, vLLM, LM Studio or a hosted provider. Without one, explanations and summaries fall back to templates and the copilot reports that it is not configured.

A third set of features protects AI workloads themselves: LLM traffic inspection, AI asset discovery, artifact scanning, threat intel, draft-only playbooks and an AI posture score (see [AI security](#ai-security)).

The guarantee in every layer is the same: **AI never changes the fleet.** The copilot's tools are read-only. The one exception is `draft_plan`, which creates a plan *preview* and is admin-only. Applying a plan still requires the plan's typed confirmation (`APPLY SHADOW`, `ENFORCE ON <device>` and so on) through the normal API or console, with every existing gate: shadow before enforce, `DUVORA_EBPF_ENFORCE`, kill switch, lease.

## Local analytics

| Feature | How it works | Where |
|---|---|---|
| Anomalies | EWMA mean and variance per device and metric (`pps`, `drops`, `tcp_retransmits_pm`, `tcp_resets_pm`, `throughput_gbps`, `temperature_c`), updated on every recorded sample. A metric is anomalous after 30 warm-up samples once three consecutive samples are beyond the z-score threshold in the same direction. Each metric has a minimum standard deviation so a flat series does not turn noise into a large z-score. | Alert rule `anomaly` (threshold = z, default 4), Insights page, `GET /api/v1/insights` |
| New destinations | Every egress (peer, port, protocol) from native or Netra flow records is remembered per device for 7 days. A destination is new when it was first seen in the last 15 minutes, not in the previous 24 hours, has at least 1 KB, and the device has been observed for at least an hour. | Alert rule `new-destination`, Insights |
| Forecasts | Least-squares line over the 24-hour, 5-minute history for temperature (against the `temperature-high` threshold) and throughput (against 90% of `link_gbps`). Shown only with at least 12 points and R² ≥ 0.5. | Alert rule `forecast-breach` (threshold = hours, default 6), `GET /api/v1/devices/{id}/forecast` |
| Allow-list suggestions | Candidate policies (one CIDR plus ports, the shape a Duvora policy has) are built from the device's observed egress: the top /32, /24, /16, /8 and 0.0.0.0/0 networks plus the tightest network covering every peer, each with no port restriction, all observed ports, or the ports carrying 95% of bytes. Every candidate is scored with the same replay the plan preview uses and ranked by bytes covered, then by narrowness. | Plan dialog ("Suggest allow-list"), briefing, `GET /api/v1/devices/{id}/allowlist-suggestions` |
| Incident evidence | Metric samples around the incident, drop reasons, TCP rates, talkers, isolation state and counters, jobs and audit events within 30 minutes, related incidents on the same device or host, and current anomalies, plus rule-based hypotheses ranked by confidence. | Incidents → Explain, `GET /api/v1/incidents/{id}/explain` |

Anomalies need a few minutes of samples per device (30 samples; 15-second agent intervals give about 8 minutes). Forecasts need an hour of 5-minute buckets, and a device that reports a forecastable metric: nodes seen only through the eBPF agent report neither `temperature_c` nor `link_gbps`, so their forecast lists the metric as not reliable with no points. Baselines are kept in the database, so a restart or upgrade does not reset warm-up.

## Language model

```bash
export DUVORA_AI_URL=http://127.0.0.1:11434/v1     # Ollama; any OpenAI-compatible base URL
export DUVORA_AI_MODEL=llama3.1:8b
export DUVORA_AI_KEY=...                           # if the endpoint needs a bearer key
export DUVORA_AI_REDACT=1                          # optional: tokenize IPs and host names
```

| Variable | Default | Meaning |
|---|---|---|
| `DUVORA_AI_URL` | — | Base URL; Duvora calls `POST {url}/chat/completions`. HTTPS unless loopback |
| `DUVORA_AI_MODEL` | — | Model name (required with the URL) |
| `DUVORA_AI_KEY` | — | Bearer key |
| `DUVORA_AI_CA_FILE` | — | PEM bundle to verify a private CA |
| `DUVORA_AI_TIMEOUT` | 30 | Seconds per request (1–300) |
| `DUVORA_AI_REDACT` | off | `1` replaces IP addresses and device, host and node names with tokens (`ip-1`, `host-2`) before any text leaves Duvora, and restores them in the answer |
| `DUVORA_AI_ALLOW_HTTP` | off | `1` allows plain HTTP to a non-loopback endpoint, for an in-cluster Ollama |

With Helm: `--set ai.url=... --set ai.model=... --set ai.key=...` (or `ai.existingSecret` with key `ai-api-key`), `ai.redact`, `ai.allowHttp`, `ai.timeoutSeconds`. With `deploy-remote.sh`, set the `DUVORA_AI_*` variables before running it.

### What is sent

- **Explain:** the incident, the device summary, eBPF evidence, up to 60 samples, nearby jobs, related incidents, anomalies and the rule-based hypotheses. The narrative is cached on the incident until its detail, state or hypotheses change.
- **Briefing summary** (`GET /api/v1/report?ai=1`, console Report → AI summary): the scorecard, fleet counts, active incidents, recent operations, kernel observations, insights and suggestions.
- **Copilot:** the conversation (at most 20 messages of 4,096 characters) and the results of the tools the model calls. No passwords, keys, tokens or session data are ever included.

Telemetry is untrusted: host names, drop reasons, incident details and flow peers come from agents. Duvora wraps every piece of data in `<data>` blocks and the system prompt tells the model to treat it as data, never as instructions. Because the model cannot change anything, a prompt-injection attempt can at most produce a misleading answer, never an action. The plan it drafts still shows its blockers and requires a person to type the confirmation.

### Copilot

`POST /api/v1/copilot` with `{"messages":[{"role":"user","content":"..."}]}` (viewer role or above). The model may call up to 6 rounds of tools:

| Tool | Returns |
|---|---|
| `fleet_summary` | Devices with health, source, provider, mode, metrics; open incidents; kill switch |
| `list_incidents` | Incidents by state |
| `device_details` | One device including its eBPF probe, drop reasons, talkers and isolation |
| `metric_history` | Up to 60 history points, optionally one metric |
| `forecast` | The device forecast |
| `anomalies` | Fleet insights |
| `explain_incident` | Evidence and hypotheses (no nested model call) |
| `suggest_allowlist` | Ranked allow-list candidates |
| `steering_state` | Rule sets and per-device steering stage, bypass and rule hits, or one device's steering |
| `list_verdicts` | Recent steering verdicts, optionally by device and action |
| `explain_verdict` | Which rule matches a flow on a device, with the trace of rules before it |
| `suggest_steering` | Steering rule candidates from observed traffic |
| `ai_traffic` | LLM endpoints, providers, finding counts and inspection coverage |
| `ai_assets` | Discovered AI services and endpoints, sanctioned or not |
| `scan_results` | Recent artifact scans |
| `intel_matches` | Threat-intel feeds and matching flows |
| `posture` | The AI security posture checks |
| `draft_plan` | Admins only: a plan preview (isolate, release, steer, unsteer and so on) with id, blockers and confirmation |

The response is `{"reply","tools":[{"name","ok"}],"plans":[...],"model"}`. Each principal may ask 20 questions per minute. Every question is audited as `copilot.asked` (length and tool names only, not the text), and drafted plans as `copilot.plan-drafted` plus the usual `plan.created`.

In the console, **Ask copilot** (bottom right) opens the drawer, and **Review plan** opens the normal plan dialog with the drafted values for a fresh preview. From the CLI: `duvoractl ask "why is node-1 dropping packets?"`; a drafted plan prints the `duvoractl apply` command to run after review.

## AI security

These features protect AI workloads. They build on traffic steering ([STEERING.md](STEERING.md)) and run on nodes with the Duvora agent. Simulated devices produce modeled data. None of them needs a language model.

### AI traffic protection

Flows that a steering rule marks `inspect` have their first payload bytes (up to 256) captured in the kernel. The agent analyzes each capture on the node and reports only the result:

- **Endpoint:** the server name, from TLS SNI or the HTTP `Host` header, and the request path.
- **Classification:** the LLM provider, from known API hosts (OpenAI, Azure OpenAI, Anthropic, Google, AWS Bedrock, Mistral, Cohere, Groq, DeepSeek, OpenRouter, Hugging Face and others) and from paths of OpenAI-compatible, Ollama, Triton and TGI servers, plus MCP.
- **Findings:**
  - Prompt injection: instruction override, system-prompt extraction, jailbreak phrases, chat-template markers, exfiltration requests.
  - Secrets: AWS, OpenAI, Anthropic, Google and Hugging Face keys, GitHub and Slack tokens, private keys, JWTs. Critical.
  - Sensitive data: email addresses, payment card numbers, US SSNs, Indian PANs.

Snippets in findings are masked: secrets and personal data are replaced before they leave the node.

| Alert rule | Fires on |
|---|---|
| `llm-prompt-injection` | Prompt injection in the last 15 minutes |
| `llm-secret-leak` | A secret sent to an LLM endpoint (critical) |
| `llm-sensitive-data` | Personal data sent to an LLM endpoint |
| `llm-new-endpoint` | An LLM endpoint not seen before on the device |

The AI traffic page (`GET /api/v1/ai-traffic`) shows endpoints, findings and coverage. Coverage is the share of LLM-bound bytes that steering inspects. `duvoractl steer-suggest DEVICE` proposes inspect rules that raise it.

### AI asset discovery

Every 5 minutes the agent reads `/proc` for listening sockets and the processes that own them. It recognizes:

- inference runtimes: Ollama, vLLM, Triton, TGI, llama.cpp, LM Studio, SGLang, Ray Serve, TensorRT-LLM, NIM;
- gateways: LiteLLM;
- vector databases: Qdrant, Milvus, Chroma, Weaviate;
- MCP servers;
- applications: Open WebUI.

Inside the Helm DaemonSet (`hostNetwork`, no `hostPID`), services are identified by port. Process names need host PID access.

LLM endpoints seen by inspection also count as assets. Once a sanctioned list exists (`duvoractl assets sanction --kind ollama --device 'gpu-*'`; glob patterns are allowed), the `unsanctioned-ai` alert reports anything not on it.

### Artifact scanning

- **What it scans:**
  - Container images, pinned by digest. Layers are pulled from the registry over HTTPS (`DUVORA_REGISTRY_TOKEN` for private registries).
  - Model files, from an HTTPS URL.
- **What it reports:**
  - Pickle code execution: dangerous globals such as `os.system`, `subprocess` and `eval`, including inside PyTorch zip archives.
  - Keras Lambda layers.
  - Embedded secrets.
  - Formats that run code on load: pickle, joblib, and similar.
- **Effect on deploys:** a failed latest scan blocks deploy plans for that image. `DUVORA_REQUIRE_SCAN=1` also blocks images that were never scanned.
- **Limits:** `DUVORA_SCAN_MAX_MB` caps each scan (default 512 MB).
- **Offline:** `duvoractl scan --file model.pt` scans a local file without contacting the server.
- **Alert rule:** `scan-failed`.

### Threat intel

Feeds are plain lists, CSV, or STIX 2 indicator bundles. They are fetched over HTTPS on a schedule, or stored inline. Indicators are matched against observed flows, and the `intel-match` alert is critical.

`duvoractl intel ruleset --id threat-intel [--base ai-gateway]` builds a steering rule set that drops every indicator. The `--base` option appends an existing rule set's rules after the drops. Apply the result like any other rule set: preview, shadow, then enforce.

### Playbooks

Playbooks run when an incident opens and only ever draft:

- `explain`: attaches a rule-based explanation.
- `draft_block`: a shadow steering plan that drops the incident's peer ahead of the device's current rules.
- `draft_bypass`: a bypass preview.
- `notify`: posts to `DUVORA_NOTIFY_URL`.

Built-in playbooks are `llm-threat`, `intel-match`, and `steering-drops` (disabled by default). Every run is recorded (`GET /api/v1/playbook-runs`). A drafted plan carries a `playbook:<id>` actor and still needs an admin to type its confirmation.

### Posture

`GET /api/v1/ai/posture`, the Report page and the shift briefing score six checks out of 100:

| Check | Weight |
|---|---|
| Inspection coverage | 25 |
| LLM findings in 24 h | 25 |
| Shadow AI | 15 |
| Artifact scans in 7 days | 15 |
| Threat intel | 10 |
| Agent identity | 10 |

Each check that does not pass names the next step. The scorecard shows the posture score next to the fleet score, but posture does not change the fleet score.

## Limits

- Statistics are per device and per metric. They do not model seasonality (for example a daily backup peak), so a regular burst can fire an anomaly until the baseline absorbs it. Raise the z threshold or disable the rule if that is noisy.
- Forecasts are linear over 24 hours and only as good as the trend. They are a prompt to look, not a capacity plan.
- Suggestions only see the flows recorded in the last hour (`NATIVE_FLOWS`, `FLOW_WINDOW`), and a policy is a single CIDR plus ports, so destinations outside the chosen network stay blocked.
- Model output can be wrong. The console labels model-written text, and the evidence and hypotheses it was given are shown next to it.

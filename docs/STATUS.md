# Capability matrix — 0.5.0

| Capability | Implementation | Validation |
|---|---|---|
| HTTP API, SQLite persistence | Working | Unit/HTTP tested |
| Username/password sign-in, session cookie, rate limit | Working (scrypt hashes, server-side sessions) | Unit/HTTP/browser tested |
| Named users (admin/viewer), personal API tokens | Working | Unit/HTTP/browser tested |
| React console (Netra design language) | Working | Typecheck, Vitest, Playwright workflow |
| CLI (`duvoractl login`, fleet, incidents, users, backup) | Working | HTTP integration tested; TLS smoke tested |
| Telemetry history (1h/24h/7d) | Working; simulator samples are a random walk | Unit tested |
| Alert rules and incidents | Working; twenty-five built-in rules, auto-resolve | Unit/browser tested |
| Anomaly detection, new egress destinations, threshold forecasts | Working; local EWMA baselines and linear fits, no external calls | Unit tested; live on native-agent telemetry (forecasts need temperature or link speed, which eBPF-only nodes do not report) |
| Allow-list suggestions, incident evidence and hypotheses | Working; local, scored with the plan's flow replay | Unit/browser tested; live on native-agent flows and incidents |
| LLM explanations, briefing summary, ops copilot | Working with any OpenAI-compatible API; optional, read-only plus admin plan drafts, never applies | Fake-model tests (tool loop, roles, redaction, fallback); no model bundled |
| Scorecard, shift briefing, topology | Working | Unit/browser tested |
| Housekeeping (plans, audit, samples, incidents, sessions) and online backup | Working | Unit tested |
| Simulator inventory | Working, explicitly labeled | Tested |
| Simulation service lifecycle | Records desired image and modeled running state | Tested; no containers launched |
| Simulation isolation | Device allow-list model | IPv4/IPv6 and release tested; no packets filtered |
| Simulation upgrade | Drain/update/verify state machine | Tested; no firmware changed |
| Simulation rollback | Snapshot restore with revision guard | Tested; refuses later changes |
| Linux PCI discovery | Read-only sysfs parser | Fixture tested; physical card untested |
| DPF inventory import | Read-only kubectl bridge | Conversion fixture tested; cluster untested |
| Helm chart, k3s and container deploy scripts | Working | `helm lint`/template and script dry-runs; remote host run pending |
| Hardware OS provisioning | Not implemented | Requires BlueField/DPF lab |
| DPU service execution | Not implemented | Requires actual runtime adapter |
| Native eBPF agent (`duvora-agent --ebpf`: libbpf via ctypes, TCX counters and flows, drop reasons, TCP events) | Working; read-only sensors | Unit tests; kernel load tests (`make bpf-test`); live on Linux 7.0 beside Cilium |
| eBPF telemetry via Netra (rates, drop reasons, TCP retransmits/resets, top talkers, capability probe) | Working, optional; read-only | Fake-Netra unit tests; live Netra on Linux 7.0 |
| Shadow isolation (flow replay at preview, kernel would-block counters) | Working via the native `duvora_nodeiso` or Netra node isolation | Unit, browser and live tested; never drops |
| Enforced node isolation (allow-only egress, leased, kill switch, agent fail-safe, local override) | Working via `duvora_nodeiso` (TCX egress) or Netra `netra_nodeiso`; node-scoped, not per-tenant | BPF_PROG_TEST_RUN verdicts and veth/netns traffic tests; live tested with SSH and controller kept reachable |
| Traffic steering (ordered 5-tuple rules: bypass, allow, inspect, drop; shadow then leased enforce; rollback) | Working via the native `duvora_steer` (TCX ingress and egress) or the simulation model; node-scoped, not DPU offload | Unit tests; BPF_PROG_TEST_RUN verdicts (`tests/test_steer_kernel.py`); live in shadow on Linux 7.0 (verdicts, inspection, bypass, enforce gate) |
| Steering bypass (manual with typed confirmation, automatic during upgrades) | Working | Unit tested; live engage and resume |
| LLM traffic inspection (SNI/Host, provider, prompt injection, secrets, sensitive data) | Working on payload samples of `inspect` flows (first 256 bytes); masked before reporting | Unit tested; live prompt-injection detection through `duvora_steer` |
| AI asset discovery, sanctioned list | Working from `/proc` on agent nodes (port-based inside the Helm pod) | Unit tested |
| Image and model artifact scanning, deploy blockers | Working (registry pull over HTTPS, pickle and Keras checks, secrets) | Unit tested with crafted artifacts; no registry in CI |
| Threat-intel feeds, matches, intel rule sets | Working (plain, CSV, STIX 2 patterns) | Unit tested |
| Draft-only playbooks | Working; drafts plans and notifications, never applies | Unit tested; live demo pipeline |
| SIEM export (webhook, syslog) | Working; bounded queue | Unit tested against a local receiver |
| Agent identity (rotating tokens, optional mTLS) | Working | Unit tested; live token rotation |
| AI posture score | Working; local | Unit tested |
| Resource budgets for deploys | Working against reported capacity or published model specifications | Unit tested |
| DPU hardware firewall/tenant isolation | Not implemented | Requires policy backend and traffic tests |
| Firmware/BFB flashing | Not implemented | Requires compatibility/recovery qualification |
| Vendor hardware counter collectors | Not implemented | Real metrics accepted only if provided by a qualified source |
| NVMe-oF/DOCA SNAP/RDMA offload | Not implemented | Requires hardware/backend qualification |
| SSO/OIDC, tenant RBAC, HA | Not implemented | Follow-up enterprise work |

This project is a complete runnable evaluation repository, not a complete production DPU orchestration implementation. Provisioning, acceleration, and DPU hardware enforcement must not be advertised as delivered by 0.5.0. Node isolation, native or through Netra, and traffic steering are host-kernel enforcement on the node, not DPU offload.

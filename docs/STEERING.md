# Traffic steering

Steering applies an ordered rule set to a device's traffic. Each rule matches a 5-tuple and a direction and has one of four actions:

| Action | Effect |
|---|---|
| `bypass` | Pass untouched and uncounted beyond the rule counter (bulk east-west traffic such as RDMA or NVMe/TCP) |
| `allow` | Pass and record a flow sample |
| `inspect` | Pass, record a flow sample, and copy the start of the flow's payload for the AI traffic analyzer ([AI.md](AI.md)) |
| `drop` | Drop in enforce; count as "would drop" in shadow |

The first matching rule wins, in priority order. Traffic that matches no rule takes the rule set's `default` (`bypass` or `drop`).

The model comes from DPU firewalls that steer selected flows to an inspection engine, for example Prisma AIRS on BlueField-3. **Duvora does not offload anything to a DPU.** It runs rule sets in two places:

- **Simulation** (simulator devices). Rules are evaluated against a modeled flow catalog. Nothing is filtered.
- **Native** (devices fed by `duvora-agent --ebpf`). The agent's `duvora_steer` program runs at the head of the TCX ingress and egress chains of the node's uplinks. This is host-kernel steering, scoped to the node.

Netra-backed devices have no steering because Netra has no steering API.

## Rule sets

```json
{"description": "AI gateway", "default": "bypass", "rules": [
  {"priority": 10, "name": "bypass-rdma", "action": "bypass", "protocol": "udp", "dport": 4791},
  {"priority": 20, "name": "drop-tor-exits", "action": "drop", "dst": "185.220.101.0/24"},
  {"priority": 30, "name": "inspect-llm", "action": "inspect", "direction": "egress", "protocol": "tcp", "dport": 443}]}
```

- **Fields:** `priority` (1–65535, unique), `name` (unique), `src`, `dst` (`any`, or an IPv4/IPv6 address or network), `protocol` (`any`, `tcp`, `udp`, `icmp`, `icmpv6`), `sport` and `dport` (`any`, a port, or a range such as `8000-8100`; TCP and UDP only), `direction` (`egress`, `ingress`, `both`), `action`, and an optional `note`.
- **Size:** at most 1,000 rules.
- **Identity:** each rule set has a `digest`, so a shadow run and an enforce promotion are guaranteed to use the same rules.

Manage rule sets with `PUT /api/v1/steering/sets/{id}`, `duvoractl steering --set ID --put FILE`, or the Steering page. A rule set that is applied to a device cannot be deleted.

The demo seeds `ai-gateway`, applied in shadow to `bf3-01` and `bf3-02`.

## Stages and gates

Changes go through the normal plan flow: preview, then a typed confirmation, then a job, with rollback available.

| Plan | Confirmation | Gates |
|---|---|---|
| `steer` in `shadow` (default) | `APPLY STEERING SHADOW` (native), `APPLY SIMULATION` (simulated) | Native: the agent reports `duvora_steer` attached and has reported recently. Simulated and native devices cannot be mixed in one plan |
| `steer` in `enforce` | `ENFORCE STEERING ON <device>` | The same rule set (by digest) is already in shadow on the device; one device; not in bypass; native needs `DUVORA_EBPF_ENFORCE=1` and the kill switch released |
| `unsteer` | `APPLY STEERING RELEASE` (native), `APPLY SIMULATION` | The device has steering |

```bash
duvoractl steer ai-gateway ebpf-node-1                                  # prints the preview
duvoractl steer ai-gateway ebpf-node-1 --confirm 'APPLY STEERING SHADOW'
duvoractl verdicts --device ebpf-node-1 --action drop
duvoractl flow ebpf-node-1 --dst 185.220.101.9 --dport 9001             # which rule matches, and why
```

The preview replays recent flow records against the rule set and shows what would be allowed, inspected and dropped. Native devices replay observed flows; simulated devices replay the modeled catalog.

Enforce on a native node is leased, like isolation (`DUVORA_NETRA_LEASE`, default 900 s). The lease renews while Duvora runs. The agent falls back to shadow when any of these happens:

- the lease lapses;
- the agent loses the control plane for `DUVORA_EBPF_FAILSAFE` seconds;
- the kill switch is engaged.

`/run/duvora/steering-off` on the host turns steering off locally.

Rolling back a steer job restores the previous rule set in shadow; it never re-enforces.

## Bypass

Bypass keeps the rule set loaded but passes all traffic, the way a DPU firewall fails open:

- **Automatic:** an upgrade engages bypass at its drain step and releases it when the upgrade succeeds.
- **Manual:** `POST /api/v1/devices/{id}/steering/bypass` with `{"engaged": true, "confirmation": "BYPASS <device>"}`, or `RESUME <device>` to release it. From the CLI: `duvoractl bypass DEVICE on --confirm 'BYPASS DEVICE'`.

Every change is audited, and the `steering-bypass` alert fires when bypass lasts longer than its threshold (default 10 minutes).

## What is always exempt

SSH (port 22), and the control plane's address on the agent's control-plane port, in either direction. The control plane's addresses come from the agent's URL plus `DUVORA_CONTROLLER_ADDRESSES`. The exemption is per port, so a control plane on the same host as the agent does not exempt the host's other traffic.

## Kernel program

`bpf/duvora_steer.c` (Apache-2.0) uses these maps:

- `steer_cfg`: generation, mode, rule count and flags.
- `steer_rules`: two halves of 1,000 rules. The agent writes the inactive half, then publishes the next generation, so an update is atomic.
- `steer_counters`: per-rule and default counters, per CPU.
- `steer_stats`: totals.
- `steer_exempt`: control-plane endpoints.
- `steer_flows`: LRU flow samples, drained on every report.
- `steer_payloads`: one capture of up to 256 bytes per inspected flow.

Matching is a bounded loop over a global function, so the verifier checks the rule match once, not once per rule.

The agent reports counters, rule hits, flow verdicts and payload analyses on every interval. The raw payload never leaves the node: the agent sends only the analyzer's result, with secrets and personal data masked.

Kernel tests: `make bpf-test` (`tests/test_steer_kernel.py`, through BPF_PROG_TEST_RUN).

## Alerts and data

- **Alert rules:**
  - `steering-bypass` (minutes in bypass)
  - `steering-drop` (enforced drops)
  - `steering-would-drop` (shadow)
- **Verdict retention:** verdicts are kept for 7 days, up to 100,000 rows.
- **API:** `GET /api/v1/verdicts?device=&action=&rule=&limit=`.
- **SIEM:** verdicts are exported with `DUVORA_SIEM_VERDICTS` (`drop` by default, or `all` or `none`).
- **Metrics:** `duvora_steering_devices{stage}`, `duvora_steering_bypass`.

## Limits

- Steering is node-scoped. It sees what crosses the node's uplinks, not pod-to-pod traffic on the same node.
- Inspection reads the first payload bytes of a flow. TLS traffic yields the server name (SNI) only, and a request body beyond the first 256 bytes is not seen.
- One rule set per device. Rules are not merged across rule sets.

# eBPF in Duvora

Duvora gets kernel observations and node isolation from one of two providers:

- **Native** (default). `duvora-agent --ebpf auto` runs on each host and loads Duvora's own eBPF programs (`bpf/duvora_*.c`, compiled to `duvora/bpf/obj/*.o`) through the system libbpf, from Python via ctypes. There is no sidecar and no second language on the node. The agent posts counters to the control plane and pulls the desired isolation for its host.
- **Netra** (optional). Duvora polls a [Netra](https://github.com/zyvorai/zyvor-netra) controller over its HTTP API (`DUVORA_NETRA_URL`, `DUVORA_NETRA_API_KEY`), and Netra's own agent does the kernel work.

`DUVORA_EBPF_SOURCE` chooses: `native`, `netra`, or `auto` (the default). In `auto`, a host whose native agent has reported in the last 90 seconds uses the native data; Netra fills in hosts without an agent. `GET /api/v1/ebpf`, the console and `duvoractl ebpf` show the provider for each device.

## What you get

| Feature | Native program | Netra source | Where in Duvora |
|---|---|---|---|
| Throughput, packets/s, drops | `duvora_iface` (TCX ingress and egress counters) plus the uplinks' `rx_dropped`/`tx_dropped` | `/ebpf/interfaces`, `/ebpf/drops` | Device metrics (`metrics_source` `duvora-ebpf` or `netra-ebpf`), Telemetry history |
| Drop reasons (`NO_SOCKET`, `QUEUE_PURGE`, ...) | `duvora_drops` (`tp_btf/kfree_skb`) | `/ebpf/drop-info` | Telemetry → Kernel observations, `packet-drops` incident detail |
| TCP retransmits and resets per minute | `duvora_tcp` (`tcp_retransmit_skb`, `tcp_send_reset`, `tcp_receive_reset`) | `/ebpf/tcp-events` | Metrics, `tcp-retransmits` / `tcp-resets` rules |
| Top talkers (last 15 minutes) | `duvora_iface` egress flow table | `/flows/history` | Telemetry, device inspect, shift briefing |
| Capability probe (kernel, BTF, attached programs) | agent report | `/fleet`, `/node-resources`, `/ebpf/coverage` | Govern → Capabilities |
| Shadow and enforced isolation | `duvora_nodeiso` (TCX egress) | `/ebpf/node-isolation` | Operate → Isolation, `isolation-would-block` / `isolation-blocked` rules |

Rates are computed from counter deltas between two reports. A counter that goes backwards (agent restart) skips that interval rather than reporting a spike. Drop-reason names come from the `kfree_skb` tracepoint format in tracefs; without tracefs the raw reason numbers are shown.

## Native agent

```bash
sudo DUVORA_TOKEN=<agent key for agent:<host>> duvora-agent --ebpf auto --url https://duvora.example:8787
```

- `--ebpf auto` loads what it can and reports what failed; `required` exits instead; `off` (the default) keeps the agent PCI-only.
- `--interfaces eth0,eth1` picks the interfaces; by default the agent uses those carrying a default route (`/proc/net/route`, `/proc/net/ipv6_route`).
- `--no-isolation` (or `DUVORA_EBPF_ISOLATION=off`) loads the sensors only.
- The agent reports every `--interval` seconds (15 by default with `--ebpf`).

Each report goes to `POST /api/v1/agent/ebpf`. It merges into a device on the same host: one already fed by the native agent, else a Netra-discovered device for that host, else any non-simulated device on that host, else a new `ebpf-<host>` device (source `duvora-ebpf`). The agent key is bound to its host (`agent:<host>`), so an agent cannot report for, or read the isolation of, another host.

The TCX programs attach at the head of each interface's chain, ahead of a CNI program such as Cilium's, and the observe-only ones always pass the packet on.

Host requirements: Linux 6.6 or later (TCX), BTF (`/sys/kernel/btf/vmlinux`), libbpf 1.3 or later (`libbpf1` on Debian and Ubuntu), and root or `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_PERFMON`. tracefs is optional (drop-reason names). The Helm chart's agent DaemonSet and `Dockerfile.agent` provide all of this.

## Mapping devices to Netra nodes

A device is matched to a Netra node, in order, by:

1. `DUVORA_NETRA_NODE_MAP`, a JSON object of device id or host to node name;
2. the node the device was matched to before;
3. the device host equal to the node name, its slug, or the node's host name.

With `DUVORA_NETRA_DISCOVER=1`, every node that matches nothing becomes a `netra-<node>` device (source `netra-ebpf`). Simulated devices are never matched. Unmatched nodes are listed in `GET /api/v1/ebpf`.

## Isolation stages

Node isolation is an allow-only egress filter at the head of the TCX egress chain on the node's uplinks (`duvora_nodeiso` natively, `netra_nodeiso` through Netra). It is node-scoped: it filters the whole host, not one tenant.

1. **Preview.** An isolate plan replays the last 15 minutes of flow records for each device against the allow-list and shows how many flows, and which destinations, would be blocked. Nothing changes.
2. **Shadow.** Applying the plan (confirmation `APPLY SHADOW`) sets the allow-list on the node in shadow mode. The kernel counts would-block packets and their top destinations; nothing is dropped. New would-block packets open an `isolation-would-block` incident.
3. **Enforce.** Promote one device whose same allow-list is already in shadow. The plan needs enforcement enabled on the server (`DUVORA_EBPF_ENFORCE=1`, or `DUVORA_NETRA_ENFORCE=1`), the kill switch released, and the typed confirmation `ENFORCE ON <device>`. The kernel then drops new outbound flows outside the allow-list; drops open an `isolation-blocked` incident.
4. **Release.** A release plan (`APPLY RELEASE`) removes the node isolation.

Always allowed, in every mode: established TCP (only SYNs are judged), ICMP and ICMPv6, DHCP and DHCPv6, non-first fragments, traffic from local port 22, and TCP to the control plane. The native agent adds the addresses of its `--url` host and any in `DUVORA_CONTROLLER_ADDRESSES` (set on the server) as allow rules. SSH and the control path stay reachable.

With the native provider, the desired state lives in the `node_isolation` table (host, body, revision, lease). The agent swaps in each new rule set as a new generation: rules are written under the new generation number first and the config entry is switched last, so a packet sees either the whole old set or the whole new one. The agent reports the revision it applied and the mode in effect.

On multi-node clusters with an overlay network, pod traffic to other nodes leaves the uplink as encapsulated UDP; include the node network in the allow-list.

## Failing safe

- **Lease.** Enforce is set with a lease (`DUVORA_NETRA_LEASE`, default 900 s, 60–3600). Duvora renews it when less than a third (at most 5 minutes) remains. If Duvora stops, the node falls back to shadow when the lease ends: the native agent checks the lease itself; Netra's controller does the same for Netra nodes.
- **Control-plane fail-safe.** The native agent falls back to shadow when it has not reached the control plane for `DUVORA_EBPF_FAILSAFE` seconds (default 60). Netra's agent does the same with its controller.
- **Local override.** If the file `DUVORA_EBPF_OVERRIDE` (default `/run/duvora/isolation-off`) exists on the host, the native agent turns isolation off at its next interval, whatever the control plane says. Remove the file to resume.
- **Fail open.** If the agent exits, its links are destroyed and the filter is gone. Any parse failure, missing map entry or zero generation passes the packet.
- **Kill switch.** `POST /api/v1/ebpf/kill-switch {"engaged":true}`, the Kill switch button, or `duvoractl kill-switch on` demotes every enforced node to shadow immediately and refuses enforce plans until released. Its state survives restarts.
- **Rollback.** Rolling back an isolation job restores the previous allow-list in shadow, or removes the isolation if there was none. It never re-enforces.
- **Drift (Netra).** If Netra demotes a node, deletes its isolation, or another client replaces it, Duvora updates the device and records an `isolation.demoted` or `isolation.drift` audit event.

## Netra requirements

- Netra with node isolation: `/api/v1/ebpf/node-isolation` and `netra_nodeiso` attached on the node. Older Netra builds give telemetry only; isolation plans are blocked with a reason.
- A Netra **admin** API key for shadow and enforce. A viewer key gives telemetry only.
- HTTPS to Netra unless it is on loopback. Pin a self-signed certificate with `DUVORA_NETRA_CA_FILE`.
- Do not run Netra's node isolation and Duvora's on the same interface; both filters would apply.

## Building the objects

```bash
make bpf        # clang -O2 -g -target bpf; needs clang and Linux UAPI headers
make bpf-test   # loads every object and runs kernel tests (Linux, sudo)
```

The compiled objects ship as package data in `duvora/bpf/obj/`, so hosts need libbpf but not clang.

## CLI

```bash
duvoractl ebpf                       # provider, connection, kill switch, per-device probe
duvoractl ebpf ebpf-node-1           # one device's kernel observations
duvoractl shadow ebpf-node-1 --cidr 10.0.0.0/8 --ports 443 --yes
duvoractl enforce ebpf-node-1                                  # prints the plan
duvoractl enforce ebpf-node-1 --confirm "ENFORCE ON ebpf-node-1"
duvoractl kill-switch on
```

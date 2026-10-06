"""Traffic steering: ordered 5-tuple rules that bypass, allow, inspect or drop traffic per device.

Modeled on DPU firewalls that steer selected flows to inspection (Prisma AIRS on BlueField-3 uses
DOCA/OVS steering rules). Duvora runs the same rule sets in two places:

  simulation  simulator devices: rules are evaluated against a modeled flow catalog; nothing is filtered.
  native      the Duvora agent's duvora_steer TCX program on the host, in shadow or leased enforce.

Neither is DPU offload. Traffic that matches no rule takes the rule set's default action."""
import hashlib
import ipaddress
import json
import random
import re
import time

from .common import Problem, canonical, name

SCHEMA = """
CREATE TABLE IF NOT EXISTS steering_sets(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS steering_applied(device TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS node_steering(host TEXT PRIMARY KEY, body TEXT NOT NULL, revision INTEGER NOT NULL, lease_until REAL);
CREATE TABLE IF NOT EXISTS verdicts(id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, ts REAL NOT NULL,
  action TEXT NOT NULL, rule TEXT, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS verdicts_device_ts ON verdicts(device, ts);
CREATE INDEX IF NOT EXISTS verdicts_ts ON verdicts(ts);
"""
ACTIONS = ("bypass", "allow", "inspect", "drop")
DEFAULTS = ("bypass", "drop")
DIRECTIONS = ("egress", "ingress", "both")
PROTOCOLS = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58}
PROTOCOL_NAMES = {v: k for k, v in PROTOCOLS.items() if v}
MAX_RULES = 1000
RULE_FIELDS = {"priority", "name", "src", "dst", "protocol", "sport", "dport", "direction", "action", "note"}
VERDICT_RETENTION = 7 * 86400
PLAYBOOK_SET_RETENTION = 86400
VERDICT_CAP = 100000
VERDICT_BATCH = 500
SIM_INTERVAL = 15
SIM_SAMPLE = 60
STEER_NOTE = "Host-kernel steering (duvora_steer) or simulation; not DPU offload."
# Ports that usually carry bulk east-west traffic a DPU firewall should not inspect.
BULK_PORTS = {("udp", 4791): "RoCEv2 (RDMA over Ethernet)", ("tcp", 4420): "NVMe over TCP", ("tcp", 3260): "iSCSI",
              ("tcp", 2049): "NFS", ("tcp", 9000): "object storage"}
# Default ports of self-hosted inference servers.
INFERENCE_PORTS = {11434: "Ollama", 8000: "vLLM / OpenAI-compatible", 8001: "Triton gRPC", 8080: "TGI / llama.cpp",
                   1234: "LM Studio", 30000: "SGLang"}


def _cidr(value, field):
    if value in (None, "", "any", "*"):
        return "any"
    try:
        return str(ipaddress.ip_network(str(value), strict=False))
    except ValueError:
        raise Problem(f"{field} must be any or an IPv4/IPv6 address or network") from None


def _ports(value, protocol, field):
    if value in (None, "", "any", "*", 0):
        return "any"
    if isinstance(value, bool):
        raise Problem(f"{field} must be any, a port, or a range such as 8000-8100")
    if isinstance(value, int):
        lo = hi = value
    elif isinstance(value, str) and re.fullmatch(r"\d{1,5}(-\d{1,5})?", value):
        lo, _, hi = value.partition("-")
        lo, hi = int(lo), int(hi or lo)
    else:
        raise Problem(f"{field} must be any, a port, or a range such as 8000-8100")
    if not 1 <= lo <= hi <= 65535:
        raise Problem(f"{field} must be within 1–65535 with the low port first")
    if protocol not in {"any", "tcp", "udp"}:
        raise Problem("Ports apply to TCP and UDP only")
    return str(lo) if lo == hi else f"{lo}-{hi}"


def port_range(text):
    """'any' -> (0, 0); '443' -> (443, 443); '8000-8100' -> (8000, 8100)."""
    if text == "any":
        return 0, 0
    lo, _, hi = text.partition("-")
    return int(lo), int(hi or lo)


def normalize_rule(r):
    if not isinstance(r, dict) or set(r) - RULE_FIELDS:
        raise Problem(f"Each rule may contain {', '.join(sorted(RULE_FIELDS))}")
    priority = r.get("priority")
    if type(priority) is not int or not 1 <= priority <= 65535:
        raise Problem("Rule priority must be an integer from 1 to 65535")
    action = r.get("action")
    if action not in ACTIONS:
        raise Problem("Rule action must be bypass, allow, inspect or drop")
    direction = r.get("direction", "both")
    if direction not in DIRECTIONS:
        raise Problem("Rule direction must be egress, ingress or both")
    protocol = str(r.get("protocol", "any")).lower()
    if protocol not in PROTOCOLS:
        raise Problem("Rule protocol must be any, tcp, udp, icmp or icmpv6")
    src, dst = _cidr(r.get("src"), "src"), _cidr(r.get("dst"), "dst")
    versions = {ipaddress.ip_network(x).version for x in (src, dst) if x != "any"}
    if len(versions) > 1:
        raise Problem("A rule's src and dst must be the same IP family")
    if protocol == "icmp" and 6 in versions or protocol == "icmpv6" and 4 in versions:
        raise Problem("icmp matches IPv4 and icmpv6 matches IPv6")
    note = r.get("note", "")
    if not isinstance(note, str) or len(note) > 200:
        raise Problem("Rule note must be at most 200 characters")
    out = {"priority": priority, "name": name(r.get("name") or f"rule-{priority}", "rule name"), "direction": direction,
           "src": src, "dst": dst, "protocol": protocol, "sport": _ports(r.get("sport"), protocol, "sport"),
           "dport": _ports(r.get("dport"), protocol, "dport"), "action": action}
    if note:
        out["note"] = note
    return out


def ruleset_digest(rules, default):
    return hashlib.sha256(canonical([default, rules]).encode()).hexdigest()[:16]


def validate_ruleset(ident, body):
    name(ident, "rule set id")
    if not isinstance(body, dict) or set(body) - {"description", "default", "rules"}:
        raise Problem("A rule set contains description, default and rules")
    description = body.get("description", "")
    if not isinstance(description, str) or len(description) > 300:
        raise Problem("Description must be at most 300 characters")
    default = body.get("default", "bypass")
    if default not in DEFAULTS:
        raise Problem("Default action must be bypass or drop")
    rules = body.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise Problem(f"A rule set holds at most {MAX_RULES} rules")
    rules = sorted((normalize_rule(r) for r in rules), key=lambda r: r["priority"])
    if len({r["priority"] for r in rules}) != len(rules):
        raise Problem("Rule priorities must be unique")
    if len({r["name"] for r in rules}) != len(rules):
        raise Problem("Rule names must be unique")
    return {"id": ident, "description": description, "default": default, "rules": rules, "digest": ruleset_digest(rules, default)}


def _ip(value):
    if value is None or value == "":
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        raise Problem(f"Invalid IP address {str(value)[:64]}") from None


def make_flow(direction, src=None, dst=None, protocol="any", sport=None, dport=None):
    if direction not in ("egress", "ingress"):
        raise Problem("Flow direction must be egress or ingress")
    proto = PROTOCOLS.get(str(protocol).lower()) if not isinstance(protocol, int) else protocol
    if proto is None:
        raise Problem("Flow protocol must be tcp, udp, icmp or icmpv6")
    for port in (sport, dport):
        if port is not None and (type(port) is not int or not 0 <= port <= 65535):
            raise Problem("Flow ports must be integers from 0 to 65535")
    return {"direction": direction, "src": _ip(src), "dst": _ip(dst), "proto": proto, "sport": sport, "dport": dport}


def compile_rules(rules):
    return [(r, None if r["src"] == "any" else ipaddress.ip_network(r["src"]), None if r["dst"] == "any" else ipaddress.ip_network(r["dst"]),
             PROTOCOLS[r["protocol"]], port_range(r["sport"]), port_range(r["dport"])) for r in rules]


def mismatch(c, flow):
    """Why compiled rule `c` does not match `flow`, or None when it matches."""
    r, src, dst, proto, sp, dp = c
    if r["direction"] != "both" and r["direction"] != flow["direction"]:
        return f"direction is {flow['direction']}, rule wants {r['direction']}"
    if proto and proto != flow["proto"]:
        return f"protocol is {PROTOCOL_NAMES.get(flow['proto'], flow['proto'])}, rule wants {r['protocol']}"
    for label, net, addr in (("source", src, flow["src"]), ("destination", dst, flow["dst"])):
        if net is not None:
            if addr is None:
                return f"{label} address unknown, rule wants {net}"
            if addr.version != net.version or addr not in net:
                return f"{label} {addr} is outside {net}"
    for label, (lo, hi), port in (("source port", sp, flow["sport"]), ("destination port", dp, flow["dport"])):
        if (lo, hi) != (0, 0):
            if flow["proto"] not in (6, 17) or port is None:
                return f"{label} unknown, rule wants {lo if lo == hi else f'{lo}-{hi}'}"
            if not lo <= port <= hi:
                return f"{label} {port} is outside {lo if lo == hi else f'{lo}-{hi}'}"
    return None


def evaluate(ruleset, flow, compiled=None, trace=False):
    """First match wins; no match takes the default action."""
    compiled = compiled if compiled is not None else compile_rules(ruleset["rules"])
    steps = []
    for c in compiled:
        why = mismatch(c, flow)
        if why is None:
            out = {"action": c[0]["action"], "rule": c[0]["name"], "priority": c[0]["priority"]}
            if trace:
                out["trace"] = steps[:20] + [{"rule": c[0]["name"], "priority": c[0]["priority"], "matched": True}]
            return out
        if trace and len(steps) < 21:
            steps.append({"rule": c[0]["name"], "priority": c[0]["priority"], "matched": False, "why": why})
    out = {"action": ruleset["default"], "rule": None, "priority": None}
    if trace:
        out["trace"] = steps[:20]
    return out


def flow_from_record(r):
    """A flow record (native agent or Netra: peer, port, protocol, direction) as a steering flow."""
    try:
        peer = ipaddress.ip_address(str(r.get("peer") or ""))
    except ValueError:
        return None
    direction = "ingress" if str(r.get("direction") or "egress").lower() in {"ingress", "inbound", "in"} else "egress"
    proto = PROTOCOLS.get(str(r.get("protocol") or "").lower(), 0)
    port = r.get("port") if isinstance(r.get("port"), int) and 0 <= r["port"] <= 65535 else None
    if direction == "egress":
        return {"direction": "egress", "src": None, "dst": peer, "proto": proto, "sport": None, "dport": port}
    return {"direction": "ingress", "src": peer, "dst": None, "proto": proto, "sport": None, "dport": port}


def replay_steering(flows, ruleset):
    """Evaluate observed flow records against a rule set: totals per action, hits per rule, top flows per action."""
    compiled = compile_rules(ruleset["rules"])
    out = {"flows": 0, "unresolved": 0, "actions": {a: {"flows": 0, "packets": 0, "bytes": 0} for a in ACTIONS}, "rules": {}, "top": {}}
    top = {}
    for r in flows:
        flow = flow_from_record(r)
        if flow is None:
            out["unresolved"] += 1
            continue
        out["flows"] += 1
        v = evaluate(ruleset, flow, compiled)
        packets = r.get("packets") if isinstance(r.get("packets"), (int, float)) else 0
        size = r.get("bytes") if isinstance(r.get("bytes"), (int, float)) else 0
        a = out["actions"][v["action"]]
        a["flows"] += 1
        a["packets"] += packets
        a["bytes"] += size
        key = v["rule"] or "(default)"
        hit = out["rules"].setdefault(key, {"flows": 0, "bytes": 0, "action": v["action"]})
        hit["flows"] += 1
        hit["bytes"] += size
        peer = str(flow["dst"] or flow["src"])
        entry = top.setdefault(v["action"], {}).setdefault((peer, flow["dport"]), {"peer": peer, "port": flow["dport"], "bytes": 0, "packets": 0,
                                                                                  "rule": v["rule"], "direction": flow["direction"]})
        entry["bytes"] += size
        entry["packets"] += packets
    out["top"] = {a: sorted(t.values(), key=lambda e: -e["bytes"])[:5] for a, t in top.items()}
    out["note"] = "Flow records carry no local address or source port; rules that test them do not match in replay."
    return out


def suggest_rules(flows, llm_peers=(), intel_peers=()):
    """A starting rule set from observed flows: drop threat-intel matches, inspect LLM traffic, bypass bulk
    storage and RDMA, allow the destinations that carry most bytes; default bypass until shadow looks clean."""
    rules, seen = [], set()

    def add(action, why, **fields):
        key = (action, fields.get("direction"), fields.get("src"), fields.get("dst"), fields.get("protocol"), fields.get("dport"))
        if key in seen or len(rules) >= 200:
            return
        seen.add(key)
        rules.append({"priority": 10 * (len(rules) + 1), "name": f"{action}-{len(rules) + 1}", "action": action, "note": why[:200], **fields})

    records = [(r, flow_from_record(r)) for r in flows]
    records = [(r, f) for r, f in records if f]
    for peer in sorted(set(intel_peers))[:50]:
        add("drop", "threat-intel indicator observed in traffic", direction="both", dst=f"{peer}/{ipaddress.ip_address(peer).max_prefixlen}")
    for peer, port in sorted(set(llm_peers))[:50]:
        ip = ipaddress.ip_address(peer)
        add("inspect", "LLM API endpoint seen by inspection", direction="egress", dst=f"{ip}/{ip.max_prefixlen}", protocol="tcp", dport=port or "any")
    ports = {}
    for r, f in records:
        if f["dport"] is None:
            continue
        proto = PROTOCOL_NAMES.get(f["proto"], "any")
        ports.setdefault((proto, f["dport"], f["direction"]), 0)
        ports[(proto, f["dport"], f["direction"])] += r.get("bytes") or 0
    for (proto, port, direction), _ in sorted(ports.items(), key=lambda x: -x[1]):
        if proto == "tcp" and port in INFERENCE_PORTS:
            add("inspect", f"{INFERENCE_PORTS[port]} default port", direction=direction, protocol="tcp", dport=port)
    for (proto, port, direction), _ in sorted(ports.items(), key=lambda x: -x[1]):
        if (proto, port) in BULK_PORTS:
            add("bypass", f"{BULK_PORTS[(proto, port)]}: bulk traffic, not inspected", direction="both", protocol=proto, dport=port)
    egress = {}
    for r, f in records:
        if f["direction"] == "egress" and f["dst"] is not None:
            egress.setdefault((str(f["dst"]), PROTOCOL_NAMES.get(f["proto"], "any"), f["dport"]), 0)
            egress[(str(f["dst"]), PROTOCOL_NAMES.get(f["proto"], "any"), f["dport"])] += r.get("bytes") or 0
    total = sum(egress.values()) or 1
    covered = 0
    for (peer, proto, port), size in sorted(egress.items(), key=lambda x: -x[1]):
        if covered >= 0.95 * total:
            break
        covered += size
        ip = ipaddress.ip_address(peer)
        fields = {"direction": "egress", "dst": f"{ip}/{ip.max_prefixlen}"}
        if proto in ("tcp", "udp") and port:
            fields.update(protocol=proto, dport=port)
        add("allow", "observed destination", **fields)
    return {"default": "bypass", "rules": rules}


# Simulated flows for demo devices: (direction, local, remote, protocol, port, bytes, packets, payload kind)
SIM_FLOWS = [
    ("egress", "10.10.0.{i}", "10.20.0.5", "tcp", 8000, 180_000, 140, "llm-local"),
    ("egress", "10.10.0.{i}", "104.18.33.45", "tcp", 443, 90_000, 80, "llm-openai"),
    ("egress", "10.10.0.{i}", "10.0.0.2", "udp", 53, 4_000, 40, None),
    ("egress", "10.10.0.{i}", "10.30.1.{i}", "udp", 4791, 9_000_000_000, 7_000_000, None),
    ("egress", "10.10.0.{i}", "10.40.0.7", "tcp", 4420, 2_000_000_000, 1_400_000, None),
    ("egress", "10.10.0.{i}", "185.220.101.4", "tcp", 9001, 12_000, 30, None),
    ("ingress", "10.10.0.{i}", "10.50.0.9", "tcp", 22, 20_000, 200, None),
    ("ingress", "10.10.0.{i}", "10.60.2.15", "tcp", 11434, 60_000, 90, "llm-ollama"),
]


def sim_flows(index, now):
    """The modeled flow catalog for simulator device `index`, with jittered volumes."""
    rng = random.Random(int(now // SIM_INTERVAL) * 31 + index)
    out = []
    for direction, local, remote, proto, port, size, packets, kind in SIM_FLOWS:
        local = local.format(i=index)
        remote = remote.format(i=index)
        k = rng.uniform(0.6, 1.4)
        sport = rng.randint(32768, 60999)
        if direction == "egress":
            flow = {"direction": "egress", "src": local, "dst": remote, "sport": sport, "dport": port}
        else:
            flow = {"direction": "ingress", "src": remote, "dst": local, "sport": sport, "dport": port}
        out.append({**flow, "protocol": proto, "bytes": int(size * k), "packets": int(packets * k), "payload": kind})
    return out


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 2 ** 63 else 0


def _text(value, limit=64):
    return value[:limit] if isinstance(value, str) else ""


STAT_KEYS = ("matched", "allowed", "dropped", "would_drop", "inspected", "bypassed", "exempt", "dropped_bytes", "would_drop_bytes")


class SteeringMixin:
    def init_steering(self):
        self.db.executescript(SCHEMA)
        self.last_steer_sim = 0.0
        self.sim_sampled = {}

    # Rule sets -----------------------------------------------------------------------------------
    def steering_sets(self):
        with self.lock:
            sets = [json.loads(r[0]) for r in self.db.execute("SELECT body FROM steering_sets ORDER BY id")]
            used = {}
            for d in self.rows("devices"):
                if d.get("steering"):
                    used.setdefault(d["steering"]["ruleset"], []).append(d["id"])
        return [{k: s[k] for k in ("id", "description", "default", "digest", "updated", "updated_by")} | {
            "rule_count": len(s["rules"]), "actions": {a: sum(r["action"] == a for r in s["rules"]) for a in ACTIONS},
            "devices": used.get(s["id"], [])} for s in sets]

    def steering_set(self, ident):
        row = self.db.execute("SELECT body FROM steering_sets WHERE id=?", (ident,)).fetchone()
        if not row:
            raise Problem("Rule set not found", 404)
        return json.loads(row[0])

    def put_steering_set(self, actor, ident, body):
        s = validate_ruleset(ident, body)
        s.update(updated=time.time(), updated_by=actor)
        with self.transaction():
            existed = self.db.execute("SELECT 1 FROM steering_sets WHERE id=?", (ident,)).fetchone()
            self.db.execute("INSERT INTO steering_sets VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (ident, canonical(s)))
            self.event(actor, "steering.set-updated" if existed else "steering.set-created",
                       {"id": ident, "rules": len(s["rules"]), "digest": s["digest"], "default": s["default"]})
        return s

    def delete_steering_set(self, actor, ident):
        with self.transaction():
            self.steering_set(ident)
            users = [d["id"] for d in self.rows("devices") if (d.get("steering") or {}).get("ruleset") == ident]
            if users:
                raise Problem(f"Rule set is applied to {', '.join(users)}; remove steering from those devices first", 409)
            self.db.execute("DELETE FROM steering_sets WHERE id=?", (ident,))
            self.event(actor, "steering.set-deleted", {"id": ident})
        return {"deleted": ident}

    def prune_playbook_sets(self, now):
        """Rule sets a playbook drafted that no device uses, a day after their plan expired (caller holds the transaction)."""
        used = {(d.get("steering") or {}).get("ruleset") for d in self.rows("devices")}
        removed = 0
        for ident, body in self.db.execute("SELECT id, body FROM steering_sets").fetchall():
            s = json.loads(body)
            if str(s.get("updated_by", "")).startswith("playbook:") and ident not in used and now - s.get("updated", now) > PLAYBOOK_SET_RETENTION:
                self.db.execute("DELETE FROM steering_sets WHERE id=?", (ident,))
                removed += 1
        return removed

    # Plans ---------------------------------------------------------------------------------------
    def steer_flows(self, d, now=None):
        """Flow records for replay: native/Netra records, or the modeled catalog for a simulator."""
        if d["source"] == "simulator":
            try:
                index = int(d["id"].rsplit("-", 1)[1])
            except (IndexError, ValueError):
                return []
            return [{"peer": f["dst"] if f["direction"] == "egress" else f["src"], "port": f["dport"], "protocol": f["protocol"],
                     "direction": f["direction"], "bytes": f["bytes"], "packets": f["packets"]} for f in sim_flows(index, now or time.time())]
        return list(self.netra_flows.get(d["id"], []))

    def steer_plan(self, spec, devices):
        """(mode, confirmation, effects, blockers, extra plan fields, job mode) for steer and unsteer."""
        action, stage = spec["action"], spec.get("stage", "shadow")
        blockers, extra = [], {}
        sims = [d for d in devices if d["source"] == "simulator"]
        natives = [d for d in devices if d["source"] != "simulator"]
        if sims and natives:
            blockers.append("Do not mix simulated and agent-backed devices in one steering plan")
        if action == "steer":
            try:
                s = self.steering_set(spec["ruleset"])
            except Problem:
                s = None
                blockers.append(f"Rule set {spec['ruleset']} does not exist")
            if s:
                extra["steering"] = {k: s[k] for k in ("id", "default", "rules", "digest")}
                extra["shadow"] = {d["id"]: {**replay_steering(self.steer_flows(d), s), "source": "replayed from observed flows"
                                             if d["source"] != "simulator" else "replayed from the modeled flow catalog"}
                                   for d in devices}
        for d in devices:
            current = d.get("steering")
            if action == "unsteer" and not current:
                blockers.append(f"{d['id']}: no steering to remove")
            if d["source"] == "simulator":
                if not self.demo:
                    blockers.append(f"{d['id']}: simulation is disabled on this server")
                continue
            e = d.get("ebpf") or {}
            if self.provider(d) != "native" or not e:
                blockers.append(f"{d['id']}: steering needs the Duvora agent (duvora-agent --ebpf); Netra has no steering API")
                continue
            if not e.get("steer_available"):
                why = (d.get("steering_status") or {}).get("unavailable")
                blockers.append(f"{d['id']}: duvora_steer is not attached on {e.get('node')}" + (f" ({why})" if why else ""))
            if not self.native_fresh(d):
                blockers.append(f"{d['id']}: the Duvora agent on {e.get('node')} has not reported recently")
        if action == "steer" and stage == "enforce":
            for d in devices:
                current = d.get("steering") or {}
                if not current or current.get("digest") != (extra.get("steering") or {}).get("digest") or current.get("stage") != "shadow":
                    blockers.append(f"{d['id']}: run this rule set in shadow first, then promote it")
                if (current.get("bypass") or {}).get("engaged"):
                    blockers.append(f"{d['id']}: steering is in bypass; resume it first")
            if natives:
                if not self.netra.get("enforce_allowed"):
                    blockers.append("Enforcement is disabled on this server (DUVORA_EBPF_ENFORCE=1 enables it)")
                if self.killed():
                    blockers.append("The kill switch is engaged")
            if len(devices) != 1:
                blockers.append("Enforce one device at a time")
        native = bool(natives) and not sims
        prefix = "native" if native else "simulation"
        if action == "steer":
            mode = f"steer-{prefix}-{stage}"
            confirmation = (f"ENFORCE STEERING ON {devices[0]['id']}" if stage == "enforce" else "APPLY STEERING SHADOW") if native else (
                f"ENFORCE STEERING ON {devices[0]['id']}" if stage == "enforce" else "APPLY SIMULATION")
            where = "the host kernel (duvora_steer)" if native else "the simulation model"
            effects = (f"Apply rule set {spec['ruleset']} in {where}: drop rules drop and inspect rules sample payloads"
                       + (f", for a lease renewed while Duvora runs; falls back to shadow" if native else "; nothing is filtered")
                       if stage == "enforce" else
                       f"Count, in {where}, what rule set {spec['ruleset']} would allow, inspect and drop; nothing is dropped")
        else:
            mode, confirmation = f"unsteer-{prefix}", "APPLY STEERING RELEASE" if native else "APPLY SIMULATION"
            effects = "Remove steering from the selected devices; all traffic passes uninspected"
        return mode, confirmation, effects, blockers, extra, "steer-native" if native else "simulation"

    def steer_fingerprint_state(self, d):
        s = d.get("steering") or {}
        return [s.get("digest"), s.get("stage"), (s.get("bypass") or {}).get("engaged"), (d.get("ebpf") or {}).get("node")]

    # Applying ------------------------------------------------------------------------------------
    def _steer_record(self, d, job, snapshot, stage, mode, extra=None):
        """Write a device's steering metadata and its applied rules (kept out of the device body)."""
        if snapshot is None:
            d.pop("steering", None)
            self.db.execute("DELETE FROM steering_applied WHERE device=?", (d["id"],))
            return
        previous = d.get("steering") or {}
        bypass = previous.get("bypass") if previous.get("digest") == snapshot["digest"] else None
        d["steering"] = {"ruleset": snapshot["id"], "digest": snapshot["digest"], "default": snapshot["default"],
                         "rule_count": len(snapshot["rules"]), "stage": stage, "mode": mode, "job": job,
                         "updated": time.time(), "bypass": bypass or {"engaged": False}, **(extra or {})}
        self.db.execute("INSERT INTO steering_applied VALUES(?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body",
                        (d["id"], canonical(snapshot)))

    def applied_rules(self, device_id):
        row = self.db.execute("SELECT body FROM steering_applied WHERE device=?", (device_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def seed_steering(self, device_ids):
        """Demo only (caller holds the transaction): an AI-gateway rule set in shadow on some simulated devices."""
        rs = validate_ruleset("ai-gateway", {"description": "Demo: inspect LLM traffic, bypass storage and RDMA, drop a Tor exit range",
                                             "default": "bypass", "rules": [
            {"priority": 10, "name": "bypass-rdma", "action": "bypass", "protocol": "udp", "dport": 4791, "note": "RoCEv2 stays on the fast path"},
            {"priority": 20, "name": "bypass-nvme-tcp", "action": "bypass", "protocol": "tcp", "dport": 4420},
            {"priority": 30, "name": "drop-tor-exits", "action": "drop", "dst": "185.220.101.0/24"},
            {"priority": 40, "name": "inspect-llm-https", "action": "inspect", "direction": "egress", "protocol": "tcp", "dport": 443},
            {"priority": 50, "name": "inspect-inference", "action": "inspect", "protocol": "tcp", "dport": "8000-8001"},
            {"priority": 60, "name": "inspect-ollama", "action": "inspect", "protocol": "tcp", "dport": 11434},
        ]})
        rs.update(updated=time.time(), updated_by="system")
        self.db.execute("INSERT OR IGNORE INTO steering_sets VALUES(?,?)", (rs["id"], canonical(rs)))
        for ident in device_ids:
            d = self.device(ident)
            self._steer_record(d, None, {k: rs[k] for k in ("id", "default", "rules", "digest")}, "shadow", "simulation")
            self.put("devices", ident, d)

    def steer_sim_complete(self, d, job):
        """Simulation reconciler: called by tick() for the final step of a steer/unsteer job."""
        if job["action"] == "unsteer":
            self._steer_record(d, job["id"], None, None, None)
            d.pop("steering_status", None)
        else:
            self._steer_record(d, job["id"], job["steering"], job["spec"].get("stage", "shadow"), "simulation")
            d["steering_status"] = {"mode": "simulation", "effective_mode": job["spec"].get("stage", "shadow"),
                                    "stats": {k: 0 for k in STAT_KEYS}, "stats_delta": {k: 0 for k in STAT_KEYS}, "rules": {}, "updated": time.time()}

    def _node_steering_put(self, host, body, lease):
        row = self.db.execute("SELECT revision FROM node_steering WHERE host=?", (host,)).fetchone()
        revision = (row[0] if row else 0) + 1
        until = time.time() + lease if lease else None
        body = {**body, "revision": revision, "leaseUntil": until}
        self.db.execute("INSERT INTO node_steering VALUES(?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                        "body=excluded.body, revision=excluded.revision, lease_until=excluded.lease_until", (host, canonical(body), revision, until))
        return revision, until

    def _native_steer(self, d, snapshot, stage, job_id):
        """Desired steering for a native agent's host, mirrored into the device."""
        from .ebpf import lease_seconds
        node = d["ebpf"]["node"]
        if snapshot is None:
            self.db.execute("DELETE FROM node_steering WHERE host=?", (node,))
            self._steer_record(d, job_id, None, None, None)
            return
        lease = lease_seconds() if stage == "enforce" else None
        bypass = ((d.get("steering") or {}).get("bypass") or {}).get("engaged", False) if (d.get("steering") or {}).get("digest") == snapshot["digest"] else False
        revision, until = self._node_steering_put(node, {"rulesetId": snapshot["id"], "digest": snapshot["digest"], "mode": stage,
                                                         "default": snapshot["default"], "rules": snapshot["rules"], "bypass": bypass}, lease)
        self._steer_record(d, job_id, snapshot, stage, "native", {"node": node, "revision": revision, "lease_until": until})

    def steering_duties(self):
        """Run queued native steering jobs, renew enforce leases, demote on the kill switch."""
        from .ebpf import lease_seconds
        with self.transaction():
            for job in self.rows("jobs"):
                if job.get("mode") != "steer-native" or job["state"] != "queued":
                    continue
                failed = []
                for ident in job["spec"]["devices"]:
                    d = self.device(ident)
                    if not (d.get("ebpf") or {}).get("node"):
                        failed.append(ident)
                        job["events"].append({"time": time.time(), "step": "steer", "message": f"{ident}: no agent node"})
                        continue
                    self._native_steer(d, job.get("steering") if job["action"] == "steer" else None, job["spec"].get("stage", "shadow"), job["id"])
                    d["version"] += 1
                    self.put("devices", ident, d)
                    verb = "removed" if job["action"] == "unsteer" else f"{job['spec'].get('stage', 'shadow')} with {job['spec']['ruleset']}"
                    job["events"].append({"time": time.time(), "step": "steer", "message": f"{ident}: steering {verb}"})
                job["step"] = 1
                job["state"] = "failed" if failed else "succeeded"
                self.put("jobs", job["id"], job)
                self.event("steering", f"job.{job['state']}", {"id": job["id"], "mode": "steer-native", "failed": failed})
            now = time.time()
            for d in self.rows("devices"):
                s = d.get("steering") or {}
                if s.get("mode") != "native" or s.get("stage") != "enforce":
                    continue
                if self.killed():
                    self._native_steer(d, self.applied_rules(d["id"]), "shadow", s.get("job"))
                    d["version"] += 1
                    self.put("devices", d["id"], d)
                    self.event("steering", "steering.demoted", {"device": d["id"], "reason": "kill switch"})
                elif (s.get("lease_until") or 0) - now < min(300, lease_seconds() / 3):
                    self._native_steer(d, self.applied_rules(d["id"]), "enforce", s.get("job"))
                    self.put("devices", d["id"], d)

    def steer_rollback(self, actor, job):
        """Undo a steering job: restore each device's previous steering, never re-enforcing."""
        with self.transaction():
            for before in job["before"]:
                current = self.device(before["id"])
                if job["action"] == "steer" and (current.get("steering") or {}).get("job") != job["id"]:
                    raise Problem("Later changes exist; roll those back first", 409)
                if job["action"] == "unsteer" and current.get("steering"):
                    raise Problem("Later changes exist; roll those back first", 409)
            for before in job["before"]:
                d = self.device(before["id"])
                prev = before.get("steering")
                snapshot = job.get("steering_before", {}).get(before["id"]) if prev else None
                if d["source"] == "simulator":
                    self._steer_record(d, prev.get("job") if prev else None, snapshot, "shadow" if prev else None, "simulation")
                    if not prev:
                        d.pop("steering_status", None)
                else:
                    self._native_steer(d, snapshot, "shadow", prev.get("job") if prev else None)
                d["version"] += 1
                self.put("devices", d["id"], d)
            job["state"] = "rolled-back"
            self.put("jobs", job["id"], job)
            self.event(actor, "job.rolled-back", {"id": job["id"], "mode": job.get("mode")})
        return job

    # Bypass --------------------------------------------------------------------------------------
    def set_bypass(self, actor, device_id, engaged, confirmation=None, reason="manual"):
        if not isinstance(engaged, bool):
            raise Problem("engaged must be true or false")
        with self.transaction():
            d = self.device(device_id)
            s = d.get("steering")
            if not s:
                raise Problem("This device has no steering", 409)
            if actor != "reconciler" and not actor.startswith("playbook:"):
                expected = f"BYPASS {device_id}" if engaged else f"RESUME {device_id}"
                if confirmation != expected:
                    raise Problem(f"Explicit confirmation must be {expected}")
            if bool((s.get("bypass") or {}).get("engaged")) == engaged:
                return s
            s["bypass"] = {"engaged": True, "reason": reason, "since": time.time(), "by": actor} if engaged else {"engaged": False}
            if s.get("mode") == "native":
                row = self.db.execute("SELECT body, lease_until FROM node_steering WHERE host=?", (s["node"],)).fetchone()
                if row:
                    body = {**json.loads(row[0]), "bypass": engaged}
                    lease = (row[1] - time.time()) if row[1] else None
                    s["revision"], _ = self._node_steering_put(s["node"], {k: v for k, v in body.items() if k not in {"revision", "leaseUntil"}},
                                                               max(60, lease) if lease else None)
            self.put("devices", device_id, d)
            self.event(actor, "steering.bypass-engaged" if engaged else "steering.bypass-released",
                       {"device": device_id, "reason": reason})
            return s

    # Agent -------------------------------------------------------------------------------------
    def agent_steering(self, actor):
        from .ebpf import lease_seconds
        host = actor.split(":", 1)[1] if actor.startswith("agent:") else ""
        if not host:
            raise Problem("Only agent keys read steering", 403)
        with self.lock:
            row = self.db.execute("SELECT body FROM node_steering WHERE host=?", (host,)).fetchone()
        return {"host": host, "steering": json.loads(row[0]) if row else None, "controller": self.controller_addresses,
                "lease_seconds": lease_seconds(), "now": time.time()}

    def ingest_steering(self, d, raw, now):
        """Merge the steering part of a native agent report into device `d` (caller holds the transaction)."""
        if not isinstance(raw, dict):
            d.setdefault("ebpf", {})["steer_available"] = False
            return
        prev = d.get("steering_status") or {}
        stats = {k: _num((raw.get("stats") or {}).get(k)) for k in STAT_KEYS}
        delta = {k: max(0, stats[k] - (prev.get("stats") or {}).get(k, 0)) if prev.get("stats") else 0 for k in STAT_KEYS}
        applied = self.applied_rules(d["id"]) or {"rules": []}
        names = [r["name"] for r in applied["rules"]]
        rules = {}
        for item in (raw.get("rules") or [])[:MAX_RULES + 1]:
            if not isinstance(item, dict):
                continue
            index = item.get("index")
            label = names[index] if isinstance(index, int) and 0 <= index < len(names) else "(default)" if index == len(names) else None
            if label:
                rules[label] = {"packets": _num(item.get("packets")), "bytes": _num(item.get("bytes"))}
        d["ebpf"]["steer_available"] = bool(raw.get("attached"))
        d["steering_status"] = {"mode": "native", "attached": bool(raw.get("attached")), "unavailable": _text(raw.get("unavailable"), 200),
                                "ruleset": _text(raw.get("rulesetId")), "requested_mode": _text(raw.get("mode")),
                                "effective_mode": _text(raw.get("effectiveMode")) or "off", "revision": raw.get("revision") if isinstance(raw.get("revision"), int) else None,
                                "applied_revision": raw.get("appliedRevision") if isinstance(raw.get("appliedRevision"), int) else None,
                                "demoted": _text(raw.get("demoted"), 200), "bypass": bool(raw.get("bypass")),
                                "stats": stats, "stats_delta": delta, "rules": rules, "updated": now}
        rows = []
        for v in (raw.get("verdicts") or [])[:VERDICT_BATCH]:
            item = self._verdict_row(v, "native", d["steering_status"]["effective_mode"])
            if item:
                rows.append(item)
        self.record_verdicts(d["id"], rows, now)

    @staticmethod
    def _verdict_row(v, source, stage):
        if not isinstance(v, dict) or v.get("action") not in ACTIONS or v.get("direction") not in ("egress", "ingress"):
            return None
        try:
            src, dst = str(ipaddress.ip_address(str(v.get("src")))), str(ipaddress.ip_address(str(v.get("dst"))))
        except ValueError:
            return None
        port = lambda p: p if isinstance(p, int) and 0 <= p <= 65535 else None
        return {"direction": v["direction"], "src": src, "dst": dst, "protocol": _text(v.get("protocol"), 8) or "any",
                "sport": port(v.get("sport")), "dport": port(v.get("dport")), "action": v["action"],
                "rule": _text(v.get("rule")) or None, "stage": stage, "packets": _num(v.get("packets")), "bytes": _num(v.get("bytes")), "source": source}

    def record_verdicts(self, device_id, rows, now):
        for r in rows:
            self.db.execute("INSERT INTO verdicts(device, ts, action, rule, body) VALUES(?,?,?,?,?)",
                            (device_id, now, r["action"], r.get("rule"), canonical({**r, "device": device_id})))
            self.export_event("verdict", {**r, "device": device_id, "time": now})

    def verdicts(self, device=None, action=None, rule=None, limit=200):
        if action not in (None, "", *ACTIONS):
            raise Problem("action must be bypass, allow, inspect or drop")
        try:
            limit = max(1, min(500, int(limit or 200)))
        except (TypeError, ValueError):
            raise Problem("limit must be an integer") from None
        sql, args = "SELECT id, ts, body FROM verdicts WHERE 1=1", []
        for col, value in (("device", device), ("action", action), ("rule", rule)):
            if value:
                sql += f" AND {col}=?"
                args.append(value)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            return [{"id": r["id"], "ts": r["ts"], **json.loads(r["body"])} for r in self.db.execute(sql, args)]

    def prune_verdicts(self, now):
        removed = self.db.execute("DELETE FROM verdicts WHERE ts<?", (now - VERDICT_RETENTION,)).rowcount
        top = self.db.execute("SELECT max(id) FROM verdicts").fetchone()[0] or 0
        removed += self.db.execute("DELETE FROM verdicts WHERE id<=?", (top - VERDICT_CAP,)).rowcount
        return removed

    # Simulation --------------------------------------------------------------------------------
    def simulate_steering(self, now=None):
        """Evaluate the modeled flows of every steered simulator device; record counters, verdicts and inspections."""
        now = now or time.time()
        if not self.demo or now - self.last_steer_sim < SIM_INTERVAL:
            return
        self.last_steer_sim = now
        from .inspection import analyze, sim_payload
        with self.transaction():
            for d in self.rows("devices"):
                s = d.get("steering")
                if d["source"] != "simulator" or not s:
                    continue
                try:
                    index = int(d["id"].rsplit("-", 1)[1])
                except (IndexError, ValueError):
                    continue
                applied = self.applied_rules(d["id"])
                if not applied:
                    continue
                compiled = compile_rules(applied["rules"])
                status = d.get("steering_status") or {"stats": {k: 0 for k in STAT_KEYS}, "rules": {}}
                stats = dict(status.get("stats") or {k: 0 for k in STAT_KEYS})
                before = dict(stats)
                rules = status.get("rules") or {}
                bypass = (s.get("bypass") or {}).get("engaged")
                stage = "bypass" if bypass else s["stage"]
                verdict_rows, inspections = [], []
                for f in sim_flows(index, now):
                    flow = make_flow(f["direction"], f["src"], f["dst"], f["protocol"], f["sport"], f["dport"])
                    v = {"action": "bypass", "rule": None} if bypass else evaluate(applied, flow, compiled)
                    action = v["action"]
                    key = v["rule"] or "(default)"
                    hit = rules.setdefault(key, {"packets": 0, "bytes": 0})
                    hit["packets"] += f["packets"]
                    hit["bytes"] += f["bytes"]
                    if v["rule"]:
                        stats["matched"] += f["packets"]
                    if action == "drop":
                        slot = "dropped" if stage == "enforce" else "would_drop"
                        stats[slot] += f["packets"]
                        stats[slot + "_bytes"] += f["bytes"]
                    elif action == "allow":
                        stats["allowed"] += f["packets"]
                    elif action == "inspect":
                        stats["inspected"] += f["packets"]
                        payload = sim_payload(f["payload"], random.Random(int(now) * 7 + index))
                        if payload is not None:
                            inspections.append(analyze(payload, {k: f[k] for k in ("direction", "src", "dst", "sport", "dport", "protocol")}))
                    else:
                        stats["bypassed"] += f["packets"]
                    sample_key = (d["id"], f["direction"], f["src"] if f["direction"] == "ingress" else f["dst"], f["dport"], action)
                    if action != "bypass" and now - self.sim_sampled.get(sample_key, 0) >= SIM_SAMPLE:
                        self.sim_sampled[sample_key] = now
                        verdict_rows.append({**{k: f[k] for k in ("direction", "src", "dst", "protocol", "sport", "dport", "packets", "bytes")},
                                             "action": action, "rule": v["rule"], "stage": stage, "source": "simulation"})
                d["steering_status"] = {"mode": "simulation", "effective_mode": stage, "stats": stats,
                                        "stats_delta": {k: stats[k] - before.get(k, 0) for k in STAT_KEYS}, "rules": rules, "updated": now}
                self.put("devices", d["id"], d)
                self.record_verdicts(d["id"], verdict_rows, now)
                self.record_inspections(d, inspections, now, "simulation")

    # Views -------------------------------------------------------------------------------------
    def steering_overview(self):
        with self.lock:
            devices = self.rows("devices")
            return {"sets": self.steering_sets(), "limits": {"max_rules": MAX_RULES, "actions": list(ACTIONS), "defaults": list(DEFAULTS)},
                    "enforce_allowed": bool(self.netra.get("enforce_allowed")), "kill_switch": self.killed(), "note": STEER_NOTE,
                    "devices": [{"id": d["id"], "host": d["host"], "source": d["source"],
                                 "provider": "simulation" if d["source"] == "simulator" else self.provider(d) if d.get("ebpf") else None,
                                 "steer_available": d["source"] == "simulator" or bool((d.get("ebpf") or {}).get("steer_available")),
                                 "steering": d.get("steering"), "status": d.get("steering_status")} for d in devices]}

    def device_steering(self, device_id):
        with self.lock:
            d = self.device(device_id)
            applied = self.applied_rules(device_id)
        return {"device": device_id, "steering": d.get("steering"), "status": d.get("steering_status"), "rules": (applied or {}).get("rules", []),
                "default": (applied or {}).get("default"), "verdicts": self.verdicts(device=device_id, limit=50)}

    def evaluate_steering(self, body):
        if not isinstance(body, dict) or set(body) - {"ruleset", "device", "flow"}:
            raise Problem("Provide ruleset or device, and flow")
        f = body.get("flow")
        if not isinstance(f, dict) or set(f) - {"direction", "src", "dst", "protocol", "sport", "dport"}:
            raise Problem("flow contains direction, src, dst, protocol, sport and dport")
        flow = make_flow(f.get("direction", "egress"), f.get("src"), f.get("dst"), f.get("protocol", "tcp"), f.get("sport"), f.get("dport"))
        with self.lock:
            if body.get("device"):
                d = self.device(str(body["device"]))
                ruleset = self.applied_rules(d["id"])
                if not ruleset:
                    raise Problem("This device has no steering", 409)
                bypass = ((d.get("steering") or {}).get("bypass") or {}).get("engaged")
                stage = d["steering"]["stage"]
            else:
                ruleset, bypass, stage = self.steering_set(name(body.get("ruleset"), "rule set id")), False, None
        v = evaluate(ruleset, flow, trace=True)
        if bypass:
            v.update(action="bypass", note="Steering is in bypass: every packet passes uninspected until it is resumed")
        elif stage == "shadow" and v["action"] == "drop":
            v["note"] = "Shadow: this would be dropped once the rule set is enforced"
        return {**v, "ruleset": ruleset["id"], "default": ruleset["default"], "stage": stage,
                "flow": {k: (str(v) if k in ("src", "dst") and v is not None else v) for k, v in flow.items()} | {"protocol": PROTOCOL_NAMES.get(flow["proto"], "any")}}

    def suggest_steering(self, device_id):
        with self.lock:
            d = self.device(device_id)
        flows = self.steer_flows(d)
        llm = [(e["peer"], e["port"]) for e in self.llm_endpoints(device_id) if e.get("peer")]
        intel = sorted({m["peer"] for m in self.intel_matches() if m["device"] == device_id})
        body = suggest_rules(flows, llm, intel)
        s = validate_ruleset(f"suggested-{d['id']}"[:63], {"description": f"Suggested from observed traffic on {d['id']}", **body})
        return {"device": device_id, "ruleset": s, "replay": replay_steering(flows, s),
                "source": "modeled flow catalog" if d["source"] == "simulator" else "observed flow records" if flows else "no flow records yet",
                "note": "Review before use: the default stays bypass until a shadow run shows nothing unexpected would be dropped."}

    def explain_verdict(self, body, use_llm=True):
        v = self.evaluate_steering(body)
        lines = []
        if v.get("rule"):
            lines.append(f"Rule {v['rule']} (priority {v['priority']}) matches first, so the flow is {v['action']}.")
        else:
            lines.append(f"No rule matches, so the default action {v['default']} applies.")
        skipped = [t for t in v.get("trace", []) if not t["matched"]][:3]
        if skipped:
            lines.append("Earlier rules did not match: " + "; ".join(f"{t['rule']} ({t['why']})" for t in skipped) + ".")
        if v.get("note"):
            lines.append(v["note"] + ".")
        v["narrative"], v["narrative_source"] = " ".join(lines), "template"
        if use_llm and self.llm:
            try:
                v["narrative"] = self.llm_text("Explain this traffic steering verdict to an operator in 2-4 sentences. "
                                               "Say which rule matched and what to change if the verdict is unexpected.", v)
                v["narrative_source"] = "llm"
            except Problem as exc:
                v["narrative_error"] = str(exc)
        return v

    # Alerts ------------------------------------------------------------------------------------
    def steering_conditions(self):
        def bypass(rule, now, firing):
            for d in self.rows("devices"):
                b = (d.get("steering") or {}).get("bypass") or {}
                if b.get("engaged") and now - b.get("since", now) >= rule["threshold"] * 60:
                    firing[f"{rule['id']}:{d['id']}"] = (rule, d["id"], f"Steering bypass on {d['id']}",
                                                         f"In bypass for {int((now - b['since']) // 60)} min ({b.get('reason', 'manual')}); traffic passes uninspected")

        def drops(slot, label):
            def check(rule, now, firing):
                for d in self.rows("devices"):
                    st = d.get("steering_status") or {}
                    n = (st.get("stats_delta") or {}).get(slot, 0)
                    if n:
                        rules = sorted(((k, v) for k, v in (st.get("rules") or {}).items()), key=lambda x: -x[1]["packets"])
                        firing[f"{rule['id']}:{d['id']}"] = (rule, d["id"], f"{label} on {d['id']}",
                                                             f"{n} packets in the last interval" + (f"; busiest rule {rules[0][0]}" if rules else ""))
            return check
        return {"steering-bypass": bypass, "steering-drop": drops("dropped", "Steering is dropping traffic"),
                "steering-would-drop": drops("would_drop", "Shadow steering would drop traffic")}

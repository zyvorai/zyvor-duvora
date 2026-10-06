"""eBPF observations and node isolation from two providers, merged into Duvora devices without
touching simulated state:

  native  Duvora's own agent (duvora-agent --ebpf) loads duvora/bpf objects on the host, posts
          counters to /api/v1/agent/ebpf and pulls desired isolation from /api/v1/agent/isolation.
  netra   an optional Netra controller, polled by the netra_sync thread.

DUVORA_EBPF_SOURCE=native|netra|auto picks the provider; in auto a fresh native report wins."""
import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

from .common import Problem, canonical
from .netra import FLOW_WINDOW, NetraError, summarize, top_talkers

SCHEMA = """
CREATE TABLE IF NOT EXISTS ebpf_state(device TEXT PRIMARY KEY, body TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS node_isolation(host TEXT PRIMARY KEY, body TEXT NOT NULL, revision INTEGER NOT NULL, lease_until REAL);
"""
MEASURED = ("throughput_gbps", "pps", "blocked_pps", "drops", "tcp_retransmits_pm", "tcp_resets_pm")
SOURCE = "netra-ebpf"
NATIVE_SOURCE = "duvora-ebpf"
EBPF_SOURCES = (SOURCE, NATIVE_SOURCE)
PROVIDERS = {SOURCE: "netra", NATIVE_SOURCE: "native"}
NATIVE_FRESH = 90
NATIVE_FLOWS = 2000
KILL_KEY = "_kill_switch"
STAGES = ("shadow", "enforce")
IFACE_NAME = re.compile(r"[A-Za-z0-9._@:-]{1,32}")


def lease_seconds():
    try:
        return min(3600, max(60, int(os.environ.get("DUVORA_NETRA_LEASE", "900"))))
    except ValueError:
        return 900


def isolation_rules(cidr, ports):
    """Duvora's allow-list (CIDR + optional ports) as Netra node-isolation rules; ports become ranges."""
    if not ports:
        return [{"cidr": cidr}]
    ranges = []
    for port in sorted(set(ports)):
        if ranges and port == ranges[-1][1] + 1:
            ranges[-1][1] = port
        else:
            ranges.append([port, port])
    return [{"cidr": cidr, "portFrom": a, "portTo": b} for a, b in ranges]


def node_slug(node):
    slug = re.sub(r"[^a-z0-9._-]+", "-", node.lower()).strip("-._")[:56] or "node"
    return slug if slug[0].isalnum() else "n" + slug


def replay(flows, cidr, ports):
    """Evaluate observed egress flow records against an allow-list (CIDR + optional ports)."""
    network = ipaddress.ip_network(cidr)
    allowed_ports = set(ports or [])
    out = {"flows": 0, "would_block_flows": 0, "would_block_packets": 0, "would_block_bytes": 0, "unresolved": 0, "top": []}
    blocked = {}
    for r in flows:
        if str(r.get("direction") or "egress").lower() not in {"egress", "outbound", "out"}:
            continue
        try:
            address = ipaddress.ip_address(str(r.get("peer") or ""))
        except ValueError:
            out["unresolved"] += 1
            continue
        out["flows"] += 1
        port = r.get("port") if isinstance(r.get("port"), int) else 0
        if address.version == network.version and address in network and (not allowed_ports or port in allowed_ports):
            continue
        packets = r.get("packets") if isinstance(r.get("packets"), (int, float)) else 0
        size = r.get("bytes") if isinstance(r.get("bytes"), (int, float)) else 0
        out["would_block_flows"] += 1
        out["would_block_packets"] += packets
        out["would_block_bytes"] += size
        key = (str(address), port)
        entry = blocked.setdefault(key, {"peer": str(address), "port": port, "packets": 0, "bytes": 0})
        entry["packets"] += packets
        entry["bytes"] += size
    out["top"] = sorted(blocked.values(), key=lambda e: (-e["bytes"], -e["packets"]))[:5]
    return out


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 2 ** 63 else 0


def _text(value, limit=200):
    return value[:limit] if isinstance(value, str) else ""


def _parse_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return None


def native_summary(host, s):
    """A native agent report, reduced to the netra.summarize() shape with every field type-checked."""
    if not isinstance(s, dict):
        raise Problem("summary must be an object")
    out = {"node": host, "hostname": _text(s.get("hostname"), 64), "kernel": _text(s.get("kernel"), 64),
           "stale": False, "age": 0, "mode": "observe", "btf": bool(s.get("btf")),
           "programs": sorted({_text(p, 64) for p in (s.get("programs") or [])[:32] if _text(p, 64)}),
           "program_count": int(_num(s.get("program_count"))), "attached": int(_num(s.get("attached"))),
           "drops": _num(s.get("drops")), "nodeiso_available": bool(s.get("nodeiso_available")),
           "drop_info_unavailable": _text(s.get("drop_info_unavailable")), "tcp_unavailable": _text(s.get("tcp_unavailable")),
           "errors": [_text(e, 300) for e in (s.get("errors") or [])[:5] if _text(e, 300)], "interfaces": {}, "flows": []}
    interfaces = s.get("interfaces") or {}
    if not isinstance(interfaces, dict):
        raise Problem("interfaces must be an object")
    for name, v in list(interfaces.items())[:32]:
        if IFACE_NAME.fullmatch(str(name)) and isinstance(v, dict):
            out["interfaces"][str(name)] = {k: _num(v.get(k)) for k in ("packets", "bytes", "blocked")}
    if isinstance(s.get("drop_reasons"), list):
        out["drop_reasons"] = [{"reason": _text(r.get("reason"), 64) or "unknown", "count": _num(r.get("count"))}
                               for r in s["drop_reasons"][:5] if isinstance(r, dict)]
    if isinstance(s.get("tcp"), dict):
        out["tcp"] = {k: _num(s["tcp"].get(k)) for k in ("retransmits", "resets")}
    for r in (s.get("flows") or [])[:200]:
        if not isinstance(r, dict):
            continue
        try:
            peer = str(ipaddress.ip_address(str(r.get("peer"))))
        except ValueError:
            continue
        port = r.get("port") if isinstance(r.get("port"), int) and 0 <= r["port"] <= 65535 else 0
        out["flows"].append({"peer": peer, "port": port, "protocol": _text(r.get("protocol"), 16), "packets": _num(r.get("packets")),
                             "bytes": _num(r.get("bytes")), "blocked": 0, "direction": "egress",
                             "observedAt": _text(r.get("observedAt"), 32)})
    iso = s.get("isolation")
    if isinstance(iso, dict):
        item = {k: _text(iso.get(k), 64) or None for k in ("policyId", "mode", "effectiveMode")}
        item.update({k: iso.get(k) if isinstance(iso.get(k), (int, float)) and not isinstance(iso.get(k), bool) else None
                     for k in ("revision", "appliedRevision", "leaseUntil")})
        item.update({k: _num(iso.get(k)) for k in ("allowedPackets", "exemptPackets", "wouldBlockPackets", "wouldBlockBytes",
                                                    "blockedPackets", "blockedBytes")})
        item.update(demoted=_text(iso.get("demoted")), unavailable=_text(iso.get("unavailable")), agentStale=False,
                    attached=bool(iso.get("attached")),
                    top=[{"address": _text(t.get("address"), 64), "port": int(_num(t.get("port"))) & 0xFFFF,
                          "protocol": _text(t.get("protocol"), 16), "packets": _num(t.get("packets")), "bytes": _num(t.get("bytes"))}
                         for t in (iso.get("top") or [])[:5] if isinstance(t, dict)])
        out["isolation"] = item
    return out


class EbpfMixin:
    def init_ebpf(self):
        self.db.executescript(SCHEMA)
        self.netra = {"configured": False, "connected": False, "last_sync": None, "error": None,
                      "unmatched": [], "isolation_supported": False, "enforce_allowed": False, "nodes": 0}
        self.netra_flows = {}
        try:
            self.node_map = json.loads(os.environ.get("DUVORA_NETRA_NODE_MAP") or "{}")
            if not isinstance(self.node_map, dict):
                raise ValueError
        except ValueError:
            raise ValueError("DUVORA_NETRA_NODE_MAP must be a JSON object of device id or host to Netra node") from None
        self.netra_discover = os.environ.get("DUVORA_NETRA_DISCOVER") == "1"
        self.netra_client = None
        self.netra_wake = threading.Event()
        self.ebpf_source = os.environ.get("DUVORA_EBPF_SOURCE", "auto")
        if self.ebpf_source not in {"native", "netra", "auto"}:
            raise ValueError("DUVORA_EBPF_SOURCE must be native, netra or auto")
        self.netra["enforce_allowed"] = "1" in {os.environ.get("DUVORA_EBPF_ENFORCE"), os.environ.get("DUVORA_NETRA_ENFORCE")}
        self.controller_addresses = [a.strip() for a in os.environ.get("DUVORA_CONTROLLER_ADDRESSES", "").split(",") if a.strip()]
        row = self.db.execute("SELECT body FROM ebpf_state WHERE device=?", (KILL_KEY,)).fetchone()
        self.netra["kill_switch"] = json.loads(row[0]) if row else {"engaged": False}

    def configure_netra(self, url, enforce=False, client=None):
        self.netra.update(configured=True, url=url, enforce_allowed=bool(enforce) or self.netra["enforce_allowed"])
        self.netra_client = client

    def netra_node(self, d):
        """The eBPF node behind a device (Netra node or native host), or None (simulators never have one)."""
        return d.get("ebpf", {}).get("node") if d["source"] != "simulator" else None

    @staticmethod
    def provider(d):
        return d.get("ebpf", {}).get("provider") or "netra"

    def native_fresh(self, d, now=None):
        e = d.get("ebpf") or {}
        return e.get("provider") == "native" and (now or time.time()) - (e.get("updated") or 0) < NATIVE_FRESH

    def killed(self):
        return bool(self.netra["kill_switch"].get("engaged"))

    def netra_plan(self, spec, devices):
        """Mode, confirmation, effects and blockers for a plan whose targets are eBPF-backed (native or Netra)."""
        action, stage = spec["action"], spec.get("stage", "shadow")
        blockers = []
        providers = {self.provider(d) for d in devices}
        if action not in {"isolate", "release"}:
            blockers.append("eBPF-backed devices support isolate and release only")
        if "netra" in providers:
            if not self.netra.get("connected"):
                blockers.append("Netra is not connected")
            elif not self.netra.get("isolation_supported"):
                blockers.append("This Netra has no node isolation API; upgrade Netra")
        for d in devices:
            e = d.get("ebpf", {})
            native = self.provider(d) == "native"
            if not e.get("nodeiso_available"):
                why = (e.get("isolation") or {}).get("unavailable")
                blockers.append(f"{d['id']}: node isolation is not attached on {e.get('node')}" + (f" ({why})" if why else ""))
            if native and not self.native_fresh(d):
                blockers.append(f"{d['id']}: the Duvora agent on {e.get('node')} has not reported for {NATIVE_FRESH} s")
            if not native and e.get("stale"):
                blockers.append(f"{d['id']}: the Netra agent on {e.get('node')} is stale")
            current = d.get("netra_isolation")
            if action == "release" and not current:
                blockers.append(f"{d['id']}: no node isolation to release")
            if action == "isolate" and stage == "enforce":
                wanted = {k: spec["policy"][k] for k in ("cidr", "ports")}
                if not current or {k: current["policy"][k] for k in ("cidr", "ports")} != wanted:
                    blockers.append(f"{d['id']}: run this allow-list in shadow first, then promote it")
        if action == "isolate" and stage == "enforce":
            if not self.netra.get("enforce_allowed"):
                blockers.append("Enforcement is disabled on this server (DUVORA_NETRA_ENFORCE=1 enables it)")
            if self.killed():
                blockers.append("The kill switch is engaged")
            if len(devices) != 1:
                blockers.append("Enforce one device at a time")
        prefix = providers.pop() if len(providers) == 1 else "ebpf"
        where = "the Duvora agent's node" if prefix == "native" else "the Netra node" if prefix == "netra" else "each node"
        if action == "isolate":
            mode = f"{prefix}-{stage}"
            confirmation = f"ENFORCE ON {devices[0]['id']}" if stage == "enforce" else "APPLY SHADOW"
            effects = (f"Drop new outbound flows outside {spec['policy']['cidr']} on {where} for a "
                       f"{lease_seconds() // 60}-minute lease, renewed while Duvora runs; falls back to shadow"
                       if stage == "enforce" else
                       f"Count, in the kernel, what this allow-list would block on {where}; nothing is dropped")
        else:
            mode, confirmation, effects = f"{prefix}-release", "APPLY RELEASE", "Remove node isolation from the selected devices"
        return mode, confirmation, effects, blockers

    def netra_body(self, ni, stage):
        return {"policyId": ni["policy_id"], "mode": stage, "rules": isolation_rules(ni["policy"]["cidr"], ni["policy"]["ports"])}

    def _netra_put(self, client, ni, stage):
        """Set a device's isolation through its provider: the native table or the Netra API."""
        lease = lease_seconds() if stage == "enforce" else None
        if ni.get("provider") == "native":
            revision, until = self._native_put(ni["node"], self.netra_body(ni, stage), lease)
        else:
            if not client:
                raise NetraError("Netra is not configured")
            out = client.put_isolation(ni["node"], self.netra_body(ni, stage), f"{lease}s" if lease else None)
            revision, until = out.get("revision"), out.get("leaseUntil")
        return {**ni, "stage": stage, "revision": revision, "updated": time.time(),
                "lease_until": time.time() + lease if lease and until else None}

    def _isolation_delete(self, client, provider, node):
        if provider == "native":
            with self.transaction():
                self.db.execute("DELETE FROM node_isolation WHERE host=?", (node,))
            return
        if not client:
            raise NetraError("Netra is not configured")
        client.delete_isolation(node)

    def _native_put(self, host, body, lease):
        """Desired isolation for a native agent; each change bumps the revision the agent reports back."""
        with self.transaction():
            row = self.db.execute("SELECT revision FROM node_isolation WHERE host=?", (host,)).fetchone()
            revision = (row[0] if row else 0) + 1
            until = time.time() + lease if lease else None
            body = {**body, "revision": revision, "leaseUntil": until}
            self.db.execute("INSERT INTO node_isolation VALUES(?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                            "body=excluded.body, revision=excluded.revision, lease_until=excluded.lease_until",
                            (host, canonical(body), revision, until))
            return revision, until

    def agent_isolation(self, actor):
        """GET /agent/isolation: the desired node isolation for the calling agent's host."""
        host = actor.split(":", 1)[1] if actor.startswith("agent:") else ""
        if not host:
            raise Problem("Only agent keys read node isolation", 403)
        if self.ebpf_source == "netra":
            return {"host": host, "isolation": None, "controller": self.controller_addresses, "now": time.time()}
        with self.lock:
            row = self.db.execute("SELECT body FROM node_isolation WHERE host=?", (host,)).fetchone()
        return {"host": host, "isolation": json.loads(row[0]) if row else None,
                "controller": self.controller_addresses, "lease_seconds": lease_seconds(), "now": time.time()}

    def ingest_native(self, actor, body):
        """POST /agent/ebpf: merge one native agent report into the device for its host."""
        if not isinstance(body, dict) or set(body) - {"host", "summary"}:
            raise Problem("Report must contain host and summary")
        host = body.get("host")
        if not isinstance(host, str) or actor != f"agent:{host}":
            raise Problem("Agent hostname does not match its key", 403)
        if self.ebpf_source == "netra":
            raise Problem("Native eBPF reports are disabled (DUVORA_EBPF_SOURCE=netra)", 409)
        s = native_summary(host, body.get("summary"))
        now = time.time()
        with self.transaction():
            candidates = [d for d in self.rows("devices") if d["host"] == host and d["source"] != "simulator"]
            rank = lambda d: (self.provider(d) != "native" or not d.get("ebpf"), d["source"] != NATIVE_SOURCE,
                              d["source"] != SOURCE, d["id"])
            d = min(candidates, key=rank) if candidates else None
            if not d:
                d = {"id": "ebpf-" + node_slug(host), "model": "Linux host (native eBPF)", "host": host, "site": "unassigned",
                     "source": NATIVE_SOURCE, "firmware": "unknown", "health": "unknown", "metrics": {}, "interfaces": [],
                     "last_seen": now, "version": 1, "mode": "observe", "services": [], "policy_ids": [],
                     "capabilities": ["read-only", "ebpf"]}
                self.event(actor, "device.discovered", {"id": d["id"], "source": NATIVE_SOURCE, "host": host})
            cutoff = now - 3600
            kept = [r for r in self.netra_flows.get(d["id"], []) if (_parse_time(r.get("observedAt")) or 0) >= cutoff]
            s["flows"] = (s["flows"] + kept)[:NATIVE_FLOWS]
            self.ingest_node(d, s, now, provider="native")
            raw = body["summary"]
            self.ingest_steering(d, raw.get("steering"), now)
            if isinstance(raw.get("inspections"), list):
                self.record_inspections(d, raw["inspections"], now, "agent")
            if isinstance(raw.get("ai_assets"), list):
                self.record_assets(d, raw["ai_assets"], now, "agent")
            self.put("devices", d["id"], d)
            return {"device": d["id"], "provider": "native"}

    def _set_isolation(self, d, ni, job_id=None):
        """Record a device's Netra isolation (or its removal, ni=None) and the matching policy row."""
        for pid in d.get("policy_ids", []):
            row = self.db.execute("SELECT body FROM policies WHERE id=?", (pid,)).fetchone()
            if row:
                policy = json.loads(row[0])
                policy["devices"] = [x for x in policy["devices"] if x != d["id"]]
                if policy["devices"]:
                    self.put("policies", pid, policy)
                else:
                    self.db.execute("DELETE FROM policies WHERE id=?", (pid,))
        if ni:
            pid = job_id or ni["job"]
            row = self.db.execute("SELECT body FROM policies WHERE id=?", (pid,)).fetchone()
            policy = json.loads(row[0]) if row else {"id": pid, **ni["policy"], "devices": [], "created": time.time()}
            policy["devices"] = sorted(set(policy["devices"]) | {d["id"]})
            policy["mode"] = f"{ni.get('provider', 'netra')}-{ni['stage']}"
            self.put("policies", pid, policy)
            d["netra_isolation"], d["mode"], d["policy_ids"] = ni, "isolated" if ni["stage"] == "enforce" else "shadow", [pid]
        else:
            d.pop("netra_isolation", None)
            d["mode"], d["policy_ids"] = "observe", []
        d["version"] += 1
        self.put("devices", d["id"], d)

    def match_node(self, device, summary):
        if device["source"] == "simulator":
            return None
        mapped = self.node_map.get(device["id"]) or self.node_map.get(device["host"])
        if mapped:
            return mapped if mapped in summary else None
        if device.get("ebpf", {}).get("node") in summary:
            return device["ebpf"]["node"]
        for node, s in summary.items():
            if device["host"] in {node, node_slug(node), (s.get("hostname") or "").lower()}:
                return node
        return None

    def netra_wanted_nodes(self):
        """Nodes to query per node (drop reasons, TCP); None means every Netra node."""
        if self.netra_discover or self.node_map:
            return None
        with self.lock:
            return sorted({d["ebpf"]["node"] for d in self.rows("devices") if d.get("ebpf", {}).get("node")})

    def ingest_netra(self, raw, now=None):
        """Merge one Netra collection pass. Rates come from deltas against the previous pass."""
        now = now or raw.get("fetched") or time.time()
        summary = summarize(raw)
        hard_errors = [v for k, v in raw.get("errors", {}).items() if k in {"fleet", "status"}]
        with self.transaction():
            self.netra.update(connected=not hard_errors, last_sync=now, nodes=len(summary),
                              error="; ".join(sorted(raw.get("errors", {}).values()))[:500] or None,
                              isolation_supported=not raw.get("isolation_unsupported") and raw.get("isolation") is not None)
            if hard_errors:
                return self.netra
            devices = {d["id"]: d for d in self.rows("devices")}
            matched = {}
            for d in devices.values():
                node = self.match_node(d, summary)
                if node:
                    matched[node] = d["id"]
            if self.netra_discover:
                for node in summary:
                    if node in matched:
                        continue
                    ident = "netra-" + node_slug(node)
                    if ident in devices and devices[ident]["source"] != SOURCE:
                        continue
                    d = devices.get(ident) or {
                        "id": ident, "model": "Netra eBPF node", "host": node_slug(node), "site": "netra",
                        "source": SOURCE, "firmware": "unknown", "health": "unknown", "metrics": {},
                        "interfaces": [], "last_seen": now, "version": 1, "mode": "observe", "services": [],
                        "policy_ids": [], "capabilities": ["read-only", "ebpf"]}
                    if ident not in devices:
                        self.event("netra", "device.discovered", {"id": ident, "source": SOURCE, "node": node})
                    devices[ident] = d
                    matched[node] = ident
            self.netra["unmatched"] = sorted(set(summary) - set(matched))
            if self.ebpf_source == "native":
                return self.netra
            listed = raw.get("isolation") is not None and "isolation" not in raw.get("errors", {})
            for node, ident in matched.items():
                if self.native_fresh(devices[ident], now):
                    continue
                self.ingest_node(devices[ident], summary[node], now, "netra", listed)
            return self.netra

    def ingest_node(self, d, s, now, provider="netra", isolation_listed=False):
        """Merge one node summary (netra.summarize() shape) from either provider into device `d`."""
        row = self.db.execute("SELECT body FROM ebpf_state WHERE device=?", (d["id"],)).fetchone()
        prev = json.loads(row[0]) if row else None
        counters = {"bytes": sum(i["bytes"] for i in s["interfaces"].values()),
                    "packets": sum(i["packets"] for i in s["interfaces"].values()),
                    "blocked": sum(i["blocked"] for i in s["interfaces"].values()),
                    "drops": s["drops"], "retransmits": s["tcp"]["retransmits"] if "tcp" in s else None,
                    "resets": s["tcp"]["resets"] if "tcp" in s else None,
                    "would_block": (s.get("isolation") or {}).get("wouldBlockPackets") if s.get("isolation") else None,
                    "iso_blocked": (s.get("isolation") or {}).get("blockedPackets") if s.get("isolation") else None,
                    "ts": now}
        measured = {}
        if prev and now > prev["ts"]:
            dt = now - prev["ts"]
            # Only diff counters present in both passes; a counter that went backwards means the
            # agent or its maps restarted, so that interval is skipped.
            delta = {k: counters[k] - prev[k] for k in counters
                     if k != "ts" and counters[k] is not None and prev.get(k) is not None}
            if delta.get("bytes", -1) >= 0 and delta.get("packets", -1) >= 0:
                measured["throughput_gbps"] = round(delta["bytes"] * 8 / dt / 1e9, 3)
                measured["pps"] = round(delta["packets"] / dt, 1)
                measured["blocked_pps"] = round(max(0, delta.get("blocked", 0)) / dt, 1)
            if delta.get("drops", -1) >= 0:
                measured["drops"] = delta["drops"]
            if delta.get("retransmits", -1) >= 0 and delta.get("resets", -1) >= 0:
                measured["tcp_retransmits_pm"] = round(delta["retransmits"] / dt * 60, 1)
                measured["tcp_resets_pm"] = round(delta["resets"] / dt * 60, 1)
            counters["would_block_delta"] = max(0, delta.get("would_block", 0))
            counters["blocked_delta"] = max(0, delta.get("iso_blocked", 0))
        self.db.execute("INSERT INTO ebpf_state VALUES(?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body, updated=excluded.updated",
                        (d["id"], canonical(counters), now))
        self.netra_flows[d["id"]] = s["flows"]
        self.observe_destinations(d["id"], s["flows"], now)
        isolation = s.get("isolation")
        source = NATIVE_SOURCE if provider == "native" else SOURCE
        d["ebpf"] = {
            "provider": provider, "errors": s.get("errors", []),
            "node": s["node"], "stale": s.get("stale", False), "age": s.get("age", 0), "kernel": s.get("kernel", ""),
            "btf": s.get("btf"), "programs": s["programs"], "program_count": s.get("program_count", 0),
            "attached": s.get("attached", 0), "mode": s.get("mode", "observe"), "interfaces": sorted(s["interfaces"]),
            "drop_reasons": s.get("drop_reasons", []), "drop_info_unavailable": s.get("drop_info_unavailable"),
            "tcp_unavailable": s.get("tcp_unavailable"), "talkers": top_talkers(s["flows"], now),
            "nodeiso_available": s.get("nodeiso_available", False),
            "isolation": None if not isolation else {
                "policy_id": isolation.get("policyId") or isolation.get("id"),
                "mode": isolation.get("effectiveMode") or isolation.get("mode"), "requested_mode": isolation.get("mode"),
                "revision": isolation.get("revision"), "applied_revision": isolation.get("appliedRevision"),
                "lease_until": isolation.get("leaseUntil"), "demoted": isolation.get("demoted") or "",
                "agent_stale": bool(isolation.get("agentStale")), "unavailable": isolation.get("unavailable") or "",
                "allowed_packets": isolation.get("allowedPackets", 0), "exempt_packets": isolation.get("exemptPackets", 0),
                "would_block_packets": isolation.get("wouldBlockPackets", 0), "would_block_bytes": isolation.get("wouldBlockBytes", 0),
                "blocked_packets": isolation.get("blockedPackets", 0), "blocked_bytes": isolation.get("blockedBytes", 0),
                "would_block_delta": counters.get("would_block_delta", 0), "blocked_delta": counters.get("blocked_delta", 0),
                "top": (isolation.get("top") or [])[:5]},
            "updated": now}
        if isolation_listed and (d.get("netra_isolation") or {}).get("provider", "netra") == provider:
            self._isolation_drift(d, isolation, now)
        if measured:
            d["metrics"] = {**d.get("metrics", {}), **measured}
            d["metrics_source"] = source
            self.record_sample(d["id"], d["metrics"], now)
        if d["source"] in EBPF_SOURCES:
            d["interfaces"] = sorted(s["interfaces"])[:32]
            d["health"] = "unknown" if s.get("stale") else ("healthy" if s.get("attached", 0) else "degraded")
            if not s.get("stale"):
                d["last_seen"] = now
        if "ebpf" not in d["capabilities"]:
            d["capabilities"] = d["capabilities"] + ["ebpf"]
        self.put("devices", d["id"], d)

    def netra_duties(self, client=None):
        """Run queued eBPF isolation jobs, hold the kill switch, and renew enforce leases, for both
        providers. Netra calls happen outside the store lock; results are written back under it."""
        client = client or self.netra_client
        self._run_netra_jobs(client)
        if self.killed():
            self._demote_all(client, "kill switch")
        self._renew_leases(client)
        self.steering_duties()

    def _run_netra_jobs(self, client):
        with self.transaction():
            jobs = [j for j in self.rows("jobs") if j.get("mode") == "netra" and j["state"] == "queued"]
            for job in jobs:
                job["state"] = "running"
                self.put("jobs", job["id"], job)
        for job in jobs:
            spec, results = job["spec"], {}
            with self.lock:
                devices = {x: self.device(x) for x in spec["devices"]}
            for ident, d in devices.items():
                try:
                    if spec["action"] == "release":
                        ni = d["netra_isolation"]
                        self._isolation_delete(client, ni.get("provider", "netra"), ni["node"])
                        results[ident] = None
                    else:
                        ni = {"node": self.netra_node(d), "provider": self.provider(d), "policy_id": f"duvora-{job['id'][:16]}",
                              "job": job["id"], "policy": spec["policy"], "lease_until": None}
                        results[ident] = self._netra_put(client, ni, spec.get("stage", "shadow"))
                except (NetraError, KeyError, TypeError) as exc:
                    results[ident] = exc
            with self.transaction():
                job = self.db.execute("SELECT body FROM jobs WHERE id=?", (job["id"],)).fetchone()
                job = json.loads(job[0])
                failed = []
                for ident, result in results.items():
                    if isinstance(result, Exception):
                        failed.append(ident)
                        job["events"].append({"time": time.time(), "step": "netra", "message": f"{ident}: {result}"[:300]})
                        continue
                    d = self.device(ident)
                    self._set_isolation(d, result, job["id"])
                    verb = "removed" if result is None else f"{result['stage']} on node {result['node']} (revision {result['revision']})"
                    job["events"].append({"time": time.time(), "step": "netra", "message": f"{ident}: isolation {verb}"})
                job["step"] = 1
                job["state"] = "failed" if failed else "succeeded"
                self.put("jobs", job["id"], job)
                self.event("netra", f"job.{job['state']}", {"id": job["id"], "mode": "netra", "failed": failed})

    def _renew_leases(self, client):
        now = time.time()
        with self.lock:
            due = [d for d in self.rows("devices") if (d.get("netra_isolation") or {}).get("stage") == "enforce"
                   and (d["netra_isolation"].get("lease_until") or 0) - now < min(300, lease_seconds() / 3)]
        for d in due:
            try:
                ni = self._netra_put(client, d["netra_isolation"], "enforce")
            except NetraError as exc:
                with self.transaction():
                    self.event("netra", "isolation.lease-renew-failed", {"device": d["id"], "error": str(exc)[:200]})
                continue
            with self.transaction():
                current = self.device(d["id"])
                if (current.get("netra_isolation") or {}).get("policy_id") == ni["policy_id"] and current["netra_isolation"]["stage"] == "enforce":
                    current["netra_isolation"] = ni
                    self.put("devices", current["id"], current)

    def _demote_all(self, client, reason):
        """Move every enforced device back to shadow. Returns {device: error or None}."""
        with self.lock:
            enforced = [d for d in self.rows("devices") if (d.get("netra_isolation") or {}).get("stage") == "enforce"]
        out = {}
        for d in enforced:
            try:
                ni = self._netra_put(client, d["netra_isolation"], "shadow")
                out[d["id"]] = None
            except NetraError as exc:
                out[d["id"]] = str(exc)[:200]
                continue
            with self.transaction():
                current = self.device(d["id"])
                if (current.get("netra_isolation") or {}).get("policy_id") == ni["policy_id"]:
                    self._set_isolation(current, ni)
                    self.event("netra", "isolation.demoted", {"device": d["id"], "reason": reason})
        return out

    def kill_switch(self, actor, engaged):
        """Engage: every enforced device goes back to shadow now, and enforce plans are refused until released."""
        if not isinstance(engaged, bool):
            raise Problem("engaged must be true or false")
        state = {"engaged": engaged, "by": actor, "at": time.time()}
        with self.transaction():
            self.db.execute("INSERT INTO ebpf_state VALUES(?,?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body, updated=excluded.updated",
                            (KILL_KEY, canonical(state), state["at"]))
            self.netra["kill_switch"] = state
            self.event(actor, "ebpf.kill-switch", {"engaged": engaged})
        demoted = self._demote_all(self.netra_client, "kill switch") if engaged else {}
        if engaged:
            self.steering_duties()
        return {**state, "demoted": sorted(k for k, v in demoted.items() if v is None),
                "errors": {k: v for k, v in demoted.items() if v}}

    def netra_rollback(self, actor, job):
        """Undo an eBPF isolation job: restore each device's previous isolation, but never re-enforce."""
        with self.lock:
            for d in job["before"]:
                current = self.device(d["id"])
                if job["action"] == "isolate" and (current.get("netra_isolation") or {}).get("job") != job["id"]:
                    raise Problem("Later changes exist; roll those back first", 409)
                if job["action"] == "release" and current.get("netra_isolation"):
                    raise Problem("Later changes exist; roll those back first", 409)
                if any(j["state"] in {"queued", "running"} and d["id"] in j["spec"]["devices"] for j in self.rows("jobs")):
                    raise Problem("Device has an active job", 409)
        restored = {}
        for d in job["before"]:
            prev = d.get("netra_isolation")
            try:
                if prev:
                    restored[d["id"]] = self._netra_put(self.netra_client, prev, "shadow")
                else:
                    after = self.device(d["id"]).get("netra_isolation") or {}
                    self._isolation_delete(self.netra_client, after.get("provider") or self.provider(d), self.netra_node(d))
                    restored[d["id"]] = None
            except NetraError as exc:
                raise Problem(f"The isolation provider refused the rollback for {d['id']}: {exc}", 502) from None
        with self.transaction():
            for ident, ni in restored.items():
                self._set_isolation(self.device(ident), ni)
            job["state"] = "rolled-back"
            self.put("jobs", job["id"], job)
            self.event(actor, "job.rolled-back", {"id": job["id"], "mode": "netra"})
            return job

    def _isolation_drift(self, d, item, fetched):
        """Netra changed a device's isolation behind Duvora's back (lease lapse, restart, edit, delete)."""
        ni = d.get("netra_isolation")
        if not ni or ni.get("updated", 0) >= fetched:
            return
        if item is None or item.get("policyId") != ni["policy_id"]:
            why = "removed" if item is None else "replaced by another policy"
            self._set_isolation(d, None)
            self.event("netra", "isolation.drift", {"device": d["id"], "node": ni["node"], "change": why})
        elif ni["stage"] == "enforce" and item.get("mode") == "shadow":
            self._set_isolation(d, {**ni, "stage": "shadow", "lease_until": None, "updated": time.time()})
            self.event("netra", "isolation.demoted", {"device": d["id"], "reason": "Netra fell back to shadow"})

    def ebpf_overview(self):
        with self.lock:
            devices = [d for d in self.rows("devices") if d.get("ebpf")]
            now = time.time()
            return {"netra": dict(self.netra), "source": self.ebpf_source,
                    "native": {"agents": sum(self.native_fresh(d, now) for d in devices)}, "devices": [
                {"id": d["id"], "host": d["host"], "source": d["source"], "metrics_source": d.get("metrics_source"),
                 "provider": self.provider(d), "errors": d["ebpf"].get("errors", []),
                 "stale": d["ebpf"].get("stale") or (self.provider(d) == "native" and not self.native_fresh(d, now)),
                 **{k: d["ebpf"].get(k) for k in ("node", "kernel", "btf", "programs", "attached", "mode", "nodeiso_available",
                                                  "drop_info_unavailable", "tcp_unavailable", "isolation", "updated")},
                 "netra_isolation": d.get("netra_isolation")}
                for d in devices]}

    def device_ebpf(self, device_id):
        with self.lock:
            d = self.device(device_id)
            if not d.get("ebpf"):
                raise Problem("No eBPF observations for this device; run duvora-agent --ebpf on its host or match it to a Netra node", 404)
            return {"device": device_id, "metrics": {k: d["metrics"][k] for k in MEASURED if k in d["metrics"]},
                    "metrics_source": d.get("metrics_source"), "provider": self.provider(d), **d["ebpf"]}

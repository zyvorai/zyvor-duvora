"""Durable control plane. Hardware observations and simulated intent stay separate."""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import __version__
from .alerts import RESOLVED_RETENTION, AlertsMixin
from .auth import AuthMixin
from .common import Problem, canonical, finite, name
from .ebpf import STAGES, EbpfMixin, replay
from .netra import FLOW_WINDOW
from .history import SAMPLE_RETENTION, HistoryMixin
from .insights import InsightsMixin
from .copilot import CopilotMixin
from .llm import AiMixin
from .reports import ReportsMixin
from .aiassets import AiAssetsMixin
from .aiprotect import AiProtectMixin
from .budget import BudgetMixin, budget_blockers, validate_resources
from .identity import IdentityMixin
from .intel import IntelMixin
from .playbooks import RUN_RETENTION, PlaybooksMixin
from .scanner import ScannerMixin
from .siem import SiemMixin
from .steering import SteeringMixin

__all__ = ["Problem", "Store", "canonical", "finite", "name"]
PLAN_GRACE = 3600
HOUSEKEEPING_INTERVAL = 60
ACTIONS = {"isolate": {"policy", "stage"}, "release": set(), "deploy": {"service", "image", "resources"}, "upgrade": {"firmware"},
           "steer": {"ruleset", "stage"}, "unsteer": set()}


class Store(AuthMixin, HistoryMixin, AlertsMixin, ReportsMixin, EbpfMixin, InsightsMixin, AiMixin, CopilotMixin, SteeringMixin,
            AiProtectMixin, AiAssetsMixin, BudgetMixin, ScannerMixin, IntelMixin, PlaybooksMixin, IdentityMixin, SiemMixin):
    def __init__(self, path, demo=False):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, actor TEXT NOT NULL, body TEXT NOT NULL,
          fingerprint TEXT NOT NULL, expires REAL NOT NULL, job TEXT);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL);
        """)
        self.demo = demo
        self.last_housekeeping = 0.0
        self.init_siem()
        self.init_auth()
        self.init_history()
        self.init_alerts()
        self.init_ebpf()
        self.init_insights()
        self.init_ai()
        self.init_steering()
        self.init_aiprotect()
        self.init_aiassets()
        self.init_scanner()
        self.init_intel()
        self.init_playbooks()
        self.init_identity()
        if demo:
            self.seed()

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def close(self):
        self.db.close()

    def event(self, actor, action, detail):
        row = {"time": time.time(), "actor": actor, "action": action, "detail": detail}
        self.db.execute("INSERT INTO audit(body) VALUES(?)", (canonical(row),))
        self.export_event("audit", row)

    def put(self, table, ident, body):
        assert table in {"devices", "jobs", "policies"}
        self.db.execute(f"INSERT INTO {table}(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (ident, canonical(body)))

    def rows(self, table):
        assert table in {"devices", "jobs", "policies"}
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute(f"SELECT body FROM {table} ORDER BY id")]

    def device(self, ident):
        row = self.db.execute("SELECT body FROM devices WHERE id=?", (ident,)).fetchone()
        if not row:
            raise Problem("Device not found", 404)
        return json.loads(row[0])

    def seed(self):
        with self.transaction():
            if self.db.execute("SELECT count(*) FROM devices").fetchone()[0]:
                return
            for i, (site, host, health) in enumerate([
                ("pune", "gpu-01", "healthy"), ("pune", "gpu-02", "healthy"),
                ("mumbai", "edge-01", "degraded"), ("mumbai", "edge-02", "healthy")
            ], 1):
                ident = f"bf3-{i:02d}"
                self.put("devices", ident, {
                    "id": ident, "model": "BlueField-3 (simulated)", "host": host, "site": site,
                    "source": "simulator", "health": health, "last_seen": time.time(),
                    "version": 1, "firmware": "demo-1.0", "mode": "observe", "services": [],
                    "policy_ids": [],                     "metrics": {"throughput_gbps": 62 + i * 18, "drops": 14 if i == 3 else 0,
                    "temperature_c": 76 if i == 3 else 43 + i, "link_gbps": 200},
                    "capabilities": ["simulation"], "interfaces": ["p0", "p1"],
                    "capacity": {"arm_cores": 16, "memory_gb": 32, "storage_gb": 120},
                    "reserved": {"arm_cores": 2, "memory_gb": 4, "storage_gb": 10}
                })
            self.seed_steering(["bf3-01", "bf3-02"])
            self.event("system", "demo.seed", "Four simulated devices; no physical hardware is controlled")

    def snapshot(self):
        with self.lock:
            devices = self.rows("devices")
            for d in devices:
                if time.time() - d["last_seen"] > 120 and d["source"] != "simulator":
                    d["health"] = "stale"
            native = any(self.native_fresh(d) for d in devices)
            return {"version": __version__, "demo": self.demo, "devices": devices,
                    "open_incidents": self.db.execute("SELECT count(*) FROM incidents WHERE state!='resolved'").fetchone()[0],
                    "policies": self.rows("policies"), "jobs": self.rows("jobs"), "netra": dict(self.netra),
                    "audit": [dict(seq=r["seq"], **json.loads(r["body"])) for r in self.db.execute("SELECT seq,body FROM audit ORDER BY seq DESC LIMIT 200")],
                    "capabilities": {"simulator": "available" if self.demo else "disabled",
                    "linux_discovery": "read-only", "dpf_import": "read-only",
                    "ebpf_telemetry": "native" if native else ("connected" if self.netra["connected"] else "disconnected") if self.netra["configured"] else "unavailable",
                    "hardware_enforcement": ("native-gated" if native else "netra-gated") if self.netra["enforce_allowed"] and (native or self.netra["isolation_supported"]) else "unavailable",
                    "traffic_steering": "native-gated" if any((d.get("ebpf") or {}).get("steer_available") for d in devices) else "simulation" if self.demo else "unavailable",
                    "ai_inspection": "available",
                    "siem_export": "configured" if self.siem else "off",
                    "dpu_offload": "unavailable",
                    "firmware_flash": "unavailable",
                    "storage_offload": "unavailable"}}

    def report(self, actor, report):
        if not isinstance(report, dict) or set(report) - {"id", "model", "host", "site", "source", "firmware", "health", "metrics", "interfaces"}:
            raise Problem("Unknown report fields")
        ident = name(report.get("id"), "device id")
        host = name(report.get("host"), "host")
        # An agent key is bound to a hostname; it cannot impersonate another agent.
        if actor != f"agent:{host}":
            raise Problem("Agent hostname does not match its key", 403)
        source = report.get("source")
        if source not in {"linux-pci", "nvidia-dpf"}:
            raise Problem("Reports must be Linux PCI or DPF observations")
        metrics = report.get("metrics", {})
        if not isinstance(metrics, dict) or set(metrics) - {"throughput_gbps", "drops", "temperature_c", "link_gbps"}:
            raise Problem("Unknown metrics")
        for key, value in metrics.items():
            finite(value, key)
        health = report.get("health", "unknown")
        if health not in {"healthy", "degraded", "unknown"}:
            raise Problem("Invalid observed health")
        for key in ("model", "firmware"):
            if not isinstance(report.get(key, "unknown"), str) or len(report.get(key, "unknown")) > 128:
                raise Problem(f"Invalid {key}")
        interfaces = report.get("interfaces", [])
        if not isinstance(interfaces, list) or len(interfaces) > 32:
            raise Problem("Invalid interface list")
        for iface in interfaces:
            name(iface, "interface")
        site = name(report.get("site", "unassigned"), "site")
        with self.transaction():
            existing = self.db.execute("SELECT body FROM devices WHERE id=?", (ident,)).fetchone()
            old = json.loads(existing[0]) if existing else None
            if old and (old["source"] != source or old["host"] != host):
                raise Problem("Device identity belongs to a different source or host", 409)
            device = {"id": ident, "model": report.get("model", "unknown"), "host": host,
                "site": site, "source": source, "firmware": report.get("firmware", "unknown"),
                "health": health, "metrics": metrics, "interfaces": interfaces,
                "last_seen": time.time(), "version": (old["version"] + 1) if old else 1,
                "mode": "observe", "services": [], "policy_ids": [], "capabilities": ["read-only"]}
            if old and old.get("ebpf"):
                # Netra-measured values and the eBPF probe survive inventory reports.
                device["ebpf"], device["metrics_source"] = old["ebpf"], old.get("metrics_source")
                device["metrics"] = {**{k: v for k, v in old["metrics"].items() if k not in metrics}, **metrics}
                device["capabilities"] = ["read-only", "ebpf"]
                device["mode"], device["policy_ids"] = old["mode"], old["policy_ids"]
                if old.get("netra_isolation"):
                    device["netra_isolation"] = old["netra_isolation"]
            self.put("devices", ident, device)
            self.record_sample(ident, metrics)
            if not old:
                self.event(actor, "device.discovered", {"id": ident, "source": source})
            return device

    def validate_spec(self, spec):
        if not isinstance(spec, dict):
            raise Problem("Plan specification must be an object")
        action = spec.get("action")
        if action not in ACTIONS:
            raise Problem("Action must be isolate, release, deploy, upgrade, steer or unsteer")
        if set(spec) - ({"action", "devices"} | ACTIONS[action]):
            raise Problem("Unknown plan fields")
        targets = spec.get("devices")
        if not isinstance(targets, list) or not 1 <= len(targets) <= 100 or len(set(map(str, targets))) != len(targets):
            raise Problem("Select 1–100 unique devices")
        for ident in targets:
            name(ident, "device id")
        spec = json.loads(canonical(spec))
        if action == "deploy":
            name(spec.get("service"), "service")
            image = spec.get("image", "")
            if not isinstance(image, str) or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]{0,200}@sha256:[a-f0-9]{64}", image):
                raise Problem("Service image must be pinned to a sha256 digest")
            if "resources" in spec:
                spec["resources"] = validate_resources(spec["resources"])
        if action == "steer":
            name(spec.get("ruleset"), "rule set id")
            if spec.setdefault("stage", "shadow") not in STAGES:
                raise Problem("Stage must be shadow or enforce")
        if action == "upgrade":
            name(spec.get("firmware"), "firmware")
        if action == "isolate":
            p = spec.get("policy")
            if not isinstance(p, dict) or set(p) != {"name", "tenant", "cidr", "ports"}:
                raise Problem("Policy requires name, tenant, cidr and ports")
            name(p.get("name"), "policy name")
            name(p.get("tenant"), "tenant")
            try:
                p["cidr"] = str(ipaddress.ip_network(p["cidr"], strict=True))
            except (ValueError, TypeError):
                raise Problem("CIDR must be a canonical IPv4 or IPv6 network") from None
            ports = p["ports"]
            if not isinstance(ports, list) or len(ports) > 64 or any(type(x) is not int or not 1 <= x <= 65535 for x in ports):
                raise Problem("Ports must contain at most 64 integers from 1 to 65535")
            p["ports"] = sorted(set(ports))
            if spec.setdefault("stage", "shadow") not in STAGES:
                raise Problem("Stage must be shadow or enforce")
        return spec

    def fingerprint(self, ids, kind="version"):
        # Agent reports bump versions constantly; eBPF plans only go stale when the isolation or steering they change does.
        kind = {True: "netra", False: "version"}.get(kind, kind)
        state = {"netra": lambda d: [d.get("netra_isolation"), d.get("ebpf", {}).get("node")],
                 "steer": self.steer_fingerprint_state, "version": lambda d: d["version"]}[kind]
        return hashlib.sha256(canonical([(x, state(self.device(x))) for x in sorted(ids)]).encode()).hexdigest()

    @staticmethod
    def fingerprint_kind(p):
        return "steer" if p.get("job_mode") == "steer-native" else "netra" if p.get("netra") else "version"

    def plan(self, actor, spec):
        spec = self.validate_spec(spec)
        with self.transaction():
            devices = [self.device(x) for x in spec["devices"]]
            netra = [d for d in devices if self.netra_node(d)] if spec["action"] not in ("steer", "unsteer") else []
            extra, job_mode = {}, None
            if spec["action"] in ("steer", "unsteer"):
                mode, confirmation, effects, blockers, extra, job_mode = self.steer_plan(spec, devices)
            elif netra:
                mode, confirmation, effects, blockers = self.netra_plan(spec, devices)
                if len(netra) != len(devices):
                    blockers.append("Do not mix Netra-backed devices with other devices in one plan")
            else:
                blockers = []
                for d in devices:
                    if not self.demo or d["source"] != "simulator":
                        blockers.append(f"{d['id']}: hardware mutation adapter is unavailable")
                    if d["health"] not in {"healthy", "degraded"}:
                        blockers.append(f"{d['id']}: device health is unknown")
                if spec.get("stage") == "enforce":
                    blockers.append("Enforcement needs Netra-backed devices; simulated isolation has no stages")
                if spec["action"] == "deploy":
                    blockers += self.image_scan_blockers(spec["image"])
                    for d in devices:
                        blockers += budget_blockers(d, spec["service"], spec.get("resources"))
                mode = "simulation" if all(d["source"] == "simulator" for d in devices) else "hardware-read-only"
                confirmation = "APPLY SIMULATION"
                effects = {"isolate": "Simulate an allow-list policy; default deny within this model only",
                           "release": "Remove all simulated isolation policies from selected devices",
                           "deploy": "Record a simulated running service; no container is launched",
                           "upgrade": "Simulate drain → update → verify; no firmware is flashed; steering bypasses during the upgrade"}[spec["action"]]
            p = {"id": secrets.token_urlsafe(24), "spec": spec, "expires": time.time() + 300, "mode": mode,
                "confirmation": confirmation, "netra": bool(netra),
                "blockers": blockers, "targets": [{"id": d["id"], "host": d["host"], "version": d["version"]} for d in devices],
                "effects": effects, **extra}
            if job_mode:
                p["job_mode"] = job_mode
            if spec["action"] == "isolate":
                shadow = {d["id"]: {**replay(self.netra_flows[d["id"]], spec["policy"]["cidr"], spec["policy"]["ports"]),
                                    "source": "replayed from Netra flow log", "window": FLOW_WINDOW}
                          for d in devices if d["id"] in self.netra_flows}
                if shadow:
                    p["shadow"] = shadow
            self.db.execute("INSERT INTO plans(id,actor,body,fingerprint,expires) VALUES(?,?,?,?,?)",
                            (p["id"], actor, canonical(p), self.fingerprint(spec["devices"], self.fingerprint_kind(p)), p["expires"]))
            self.event(actor, "plan.created", {"id": p["id"], "action": spec["action"], "devices": spec["devices"], "mode": p["mode"]})
            return p

    def apply(self, actor, ident, confirmation):
        with self.transaction():
            row = self.db.execute("SELECT * FROM plans WHERE id=?", (ident,)).fetchone()
            if not row:
                raise Problem("Plan not found", 404)
            # Playbook drafts belong to no person; any administrator may review and apply them.
            if row["actor"] != actor and not row["actor"].startswith("playbook:"):
                raise Problem("Plan belongs to another principal", 403)
            if row["job"]:
                return json.loads(self.db.execute("SELECT body FROM jobs WHERE id=?", (row["job"],)).fetchone()[0])
            p = json.loads(row["body"])
            expected = p.get("confirmation", "APPLY SIMULATION")
            if confirmation != expected:
                raise Problem(f"Explicit confirmation must be {expected}")
            if p.get("job_mode") == "steer-native":
                if p["spec"].get("stage") == "enforce" and p["spec"]["action"] == "steer":
                    if not self.netra.get("enforce_allowed"):
                        raise Problem("Enforcement is disabled on this server", 409)
                    if self.killed():
                        raise Problem("The kill switch is engaged", 409)
            elif p.get("netra"):
                if p["spec"].get("stage") == "enforce" and p["spec"]["action"] == "isolate":
                    if not self.netra.get("enforce_allowed"):
                        raise Problem("Enforcement is disabled on this server", 409)
                    if self.killed():
                        raise Problem("The kill switch is engaged", 409)
                if not self.netra_client and any(self.provider(self.device(x)) == "netra" for x in p["spec"]["devices"]):
                    raise Problem("Netra is not configured", 409)
            elif not self.demo:
                raise Problem("Simulation is disabled in this server", 409)
            if row["expires"] < time.time():
                raise Problem("Plan expired; create a fresh preview", 409)
            if p["blockers"]:
                raise Problem("Plan blocked: " + "; ".join(p["blockers"]), 409)
            if self.fingerprint(p["spec"]["devices"], self.fingerprint_kind(p)) != row["fingerprint"]:
                raise Problem("Device state changed; create a fresh preview", 409)
            job = {"id": secrets.token_hex(12), "plan_id": ident, "state": "queued", "step": 0,
                "mode": p.get("job_mode") or ("netra" if p.get("netra") else "simulation"), "action": p["spec"]["action"], "spec": p["spec"], "created": time.time(),
                "actor": actor, "before": [self.device(x) for x in p["spec"]["devices"]],
                "policies_before": [x for x in self.rows("policies") if set(x["devices"]) & set(p["spec"]["devices"])], "events": []}
            if p["spec"]["action"] in ("steer", "unsteer"):
                job["steering"] = p.get("steering")
                job["steering_before"] = {x: self.applied_rules(x) for x in p["spec"]["devices"] if self.applied_rules(x)}
            # Prevent competing plans from starting against the same device.
            for active in self.rows("jobs"):
                if active["state"] in {"queued", "running"} and set(active["spec"]["devices"]) & set(job["spec"]["devices"]):
                    raise Problem("A selected device already has an active job", 409)
            self.put("jobs", job["id"], job)
            self.db.execute("UPDATE plans SET job=? WHERE id=?", (job["id"], ident))
            self.event(actor, "job.queued", {"id": job["id"], "action": job["action"], "mode": job["mode"]})
            if job["mode"] in ("netra", "steer-native"):
                self.netra_wake.set()
            return job

    def tick(self):
        if not self.demo:
            return
        with self.transaction():
            for job in self.rows("jobs"):
                if job["state"] not in {"queued", "running"} or job.get("mode", "simulation") != "simulation":
                    continue
                job["state"] = "running"
                steps = ["preflight", "drain", "update", "verify"] if job["action"] == "upgrade" else ["preflight", "reconcile", "verify"]
                job["events"].append({"time": time.time(), "step": steps[job["step"]], "message": "Simulator completed this step"})
                if job["action"] == "upgrade" and steps[job["step"]] == "drain":
                    # Like a DPU firewall upgrade: steering bypasses while the device is drained. No version bump, so rollback still applies.
                    for ident in job["spec"]["devices"]:
                        d = self.device(ident)
                        s = d.get("steering")
                        if s and not (s.get("bypass") or {}).get("engaged"):
                            s["bypass"] = {"engaged": True, "reason": "upgrade", "since": time.time(), "by": "reconciler", "job": job["id"]}
                            self.put("devices", ident, d)
                            self.event("reconciler", "steering.bypass-engaged", {"device": ident, "reason": "upgrade", "job": job["id"]})
                job["step"] += 1
                if job["step"] == len(steps):
                    spec = job["spec"]
                    if job["action"] == "isolate":
                        policy = {"id": job["id"], **spec["policy"], "devices": spec["devices"], "mode": "simulation", "created": time.time()}
                        self.put("policies", policy["id"], policy)
                    for ident in spec["devices"]:
                        d = self.device(ident)
                        if job["action"] == "isolate":
                            d["mode"] = "isolated"
                            d["policy_ids"].append(job["id"])
                        elif job["action"] == "release":
                            for pid in d["policy_ids"]:
                                policyrow = self.db.execute("SELECT body FROM policies WHERE id=?", (pid,)).fetchone()
                                if policyrow:
                                    policy = json.loads(policyrow[0])
                                    policy["devices"] = [x for x in policy["devices"] if x != ident]
                                    if policy["devices"]:
                                        self.put("policies", pid, policy)
                                    else:
                                        self.db.execute("DELETE FROM policies WHERE id=?", (pid,))
                            d["policy_ids"] = []
                            d["mode"] = "observe"
                        elif job["action"] == "deploy":
                            service = {"name": spec["service"], "image": spec["image"], "state": "simulated-running"}
                            if spec.get("resources"):
                                service["resources"] = spec["resources"]
                            d["services"] = [x for x in d["services"] if x["name"] != spec["service"]] + [service]
                        elif job["action"] in ("steer", "unsteer"):
                            self.steer_sim_complete(d, job)
                        else:
                            d["firmware"] = spec["firmware"]
                            b = (d.get("steering") or {}).get("bypass") or {}
                            if b.get("engaged") and b.get("reason") == "upgrade":
                                d["steering"]["bypass"] = {"engaged": False}
                                self.event("reconciler", "steering.bypass-released", {"device": ident, "reason": "upgrade complete", "job": job["id"]})
                        d["version"] += 1
                        self.put("devices", ident, d)
                    job["state"] = "succeeded"
                    self.event("reconciler", "job.succeeded", {"id": job["id"], "mode": "simulation"})
                self.put("jobs", job["id"], job)

    def rollback(self, actor, ident):
        with self.transaction():
            row = self.db.execute("SELECT body FROM jobs WHERE id=?", (ident,)).fetchone()
            if not row:
                raise Problem("Job not found", 404)
            job = json.loads(row[0])
            if job["state"] == "rolled-back":
                return job
            if job["state"] != "succeeded":
                raise Problem("Only succeeded jobs can be rolled back", 409)
        if job.get("mode") == "netra":
            return self.netra_rollback(actor, job)
        if job.get("mode") == "steer-native" or job["action"] in ("steer", "unsteer"):
            return self.steer_rollback(actor, job)
        with self.transaction():
            for d in job["before"]:
                current = self.device(d["id"])
                if current["version"] != d["version"] + 1:
                    raise Problem("Later changes exist; roll those back first", 409)
                if any(j["state"] in {"queued", "running"} and d["id"] in j["spec"]["devices"] for j in self.rows("jobs")):
                    raise Problem("Device has an active job", 409)
            # Restore desired state but keep monotonic revisions to invalidate old plans.
            for d in job["before"]:
                d["version"] = self.device(d["id"])["version"] + 1
                self.put("devices", d["id"], d)
            if job["action"] == "isolate":
                self.db.execute("DELETE FROM policies WHERE id=?", (ident,))
            if job["action"] == "release":
                # Restore membership only for this job’s targets; preserve changes elsewhere.
                for policy in job.get("policies_before", []):
                    row = self.db.execute("SELECT body FROM policies WHERE id=?", (policy["id"],)).fetchone()
                    targets = set(job["spec"]["devices"])
                    current = json.loads(row[0]) if row else dict(policy, devices=[])
                    current["devices"] = sorted(set(current["devices"]) | (set(policy["devices"]) & targets))
                    self.put("policies", current["id"], current)
            job["state"] = "rolled-back"
            self.put("jobs", ident, job)
            self.event(actor, "job.rolled-back", {"id": ident, "mode": "simulation"})
            return job

    def evaluate(self, device_id, address, port):
        try:
            address = ipaddress.ip_address(address)
        except ValueError:
            raise Problem("Invalid destination IP") from None
        if type(port) is not int or not 1 <= port <= 65535:
            raise Problem("Invalid destination port")
        with self.lock:
            d = self.device(device_id)
            if d["source"] != "simulator":
                raise Problem("Policy evaluation is available only for simulated devices", 409)
            policies = [p for p in self.rows("policies") if device_id in p["devices"]]
            matches = [p["name"] for p in policies if address in ipaddress.ip_network(p["cidr"]) and (not p["ports"] or port in p["ports"])]
            return {"mode": "simulation", "verdict": "allow" if not policies or matches else "deny", "matched": matches,
                    "hardware_enforced": False, "note": "Model evaluation only; no real packet is filtered"}

    def maintain(self, now=None):
        """Background work besides reconciliation: demo sampling, alert evaluation, retention."""
        now = now or time.time()
        self.simulate_metrics(now)
        self.simulate_steering(now)
        self.evaluate_alerts(now)
        self.persist_destinations(now)
        self.maybe_refresh_intel(now)
        self.flush_siem()
        if now - self.last_housekeeping >= HOUSEKEEPING_INTERVAL:
            self.simulate_assets(now)
            self.housekeeping(now)

    def extra_conditions(self):
        """Alert rule kinds implemented outside alerts.py: {kind: fn(rule, now, firing)}."""
        return {**self.steering_conditions(), **self.aiprotect_conditions(), **self.aiassets_conditions(),
                **self.intel_conditions(), **self.scanner_conditions(), **self.identity_conditions()}

    def housekeeping(self, now=None):
        now = now or time.time()
        self.last_housekeeping = now
        days = int(os.environ.get("DUVORA_AUDIT_RETENTION_DAYS", "90") or 90)
        with self.transaction():
            removed = {
                "plans": self.db.execute("DELETE FROM plans WHERE job IS NULL AND expires<?", (now - PLAN_GRACE,)).rowcount,
                "audit": self.db.execute("DELETE FROM audit WHERE json_extract(body,'$.time')<?", (now - max(days, 1) * 86400,)).rowcount,
                "samples": self.db.execute("DELETE FROM samples WHERE ts<?", (now - SAMPLE_RETENTION,)).rowcount,
                "incidents": self.db.execute("DELETE FROM incidents WHERE state='resolved' AND opened<?", (now - RESOLVED_RETENTION,)).rowcount,
                "sessions": self.db.execute("DELETE FROM sessions WHERE expires<?", (now,)).rowcount,
                "verdicts": self.prune_verdicts(now),
                "ai": self.prune_ai(now) + self.prune_assets(now),
                "agent_tokens": self.prune_identity(now),
                "playbook_runs": self.db.execute("DELETE FROM playbook_runs WHERE created<?", (now - RUN_RETENTION,)).rowcount,
                "playbook_rule_sets": self.prune_playbook_sets(now),
            }
            if any(removed.values()):
                self.event("system", "housekeeping", removed)
            return removed

    def backup(self, actor):
        """Consistent copy of the whole database via SQLite's online backup API."""
        with self.lock:
            target = sqlite3.connect(":memory:")
            try:
                self.db.backup(target)
                data = target.serialize()
            finally:
                target.close()
            with self.transaction():
                self.event(actor, "backup.created", {"bytes": len(data)})
        return data

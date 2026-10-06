"""The agent's native eBPF loop: report counters, pull desired isolation, apply it with local safety.

Safety is local and does not depend on the control plane:
  - enforce falls back to shadow when the lease in the desired state has lapsed;
  - enforce falls back to shadow when the control plane has been unreachable for `failsafe` seconds;
  - an override file on the host (DUVORA_EBPF_OVERRIDE) turns isolation off entirely.

Steering (duvora_steer) follows the same rules, with its own override file (DUVORA_STEER_OVERRIDE)."""
import hashlib
import json
import os
import time
from urllib.parse import urlsplit

from .nodeiso import build_rules, resolve_controller

OVERRIDE = "/run/duvora/isolation-off"
STEER_OVERRIDE = "/run/duvora/steering-off"
ASSET_INTERVAL = 300


def failsafe_seconds():
    try:
        return min(3600, max(15, int(os.environ.get("DUVORA_EBPF_FAILSAFE", "60"))))
    except ValueError:
        return 60


def decide(desired, now, last_contact, failsafe, override=False):
    """(effective mode, demoted reason) for a desired isolation (or None)."""
    if not desired or desired.get("mode") not in {"shadow", "enforce"}:
        return "off", ""
    if override:
        return "off", "local override"
    if desired["mode"] == "enforce":
        lease = desired.get("leaseUntil")
        if not isinstance(lease, (int, float)) or now >= lease:
            return "shadow", "lease expired"
        if last_contact is None or now - last_contact > failsafe:
            return "shadow", "control plane unreachable"
    return desired["mode"], ""


class EbpfAgent:
    def __init__(self, host, url, call, sensors, isolation=None, isolation_error="", failsafe=None, override_path=None,
                 steering=None, steering_error="", steer_override_path=None, discover_assets=None):
        """`call(method, path, body)` talks to the control plane; `isolation` is a NodeIsolation, `steering` a Steering, or None."""
        self.host, self.url, self.call = host, url, call
        self.sensors, self.isolation, self.isolation_error = sensors, isolation, isolation_error
        self.steering, self.steering_error = steering, steering_error
        self.failsafe = failsafe or failsafe_seconds()
        self.override_path = override_path or os.environ.get("DUVORA_EBPF_OVERRIDE") or OVERRIDE
        self.steer_override_path = steer_override_path or os.environ.get("DUVORA_STEER_OVERRIDE") or STEER_OVERRIDE
        self.desired, self.last_contact, self.server_controller = None, None, []
        self.steer_desired, self.steer_supported = None, True
        self.controller = resolve_controller(urlsplit(url).hostname or "")
        self.applied = {"key": None, "mode": "off", "revision": None, "demoted": ""}
        self.steer_applied = {"key": None, "mode": "off", "revision": None, "demoted": "", "rules": []}
        self.discover_assets, self.last_assets = discover_assets, 0.0
        self.errors = []

    def steering_status(self, now):
        """Steering counters, rule hits, flow verdicts and payload analyses for this interval, or None."""
        d, a = self.steer_desired or {}, self.steer_applied
        if self.steering is None and not self.steering_error:
            return None, []
        status = {"attached": self.steering is not None, "unavailable": self.steering_error, "rulesetId": d.get("rulesetId"),
                  "mode": d.get("mode") or "off", "effectiveMode": a["mode"], "revision": d.get("revision"),
                  "appliedRevision": a["revision"], "demoted": a["demoted"], "bypass": bool(d.get("bypass")) and a["mode"] != "off",
                  "stats": {}, "rules": [], "verdicts": []}
        inspections = []
        if self.steering is None:
            return status, inspections
        from .. import inspection
        status["stats"] = self.steering.stats()
        status["rules"] = self.steering.rule_counters()
        names = [r.get("name") for r in a["rules"]]
        rule_name = lambda i: names[i] if 0 <= i < len(names) else "(default)"
        for f in self.steering.drain_flows():
            status["verdicts"].append({**{k: f[k] for k in ("direction", "src", "dst", "protocol", "sport", "dport", "action", "packets", "bytes")},
                                       "rule": rule_name(f["rule_index"])})
        for flow, data in self.steering.drain_payloads():
            record = inspection.analyze(data, flow)
            record["rule"] = rule_name(flow["rule_index"])
            inspections.append(record)
        return status, inspections

    def status(self):
        """Isolation status in the shape of a Netra node-isolation item, or None if there is nothing to show."""
        d, a = self.desired or {}, self.applied
        if not d and a["mode"] == "off" and not self.isolation_error:
            return None
        item = {"policyId": d.get("policyId"), "mode": d.get("mode") or "off", "effectiveMode": a["mode"],
                "revision": d.get("revision"), "appliedRevision": a["revision"], "leaseUntil": d.get("leaseUntil"),
                "demoted": a["demoted"], "agentStale": False, "unavailable": self.isolation_error,
                "attached": self.isolation is not None}
        stats = self.isolation.stats() if self.isolation else {}
        for key, name in (("allowed", "allowedPackets"), ("exempt", "exemptPackets"), ("would_block", "wouldBlockPackets"),
                          ("would_block_bytes", "wouldBlockBytes"), ("blocked", "blockedPackets"), ("blocked_bytes", "blockedBytes")):
            item[name] = stats.get(key, 0)
        item["top"] = stats.get("top", [])
        return item

    def report(self, now):
        summary = self.sensors.snapshot(self.host, now)
        summary["nodeiso_available"] = self.isolation is not None
        summary["isolation"] = self.status()
        steering, inspections = self.steering_status(now)
        if steering is not None:
            summary["steering"] = steering
        if inspections:
            summary["inspections"] = inspections[:100]
        if self.discover_assets and now - self.last_assets >= ASSET_INTERVAL:
            self.last_assets = now
            summary["ai_assets"] = self.discover_assets()
        summary["errors"] = self.errors[-5:]
        self.call("POST", "/api/v1/agent/ebpf", {"host": self.host, "summary": summary})
        self.errors = []

    def pull(self, now):
        out = self.call("GET", "/api/v1/agent/isolation", None)
        self.desired = out.get("isolation") if isinstance(out, dict) else None
        self.server_controller = [a for a in (out.get("controller") or []) if isinstance(a, str)] if isinstance(out, dict) else []
        self.last_contact = now

    def pull_steering(self, now):
        if self.steering is None or not self.steer_supported:
            return
        try:
            out = self.call("GET", "/api/v1/agent/steering", None)
        except OSError as exc:
            if "404" in str(exc):
                self.steer_supported = False  # an older control plane
                return
            raise
        self.steer_desired = out.get("steering") if isinstance(out, dict) else None
        if isinstance(out, dict):
            self.server_controller = sorted(set(self.server_controller) | {a for a in (out.get("controller") or []) if isinstance(a, str)})

    def apply_steering(self, now):
        if self.steering is None:
            return
        d = self.steer_desired
        mode, why = decide(d, now, self.last_contact, self.failsafe, os.path.exists(self.steer_override_path))
        rules = (d or {}).get("rules") or [] if mode != "off" else []
        default = (d or {}).get("default", "bypass")
        bypass = bool((d or {}).get("bypass"))
        controller = sorted(set(self.controller) | set(self.server_controller))
        key = hashlib.sha256(json.dumps([mode, rules, default, bypass, controller], sort_keys=True).encode()).hexdigest()
        if key != self.steer_applied["key"]:
            parts = urlsplit(self.url)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            self.steering.apply(mode, rules, default, bypass, controller, controller_ports=(port,))
        self.steer_applied = {"key": key, "mode": mode, "demoted": why, "rules": rules,
                              "revision": (d or {}).get("revision") if mode != "off" else None}

    def apply(self, now):
        mode, why = decide(self.desired, now, self.last_contact, self.failsafe, os.path.exists(self.override_path))
        if self.isolation is None:
            return
        rules = (self.desired or {}).get("rules") or [] if mode != "off" else []
        controller = sorted(set(self.controller) | set(self.server_controller))
        key = hashlib.sha256(json.dumps([mode, rules, controller], sort_keys=True).encode()).hexdigest()
        if key != self.applied["key"]:
            self.isolation.apply(mode, build_rules(rules, controller) if mode != "off" else [])
        self.applied = {"key": key, "mode": mode, "demoted": why,
                        "revision": (self.desired or {}).get("revision") if mode != "off" else None}

    def step(self, now=None):
        """One interval. Each phase fails independently; apply always runs so local safety holds."""
        now = now or time.time()
        fresh = resolve_controller(urlsplit(self.url).hostname or "")
        if fresh:
            self.controller = fresh
        for phase in (self.report, self.pull, self.pull_steering):
            try:
                phase(now)
            except Exception as exc:  # network, HTTP or map errors; keep going
                self.errors.append(f"{phase.__name__}: {exc}"[:300])
        for phase in (self.apply, self.apply_steering):
            try:
                phase(now)
            except Exception as exc:
                self.errors.append(f"{phase.__name__}: {exc}"[:300])
        self.errors = self.errors[-20:]
        return self.applied

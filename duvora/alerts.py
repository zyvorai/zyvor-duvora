"""Alert rules evaluated against the fleet; one incident per rule and target."""
import json
import secrets
import time

from .common import Problem, canonical, finite

SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_rules(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, key TEXT NOT NULL, state TEXT NOT NULL, opened REAL NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS incidents_state ON incidents(state, key);
"""
SEVERITIES = ("info", "warning", "critical")
DEFAULT_RULES = [
    {"id": "temperature-high", "name": "Temperature above threshold", "kind": "metric", "metric": "temperature_c", "threshold": 80, "severity": "warning", "enabled": True},
    {"id": "packet-drops", "name": "Packet drops reported", "kind": "metric", "metric": "drops", "threshold": 0, "severity": "info", "enabled": True},
    {"id": "health-degraded", "name": "Device health degraded", "kind": "health", "severity": "warning", "enabled": True},
    {"id": "device-stale", "name": "Observation is stale", "kind": "stale", "threshold": 120, "severity": "critical", "enabled": True},
    {"id": "job-failed", "name": "Operation failed", "kind": "job", "severity": "critical", "enabled": True},
    {"id": "tcp-retransmits", "name": "TCP retransmits per minute above threshold", "kind": "metric", "metric": "tcp_retransmits_pm", "threshold": 100, "severity": "warning", "enabled": True},
    {"id": "tcp-resets", "name": "TCP resets per minute above threshold", "kind": "metric", "metric": "tcp_resets_pm", "threshold": 50, "severity": "warning", "enabled": True},
    {"id": "ebpf-detached", "name": "eBPF sensor detached or stale", "kind": "ebpf", "severity": "warning", "enabled": True},
    {"id": "isolation-would-block", "name": "Shadow isolation would block traffic", "kind": "isolation", "severity": "info", "enabled": True},
    {"id": "isolation-blocked", "name": "Enforced isolation is dropping traffic", "kind": "isolation-enforce", "severity": "warning", "enabled": True},
    {"id": "anomaly", "name": "Metric deviates from its learned baseline (z-score)", "kind": "anomaly", "threshold": 4, "severity": "warning", "enabled": True},
    {"id": "new-destination", "name": "New egress destination", "kind": "new-destination", "severity": "info", "enabled": True},
    {"id": "forecast-breach", "name": "Forecast crosses a threshold within N hours", "kind": "forecast", "threshold": 6, "severity": "warning", "enabled": True},
    {"id": "steering-bypass", "name": "Steering in bypass longer than N minutes", "kind": "steering-bypass", "threshold": 10, "severity": "warning", "enabled": True},
    {"id": "steering-drop", "name": "Enforced steering is dropping traffic", "kind": "steering-drop", "severity": "warning", "enabled": True},
    {"id": "steering-would-drop", "name": "Shadow steering would drop traffic", "kind": "steering-would-drop", "severity": "info", "enabled": True},
    {"id": "llm-prompt-injection", "name": "Prompt injection in LLM traffic", "kind": "llm-prompt-injection", "severity": "critical", "enabled": True},
    {"id": "llm-secret-leak", "name": "Secret sent to an LLM endpoint", "kind": "llm-secret-leak", "severity": "critical", "enabled": True},
    {"id": "llm-sensitive-data", "name": "Sensitive data sent to an LLM endpoint", "kind": "llm-sensitive-data", "severity": "warning", "enabled": True},
    {"id": "llm-new-endpoint", "name": "New LLM endpoint contacted", "kind": "llm-new-endpoint", "severity": "info", "enabled": True},
    {"id": "unsanctioned-ai", "name": "Unsanctioned AI runtime on a node", "kind": "unsanctioned-ai", "severity": "warning", "enabled": True},
    {"id": "intel-match", "name": "Traffic to or from a threat-intel indicator", "kind": "intel-match", "severity": "critical", "enabled": True},
    {"id": "scan-failed", "name": "Artifact scan failed", "kind": "scan-failed", "severity": "warning", "enabled": True},
    {"id": "agent-identity-stale", "name": "Agent token not rotated in N hours", "kind": "agent-identity-stale", "threshold": 2, "severity": "warning", "enabled": True},
    {"id": "agent-identity-unknown", "name": "Unknown agent identity attempted to report", "kind": "agent-identity-unknown", "severity": "warning", "enabled": True},
]
ALERT_INTERVAL = 5
RESOLVED_RETENTION = 30 * 86400


class AlertsMixin:
    def init_alerts(self):
        self.db.executescript(SCHEMA)
        self.last_alert = 0.0
        with self.transaction():
            for rule in DEFAULT_RULES:
                self.db.execute("INSERT OR IGNORE INTO alert_rules VALUES(?,?)", (rule["id"], canonical(rule)))

    def alert_rules(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM alert_rules ORDER BY id")]

    def update_rule(self, actor, ident, body):
        if not isinstance(body, dict) or not body or set(body) - {"enabled", "threshold", "severity"}:
            raise Problem("Rule updates may change enabled, threshold or severity")
        with self.transaction():
            row = self.db.execute("SELECT body FROM alert_rules WHERE id=?", (ident,)).fetchone()
            if not row:
                raise Problem("Alert rule not found", 404)
            rule = json.loads(row[0])
            if "enabled" in body:
                if not isinstance(body["enabled"], bool):
                    raise Problem("enabled must be true or false")
                rule["enabled"] = body["enabled"]
            if "severity" in body:
                if body["severity"] not in SEVERITIES:
                    raise Problem("Severity must be info, warning or critical")
                rule["severity"] = body["severity"]
            if "threshold" in body:
                if "threshold" not in rule:
                    raise Problem("This rule has no threshold")
                rule["threshold"] = finite(body["threshold"], "threshold", 0, 1e9)
            self.db.execute("UPDATE alert_rules SET body=? WHERE id=?", (canonical(rule), ident))
            self.event(actor, "alert-rule.updated", {"id": ident, "fields": sorted(body)})
            return rule

    def conditions(self, now):
        """Return {key: (rule, target, title, detail)} for every currently firing rule."""
        firing = {}
        devices = self.rows("devices")
        extra = self.extra_conditions() if hasattr(self, "extra_conditions") else {}
        for rule in self.alert_rules():
            if not rule["enabled"]:
                continue
            if rule["kind"] in extra:
                extra[rule["kind"]](rule, now, firing)
                continue
            if rule["kind"] == "job":
                for job in self.rows("jobs"):
                    if job["state"] == "failed":
                        firing[f"{rule['id']}:{job['id']}"] = (rule, job["id"], f"{job['action']} job failed", f"Job {job['id']}")
                continue
            if rule["kind"] == "anomaly":
                for a in self.anomalies(threshold=rule["threshold"]):
                    firing[f"{rule['id']}:{a['device']}:{a['metric']}"] = (
                        rule, a["device"], f"{a['metric']} anomaly on {a['device']}",
                        f"{a['metric']} = {a['value']} vs baseline {a['baseline']} ± {a['std']} (z {a['z']})")
                continue
            if rule["kind"] == "new-destination":
                found = {}
                for x in self.new_destinations(now=now):
                    found.setdefault(x["device"], []).append(x)
                for dev, items in found.items():
                    shown = ", ".join(f"{x['peer']}:{x['port']}/{x['protocol']}" for x in items[:3])
                    firing[f"{rule['id']}:{dev}"] = (rule, dev, f"New egress destination on {dev}",
                                                     f"{len(items)} new in the last 15 minutes: {shown}")
                continue
            if rule["kind"] == "forecast":
                for f in self.forecast_breaches(rule["threshold"], now):
                    firing[f"{rule['id']}:{f['device']}:{f['metric']}"] = (
                        rule, f["device"], f"{f['metric']} forecast to cross {f['threshold']} on {f['device']}",
                        f"{f['metric']} {f['current']} rising {f['slope_per_hour']}/h; crosses {f['threshold']} in about {f['eta_hours']} h (R² {f['r2']})")
                continue
            for d in devices:
                hit = None
                if rule["kind"] == "metric":
                    value = d["metrics"].get(rule["metric"])
                    if value is not None and value > rule["threshold"]:
                        hit = f"{rule['metric']} = {value} (threshold {rule['threshold']})"
                        reasons = d.get("ebpf", {}).get("drop_reasons") if rule["metric"] == "drops" else None
                        if reasons:
                            hit += f"; top kernel reason {reasons[0]['reason']} ({reasons[0]['count']})"
                elif rule["kind"] == "ebpf" and d.get("ebpf"):
                    e = d["ebpf"]
                    if e.get("stale"):
                        hit = f"eBPF sensor on {e['node']} is stale ({e.get('age', 0)} s)"
                    elif e.get("program_count") and not e.get("attached"):
                        hit = f"No eBPF programs attached on {e['node']}"
                elif rule["kind"] == "isolation" and (d.get("ebpf", {}).get("isolation") or {}).get("mode") == "shadow":
                    iso = d["ebpf"]["isolation"]
                    if iso.get("would_block_delta"):
                        top = iso.get("top") or []
                        hit = f"{iso['would_block_delta']} packets would have been blocked in the last interval" + (
                            f"; top {top[0].get('address') or top[0].get('destination') or top[0].get('peer')}:{top[0].get('port')}" if top else "")
                elif rule["kind"] == "isolation-enforce" and (d.get("ebpf", {}).get("isolation") or {}).get("mode") == "enforce":
                    iso = d["ebpf"]["isolation"]
                    if iso.get("blocked_delta"):
                        top = iso.get("top") or []
                        hit = f"{iso['blocked_delta']} packets dropped by enforced isolation in the last interval" + (
                            f"; top {top[0].get('address') or top[0].get('destination')}:{top[0].get('port')}" if top else "")
                elif rule["kind"] == "health" and d["health"] == "degraded":
                    hit = "Source reports degraded health"
                elif rule["kind"] == "stale" and d["source"] != "simulator" and now - d["last_seen"] > rule["threshold"]:
                    hit = f"No report for {int(now - d['last_seen'])} s"
                if hit:
                    firing[f"{rule['id']}:{d['id']}"] = (rule, d["id"], f"{rule['name']} on {d['id']}", hit)
        return firing

    def evaluate_alerts(self, now=None, force=False):
        now = now or time.time()
        if not force and now - self.last_alert < ALERT_INTERVAL:
            return
        self.last_alert = now
        opened = []
        with self.transaction():
            firing = self.conditions(now)
            active = {r["key"]: json.loads(r["body"]) for r in self.db.execute("SELECT key, body FROM incidents WHERE state!='resolved'")}
            for key, (rule, target, title, detail) in firing.items():
                if key in active:
                    inc = active[key]
                    if inc["detail"] != detail:
                        inc.update(detail=detail, updated=now)
                        self.db.execute("UPDATE incidents SET body=? WHERE id=?", (canonical(inc), inc["id"]))
                    continue
                inc = {"id": secrets.token_hex(8), "key": key, "rule": rule["id"], "target": target, "severity": rule["severity"],
                       "title": title, "detail": detail, "state": "open", "opened": now, "updated": now,
                       "acknowledged_by": None, "resolved_at": None, "resolved_by": None}
                self.db.execute("INSERT INTO incidents VALUES(?,?,?,?,?)", (inc["id"], key, "open", now, canonical(inc)))
                self.event("alerts", "incident.opened", {"id": inc["id"], "rule": rule["id"], "target": target, "severity": rule["severity"]})
                opened.append(inc)
            for key, inc in active.items():
                if key not in firing:
                    self._resolve(inc, "alerts", now)
        if opened and hasattr(self, "on_incidents_opened"):
            self.on_incidents_opened(opened)

    def _resolve(self, inc, actor, now):
        inc.update(state="resolved", resolved_at=now, resolved_by=actor, updated=now)
        self.db.execute("UPDATE incidents SET state='resolved', body=? WHERE id=?", (canonical(inc), inc["id"]))
        self.event(actor, "incident.resolved", {"id": inc["id"], "rule": inc["rule"], "target": inc["target"]})

    def incidents(self, state=None):
        if state not in (None, "open", "acknowledged", "resolved", "active"):
            raise Problem("State must be open, acknowledged, resolved or active")
        with self.lock:
            if state == "active":
                rows = self.db.execute("SELECT body FROM incidents WHERE state!='resolved' ORDER BY opened DESC")
            elif state:
                rows = self.db.execute("SELECT body FROM incidents WHERE state=? ORDER BY opened DESC LIMIT 500", (state,))
            else:
                rows = self.db.execute("SELECT body FROM incidents ORDER BY opened DESC LIMIT 500")
            return [json.loads(r[0]) for r in rows]

    def incident_action(self, actor, ident, action):
        with self.transaction():
            row = self.db.execute("SELECT body FROM incidents WHERE id=?", (ident,)).fetchone()
            if not row:
                raise Problem("Incident not found", 404)
            inc = json.loads(row[0])
            if inc["state"] == "resolved":
                return inc
            now = time.time()
            if action == "ack":
                if inc["state"] != "acknowledged":
                    inc.update(state="acknowledged", acknowledged_by=actor, updated=now)
                    self.db.execute("UPDATE incidents SET state='acknowledged', body=? WHERE id=?", (canonical(inc), ident))
                    self.event(actor, "incident.acknowledged", {"id": ident})
            elif action == "resolve":
                self._resolve(inc, actor, now)
            else:
                raise Problem("Endpoint not found", 404)
            return inc

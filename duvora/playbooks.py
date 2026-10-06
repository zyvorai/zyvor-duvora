"""Response playbooks: when an incident opens, run ordered steps that only prepare a response —
explain it, draft a steering plan that drops the offending peer, preview bypass, notify a webhook.

Playbooks never apply anything. Drafted plans wait for an administrator to review them and type the
confirmation, with every normal gate (shadow before enforce, enforcement switch, kill switch, lease)."""
import hashlib
import json
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .common import Problem, canonical, name
from .netra import LOOPBACK, NoRedirect

SCHEMA = """
CREATE TABLE IF NOT EXISTS playbooks(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS playbook_runs(id TEXT PRIMARY KEY, incident TEXT, created REAL NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS playbook_runs_incident ON playbook_runs(incident);
"""
STEP_TYPES = ("explain", "draft_block", "draft_bypass", "notify")
RUN_RETENTION = 30 * 86400
DEFAULT_PLAYBOOKS = [
    {"id": "llm-threat", "name": "LLM threat: explain and draft a block", "enabled": True,
     "match": {"rules": ["llm-prompt-injection", "llm-secret-leak"], "min_severity": "warning"},
     "steps": [{"type": "explain"}, {"type": "draft_block"}, {"type": "notify"}]},
    {"id": "intel-match", "name": "Threat-intel hit: draft a block", "enabled": True,
     "match": {"rules": ["intel-match"], "min_severity": "info"},
     "steps": [{"type": "explain"}, {"type": "draft_block"}, {"type": "notify"}]},
    {"id": "steering-drops", "name": "Enforced steering drops: preview bypass", "enabled": False,
     "match": {"rules": ["steering-drop"], "min_severity": "warning"},
     "steps": [{"type": "explain"}, {"type": "draft_bypass"}, {"type": "notify"}]},
]
RANK = {"info": 0, "warning": 1, "critical": 2}
FINDING_RULES = {"llm-prompt-injection": "prompt-injection", "llm-secret-leak": "secret", "llm-sensitive-data": "pii"}
PEER = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


def validate_playbook(ident, body):
    name(ident, "playbook id")
    if not isinstance(body, dict) or set(body) - {"name", "enabled", "match", "steps"}:
        raise Problem("A playbook has name, enabled, match and steps")
    label = body.get("name", ident)
    if not isinstance(label, str) or not 1 <= len(label) <= 100:
        raise Problem("name must be 1–100 characters")
    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        raise Problem("enabled must be true or false")
    match = body.get("match") or {}
    if not isinstance(match, dict) or set(match) - {"rules", "min_severity"}:
        raise Problem("match has rules and min_severity")
    rules = match.get("rules", [])
    if not isinstance(rules, list) or not 1 <= len(rules) <= 30:
        raise Problem("match.rules must list 1–30 alert rule ids")
    for r in rules:
        name(r, "alert rule id")
    if match.get("min_severity", "info") not in RANK:
        raise Problem("min_severity must be info, warning or critical")
    steps = body.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 10:
        raise Problem("steps must list 1–10 steps")
    clean = []
    for s in steps:
        if not isinstance(s, dict) or s.get("type") not in STEP_TYPES or set(s) - {"type", "url", "ruleset"}:
            raise Problem(f"Each step has a type ({', '.join(STEP_TYPES)}) and, for notify, an optional https url")
        if s.get("url"):
            parts = urlsplit(s["url"]) if isinstance(s["url"], str) else None
            if not parts or parts.scheme != "https" and parts.hostname not in LOOPBACK or not parts.hostname or parts.username:
                raise Problem("notify url must be https (or loopback) without credentials")
        clean.append({k: s[k] for k in ("type", "url") if s.get(k)})
    return {"id": ident, "name": label, "enabled": enabled, "match": {"rules": sorted(set(rules)), "min_severity": match.get("min_severity", "info")},
            "steps": clean}


def incident_peer(inc):
    """(address, port) named in an incident's detail, for draft_block."""
    m = PEER.search(inc.get("detail") or "")
    if not m:
        return None, None
    port = int(m.group(2)) if m.group(2) and 1 <= int(m.group(2)) <= 65535 else None
    return m.group(1), port


def post_json(url, payload, timeout=10):
    parts = urlsplit(url)
    handlers = [NoRedirect()]
    if parts.scheme == "https":
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ.get("DUVORA_NOTIFY_CA_FILE") or None)))
    headers = {"Content-Type": "application/json"}
    if os.environ.get("DUVORA_NOTIFY_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["DUVORA_NOTIFY_KEY"]
    req = urllib.request.Request(url, data=json.dumps(payload, default=str).encode(), headers=headers, method="POST")
    with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as response:
        response.read(1024)


class PlaybooksMixin:
    def init_playbooks(self):
        self.db.executescript(SCHEMA)
        self.notify_url = os.environ.get("DUVORA_NOTIFY_URL", "")
        with self.transaction():
            for pb in DEFAULT_PLAYBOOKS:
                self.db.execute("INSERT OR IGNORE INTO playbooks VALUES(?,?)", (pb["id"], canonical(pb)))

    def playbooks(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM playbooks ORDER BY id")]

    def put_playbook(self, actor, ident, body):
        pb = validate_playbook(ident, body)
        with self.transaction():
            existed = self.db.execute("SELECT 1 FROM playbooks WHERE id=?", (ident,)).fetchone()
            self.db.execute("INSERT INTO playbooks VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (ident, canonical(pb)))
            self.event(actor, "playbook.updated" if existed else "playbook.created", {"id": ident, "enabled": pb["enabled"]})
        return pb

    def delete_playbook(self, actor, ident):
        with self.transaction():
            if not self.db.execute("DELETE FROM playbooks WHERE id=?", (ident,)).rowcount:
                raise Problem("Playbook not found", 404)
            self.event(actor, "playbook.deleted", {"id": ident})
        return {"deleted": ident}

    def playbook_runs(self, incident=None, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT body FROM playbook_runs" + (" WHERE incident=?" if incident else "") + " ORDER BY created DESC LIMIT ?",
                                   ((incident,) if incident else ()) + (max(1, min(500, int(limit))),))
            return [json.loads(r[0]) for r in rows]

    def on_incidents_opened(self, incidents):
        """Run every enabled playbook whose match covers a newly opened incident."""
        books = [pb for pb in self.playbooks() if pb["enabled"]]
        for inc in incidents:
            for pb in books:
                if inc["rule"] in pb["match"]["rules"] and RANK.get(inc["severity"], 0) >= RANK[pb["match"]["min_severity"]]:
                    try:
                        self.run_playbook(f"playbook:{pb['id']}", pb, inc)
                    except Exception as exc:
                        with self.transaction():
                            self.event(f"playbook:{pb['id']}", "playbook.error", {"incident": inc["id"], "error": f"{type(exc).__name__}: {exc}"[:200]})

    def run_playbook_manual(self, actor, ident, body):
        incident = (body or {}).get("incident")
        with self.lock:
            row = self.db.execute("SELECT body FROM playbooks WHERE id=?", (ident,)).fetchone()
            irow = self.db.execute("SELECT body FROM incidents WHERE id=?", (str(incident),)).fetchone()
        if not row:
            raise Problem("Playbook not found", 404)
        if not irow:
            raise Problem("Incident not found", 404)
        return self.run_playbook(f"playbook:{ident}", json.loads(row[0]), json.loads(irow[0]), requested_by=actor)

    def _draft_block(self, actor, inc):
        """A shadow steering plan whose rule set drops the peer named in the incident, ahead of the device's current rules."""
        peer, port = incident_peer(inc)
        kind = FINDING_RULES.get(inc["rule"])
        if kind:
            latest = self.ai_findings(device=inc["target"], kind=kind, limit=1)
            if latest:
                f = latest[0]
                # Egress: block the remote server. Ingress: the server is this node, so block the client.
                peer, port = (f.get("peer"), f.get("port")) if f.get("direction") == "egress" else (f.get("client"), None)
        if not peer:
            return {"ok": False, "detail": "No peer address in the incident to block"}
        with self.lock:
            d = self.device(inc["target"])
            current = self.applied_rules(d["id"]) if d.get("steering") else None
        # One rule set per device and peer, so a reopened incident updates its draft instead of adding one.
        ident = "pb-" + hashlib.sha256(f"{d['id']}|{peer}".encode()).hexdigest()[:12]
        rules = [{"priority": 1, "name": "pb-block-out", "action": "drop", "direction": "egress", "dst": peer,
                  "note": f"playbook {actor.split(':', 1)[1]} for incident {inc['id']}"},
                 {"priority": 2, "name": "pb-block-in", "action": "drop", "direction": "ingress", "src": peer,
                  "note": f"playbook {actor.split(':', 1)[1]} for incident {inc['id']}"}]
        for r in [r for r in (current or {}).get("rules", []) if r.get("name") not in ("pb-block-out", "pb-block-in")][:998]:
            rules.append({**r, "priority": len(rules) + 1})
        self.put_steering_set(actor, ident, {"description": f"Block {peer} on {d['id']} (incident {inc['id']})",
                                             "default": (current or {}).get("default", "bypass"), "rules": rules})
        plan = self.plan(actor, {"action": "steer", "devices": [d["id"]], "ruleset": ident, "stage": "shadow"})
        return {"ok": True, "detail": f"Drafted shadow plan dropping {peer}" + (f" (seen on port {port})" if port else ""),
                "plan": {k: plan.get(k) for k in ("id", "mode", "confirmation", "blockers", "expires", "effects")} | {"ruleset": ident}}

    def run_playbook(self, actor, pb, inc, requested_by=None):
        run = {"id": secrets.token_hex(8), "playbook": pb["id"], "name": pb["name"], "incident": inc["id"], "rule": inc["rule"],
               "target": inc["target"], "created": time.time(), "requested_by": requested_by, "steps": [], "plans": []}
        notify = []
        for step in pb["steps"]:
            kind = step["type"]
            try:
                if kind == "explain":
                    ev = self.incident_evidence(inc["id"])
                    lead = ev["hypotheses"][0]
                    result = {"ok": True, "detail": lead["text"], "confidence": lead["confidence"]}
                elif kind == "draft_block":
                    result = self._draft_block(actor, inc)
                    if result.get("plan"):
                        run["plans"].append(result["plan"])
                elif kind == "draft_bypass":
                    with self.lock:
                        d = self.device(inc["target"])
                    if not d.get("steering"):
                        result = {"ok": False, "detail": "The device has no steering"}
                    else:
                        result = {"ok": True, "detail": f"To stop steering drops on {d['id']}, an admin can engage bypass",
                                  "confirmation": f"BYPASS {d['id']}"}
                else:
                    url = step.get("url") or self.notify_url
                    if not url:
                        result = {"ok": False, "detail": "No notify URL (step url or DUVORA_NOTIFY_URL)"}
                    else:
                        notify.append(url)
                        result = {"ok": True, "detail": f"Notification queued to {urlsplit(url).hostname}"}
            except Problem as exc:
                result = {"ok": False, "detail": str(exc)}
            run["steps"].append({"type": kind, **result})
        with self.transaction():
            self.db.execute("INSERT INTO playbook_runs VALUES(?,?,?,?)", (run["id"], inc["id"], run["created"], canonical(run)))
            self.event(actor, "playbook.ran", {"run": run["id"], "incident": inc["id"], "plans": [p["id"] for p in run["plans"]],
                                               "requested_by": requested_by})
        self.export_event("playbook", {"time": run["created"], **{k: run[k] for k in ("id", "playbook", "incident", "rule", "target")},
                                       "plans": [p["id"] for p in run["plans"]]})
        if notify:
            payload = {"source": "duvora", "incident": {k: inc.get(k) for k in ("id", "rule", "target", "severity", "title", "detail")},
                       "playbook": pb["id"], "steps": run["steps"],
                       "note": "Drafted plans are previews; an administrator must review and confirm them in Duvora."}
            for url in notify:
                threading.Thread(target=self._notify, args=(url, payload, run["id"]), daemon=True).start()
        return run

    def _notify(self, url, payload, run_id):
        try:
            post_json(url, payload)
            outcome = None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            outcome = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"[:200]
        with self.transaction():
            self.event("playbook", "playbook.notified" if not outcome else "playbook.notify-failed",
                       {"run": run_id, "host": urlsplit(url).hostname, "error": outcome})

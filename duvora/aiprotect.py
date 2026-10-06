"""AI traffic protection on the control plane: LLM endpoints seen by inspection, threat findings
(prompt injection, secrets, personal data) and their alert rules. Inspection never blocks; blocking is
a drop steering rule the operator adds through a reviewed plan."""
import ipaddress
import json
import time

from .common import Problem, canonical

SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_endpoints(key TEXT PRIMARY KEY, device TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_findings(id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ai_findings_ts ON ai_findings(ts);
CREATE INDEX IF NOT EXISTS ai_findings_device ON ai_findings(device, ts);
"""
FINDING_KINDS = ("prompt-injection", "secret", "pii")
FINDING_WINDOW = 900
FINDING_RETENTION = 30 * 86400
ENDPOINT_RETENTION = 30 * 86400
MAX_INSPECTIONS = 100


def _text(value, limit=200):
    return value[:limit] if isinstance(value, str) else None


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def clean_inspection(r):
    """Type-check one inspection record (agent-supplied, untrusted)."""
    if not isinstance(r, dict) or r.get("direction") not in ("egress", "ingress"):
        return None
    port = lambda p: p if isinstance(p, int) and 0 <= p <= 65535 else None
    llm = r.get("llm") if isinstance(r.get("llm"), dict) else None
    out = {"direction": r["direction"], "src": _ip(r.get("src")), "dst": _ip(r.get("dst")), "sport": port(r.get("sport")),
           "dport": port(r.get("dport")), "protocol": _text(r.get("protocol"), 8), "sni": _text(r.get("sni"), 253),
           "host": _text(r.get("host"), 253), "method": _text(r.get("method"), 8), "path": _text(r.get("path"), 256),
           "encrypted": bool(r.get("encrypted")),
           "llm": {"provider": _text(llm.get("provider"), 64), "kind": llm.get("kind") if llm.get("kind") in ("hosted", "self-hosted", "mcp") else "self-hosted"} if llm else None,
           "findings": []}
    for f in (r.get("findings") or [])[:10]:
        if isinstance(f, dict) and f.get("kind") in FINDING_KINDS:
            out["findings"].append({"kind": f["kind"], "detail": _text(f.get("detail"), 80) or f["kind"],
                                    "severity": f.get("severity") if f.get("severity") in ("info", "warning", "critical") else "warning",
                                    "snippet": _text(f.get("snippet"), 160) or ""})
    return out


class AiProtectMixin:
    def init_aiprotect(self):
        self.db.executescript(SCHEMA)

    def record_inspections(self, d, records, now, source):
        """Store LLM endpoints and findings from inspection records (caller holds the transaction)."""
        for raw in (records or [])[:MAX_INSPECTIONS]:
            r = clean_inspection(raw)
            if not r:
                continue
            # The server is always the destination: a remote API for egress, this node for ingress.
            server, port = r["dst"], r["dport"]
            local_server = r["direction"] == "ingress"
            if r["llm"]:
                peer = server
                endpoint = r["host"] or peer or "unknown"
                key = f"{d['id']}|{endpoint}|{port}"
                row = self.db.execute("SELECT body FROM llm_endpoints WHERE key=?", (key,)).fetchone()
                e = json.loads(row[0]) if row else {"device": d["id"], "endpoint": endpoint, "peer": peer, "port": port,
                                                    "provider": r["llm"]["provider"], "kind": r["llm"]["kind"],
                                                    "serves": "this node" if local_server else "remote", "first": now,
                                                    "requests": 0, "findings": 0, "source": source, "clients": []}
                e.update(last=now, requests=e["requests"] + 1, findings=e["findings"] + len(r["findings"]), peer=peer or e.get("peer"))
                if local_server and r["src"] and r["src"] not in e["clients"]:
                    e["clients"] = (e["clients"] + [r["src"]])[-10:]
                self.db.execute("INSERT INTO llm_endpoints VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET body=excluded.body",
                                (key, d["id"], canonical(e)))
                if not row:
                    self.event("inspection", "ai.endpoint-discovered", {"device": d["id"], "endpoint": endpoint, "provider": e["provider"], "kind": e["kind"]})
            for f in r["findings"]:
                body = {**f, "device": d["id"], "source": source, "endpoint": r["host"] or server, "peer": server,
                        "port": port, "direction": r["direction"], "client": r["src"],
                        "path": r["path"], "provider": (r["llm"] or {}).get("provider")}
                self.db.execute("INSERT INTO ai_findings(device, ts, kind, body) VALUES(?,?,?,?)", (d["id"], now, f["kind"], canonical(body)))
                self.export_event("ai-finding", {**body, "time": now})

    def llm_endpoints(self, device=None):
        with self.lock:
            rows = self.db.execute("SELECT body FROM llm_endpoints" + (" WHERE device=?" if device else "") + " ORDER BY key",
                                   (device,) if device else ())
            return [json.loads(r[0]) for r in rows]

    def ai_findings(self, device=None, kind=None, since=None, limit=200):
        if kind not in (None, "", *FINDING_KINDS):
            raise Problem("kind must be prompt-injection, secret or pii")
        sql, args = "SELECT id, ts, body FROM ai_findings WHERE 1=1", []
        for col, value in (("device", device), ("kind", kind)):
            if value:
                sql += f" AND {col}=?"
                args.append(value)
        if since:
            sql += " AND ts>=?"
            args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(500, int(limit))))
        with self.lock:
            return [{"id": r["id"], "ts": r["ts"], **json.loads(r["body"])} for r in self.db.execute(sql, args)]

    def ai_coverage(self):
        """Share of LLM-bound traffic that steering inspects, per device and overall."""
        from .steering import INFERENCE_PORTS, compile_rules, evaluate, flow_from_record
        per, total, inspected = {}, 0, 0
        with self.lock:
            devices = self.rows("devices")
        endpoints = self.llm_endpoints()
        for d in devices:
            known = {(e["peer"], e["port"]) for e in endpoints if e["device"] == d["id"] and e.get("peer")}
            flows = self.steer_flows(d)
            applied = self.applied_rules(d["id"]) if d.get("steering") else None
            compiled = compile_rules(applied["rules"]) if applied else None
            bypass = ((d.get("steering") or {}).get("bypass") or {}).get("engaged")
            dev_total = dev_inspected = 0
            for r in flows:
                f = flow_from_record(r)
                if not f or f["proto"] != 6:
                    continue
                server = str(f["dst"] if f["direction"] == "egress" else f["src"])
                if f["dport"] not in INFERENCE_PORTS and (server, f["dport"]) not in known:
                    continue
                size = r.get("bytes") or 0
                dev_total += size
                if applied and not bypass and evaluate(applied, f, compiled)["action"] == "inspect":
                    dev_inspected += size
            if dev_total:
                per[d["id"]] = round(dev_inspected / dev_total, 3)
            total += dev_total
            inspected += dev_inspected
        return {"overall": round(inspected / total, 3) if total else None, "devices": per}

    def ai_traffic(self):
        now = time.time()
        findings = self.ai_findings(since=now - 86400, limit=200)
        counts = {k: sum(f["kind"] == k for f in findings) for k in FINDING_KINDS}
        endpoints = sorted(self.llm_endpoints(), key=lambda e: -e["last"])
        return {"generated": now, "endpoints": endpoints[:200], "findings": findings[:100], "counts_24h": counts,
                "coverage": self.ai_coverage(), "assets": self.ai_assets(),
                "note": "Inspection reads payload samples of flows a steering rule marks inspect. TLS payloads yield only the server name."}

    def prune_ai(self, now):
        removed = self.db.execute("DELETE FROM ai_findings WHERE ts<?", (now - FINDING_RETENTION,)).rowcount
        removed += self.db.execute("DELETE FROM llm_endpoints WHERE json_extract(body,'$.last')<?", (now - ENDPOINT_RETENTION,)).rowcount
        return removed

    def aiprotect_conditions(self):
        def findings(kind, label):
            def check(rule, now, firing):
                rows = self.db.execute("SELECT device, body FROM ai_findings WHERE kind=? AND ts>=? ORDER BY id DESC LIMIT 500",
                                       (kind, now - FINDING_WINDOW)).fetchall()
                by = {}
                for r in rows:
                    by.setdefault(r["device"], []).append(json.loads(r["body"]))
                for dev, items in by.items():
                    top = items[0]
                    firing[f"{rule['id']}:{dev}"] = (rule, dev, f"{label} on {dev}",
                                                     f"{len(items)} in 15 min; latest {top['detail']} to {top.get('endpoint')}:{top.get('port')}"
                                                     + (f" ({top['provider']})" if top.get("provider") else ""))
            return check

        def new_endpoint(rule, now, firing):
            by = {}
            for e in self.llm_endpoints():
                if now - e["first"] <= FINDING_WINDOW:
                    by.setdefault(e["device"], []).append(e)
            for dev, items in by.items():
                shown = ", ".join(f"{e['endpoint']}:{e['port']} ({e['provider']})" for e in items[:3])
                firing[f"{rule['id']}:{dev}"] = (rule, dev, f"New LLM endpoint on {dev}", f"{len(items)} first seen in 15 min: {shown}")
        return {"llm-prompt-injection": findings("prompt-injection", "Prompt injection in LLM traffic"),
                "llm-secret-leak": findings("secret", "Secret sent in LLM traffic"),
                "llm-sensitive-data": findings("pii", "Personal data sent in LLM traffic"),
                "llm-new-endpoint": new_endpoint}

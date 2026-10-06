"""Local, dependency-free analytics: metric baselines and anomalies, new egress destinations,
threshold forecasts, allow-list suggestions and incident evidence. Nothing here calls out."""
import ipaddress
import json
import math
import time

from .common import Problem, canonical
from .ebpf import replay
from .netra import _parse_time

SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines(device TEXT NOT NULL, metric TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(device, metric));
CREATE TABLE IF NOT EXISTS destinations(device TEXT PRIMARY KEY, body TEXT NOT NULL);
"""
# Metric -> smallest standard deviation worth alerting on, so a flat series does not turn noise into "10 sigma".
BASELINE_METRICS = {"pps": 5.0, "drops": 1.0, "tcp_retransmits_pm": 5.0, "tcp_resets_pm": 5.0,
                    "throughput_gbps": 0.05, "temperature_c": 1.0}
ALPHA = 0.05
ALPHA_ANOMALOUS = 0.01
WARMUP = 30
STREAK = 3
DEFAULT_Z = 4.0
NEW_WINDOW = 900
DEST_MEMORY = 86400
DEST_RETENTION = 7 * 86400
DEST_WARMUP = 3600
DEST_FLOOR = 1024
DEST_CAP = 5000
DEST_PERSIST = 3600
FORECAST_MIN_POINTS = 12
FORECAST_MIN_R2 = 0.5
FORECAST_CACHE = 300
EVIDENCE_WINDOW = 1800


def ewma_update(state, value, threshold=DEFAULT_Z):
    """Fold one sample into {n, mean, var, recent}; z is computed against the baseline before the update."""
    n, mean, var = state.get("n", 0), state.get("mean", value), state.get("var", 0.0)
    floor = state.get("floor", 0.0)
    std = max(math.sqrt(var), floor, 1e-9)
    z = (value - mean) / std if n else 0.0
    alpha = ALPHA_ANOMALOUS if n >= WARMUP and abs(z) >= threshold else ALPHA
    diff = value - mean
    mean += alpha * diff
    var = (1 - alpha) * (var + alpha * diff * diff)
    recent = (state.get("recent", []) + [round(z, 2)])[-STREAK:]
    return {**state, "n": n + 1, "mean": mean, "var": var, "recent": recent, "value": value, "z": round(z, 2)}


def is_anomalous(state, threshold=DEFAULT_Z):
    recent = state.get("recent", [])
    if state.get("n", 0) < WARMUP or len(recent) < STREAK:
        return False
    # Same direction for the whole streak: a spike up then down is two blips, not a shift.
    return all(z >= threshold for z in recent) or all(z <= -threshold for z in recent)


def linear_fit(points):
    """Least squares y = a + b*x over [(x, y)]; returns (a, b, r2) or None."""
    n = len(points)
    if n < 2:
        return None
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    sxx = sum((p[0] - mx) ** 2 for p in points)
    if sxx == 0:
        return None
    sxy = sum((p[0] - mx) * (p[1] - my) for p in points)
    b = sxy / sxx
    a = my - b * mx
    syy = sum((p[1] - my) ** 2 for p in points)
    r2 = 1.0 if syy == 0 else max(0.0, 1 - sum((p[1] - (a + b * p[0])) ** 2 for p in points) / syy)
    return a, b, r2


def _peer(r):
    try:
        return ipaddress.ip_address(str(r.get("peer") or ""))
    except ValueError:
        return None


def _egress(flows):
    return [r for r in flows if str(r.get("direction") or "egress").lower() in {"egress", "outbound", "out"} and _peer(r)]


def suggest_policies(flows, limit=5):
    """Rank single-CIDR + ports allow-lists by how much observed egress they cover, then by narrowness."""
    flows = _egress(flows)
    total_bytes = sum(r.get("bytes") or 0 for r in flows)
    total_flows = len(flows)
    if not flows:
        return {"flows": 0, "bytes": 0, "candidates": []}
    by_family = {}
    for r in flows:
        by_family.setdefault(_peer(r).version, []).append(r)
    family = max(by_family, key=lambda v: sum(r.get("bytes") or 0 for r in by_family[v]))
    group = by_family[family]
    prefixes = (32, 24, 16, 8, 0) if family == 4 else (128, 64, 48, 32, 0)
    nets = set()
    for prefix in prefixes:
        totals = {}
        for r in group:
            net = ipaddress.ip_network(f"{_peer(r)}/{prefix}", strict=False)
            totals[net] = totals.get(net, 0) + (r.get("bytes") or 0)
        nets.update(sorted(totals, key=lambda n: -totals[n])[:3])
    # The tightest single network covering every peer of the dominant family.
    peers = sorted({int(_peer(r)) for r in group})
    width = 32 if family == 4 else 128
    common = width - (peers[0] ^ peers[-1]).bit_length()
    nets.add(ipaddress.ip_network(f"{ipaddress.ip_address(peers[0])}/{common}", strict=False))
    candidates = []
    for net in nets:
        inside = [r for r in group if _peer(r) in net]
        port_bytes = {}
        for r in inside:
            port = r.get("port") if isinstance(r.get("port"), int) else 0
            if 1 <= port <= 65535:
                port_bytes[port] = port_bytes.get(port, 0) + (r.get("bytes") or 0)
        port_sets = [[]]
        covered, chosen, inside_bytes = 0, [], sum(port_bytes.values())
        for port in sorted(port_bytes, key=lambda p: -port_bytes[p]):
            if len(chosen) >= 64 or (inside_bytes and covered >= 0.95 * inside_bytes):
                break
            chosen.append(port)
            covered += port_bytes[port]
        if chosen and len(port_bytes) <= 64:
            port_sets.append(sorted(port_bytes))
        if chosen:
            port_sets.append(sorted(chosen))
        for ports in {tuple(p) for p in port_sets}:
            result = replay(flows, str(net), list(ports))
            candidates.append({
                "cidr": str(net), "ports": list(ports),
                "coverage_bytes": round(1 - result["would_block_bytes"] / total_bytes, 4) if total_bytes else 1.0,
                "coverage_flows": round(1 - result["would_block_flows"] / total_flows, 4) if total_flows else 1.0,
                "addresses": net.num_addresses, "would_block_top": result["top"][:3]})
    candidates.sort(key=lambda c: (-round(c["coverage_bytes"], 2), math.log2(c["addresses"]), 0 if c["ports"] else 1, len(c["ports"])))
    return {"flows": total_flows, "bytes": total_bytes, "candidates": candidates[:limit]}


def hypotheses(ev):
    """Rule-based explanations from an evidence bundle; ordered by confidence."""
    out = []
    inc, d = ev["incident"], ev.get("device") or {}
    e = ev.get("ebpf") or {}
    reasons = [r.get("reason", "") for r in e.get("drop_reasons") or []][:3]
    metrics = d.get("metrics") or {}
    iso = e.get("isolation") or {}

    def add(ident, confidence, text, signals):
        out.append({"id": ident, "confidence": confidence, "text": text, "signals": signals})

    if iso.get("mode") == "enforce" and (iso.get("blocked_delta") or inc["rule"] == "isolation-blocked"):
        top = (iso.get("top") or [{}])[0]
        add("isolation-blocking", "high", "Enforced node isolation is dropping egress outside the allow-list"
            + (f", mostly to {top.get('address') or top.get('destination')}:{top.get('port')}" if top else "")
            + ". If that destination is needed, add it to the allow-list or engage the kill switch.",
            [f"isolation mode enforce", f"blocked in last interval: {iso.get('blocked_delta', 0)}"])
    if iso.get("mode") == "shadow" and (iso.get("would_block_delta") or inc["rule"] == "isolation-would-block"):
        add("allowlist-gap", "medium", "The shadow allow-list misses destinations this node uses; enforcing it now would cut them off.",
            [f"would block in last interval: {iso.get('would_block_delta', 0)}"])
    if "NO_SOCKET" in reasons:
        add("closed-port", "medium", "Packets arrive for ports with no listening socket (kernel NO_SOCKET drops): a stopped service, "
            "a client using the wrong port, or a scan.", ["drop reason NO_SOCKET in top 3"])
    if any(k in r for r in reasons for k in ("QUEUE", "QDISC", "FULL", "NOMEM")) and (metrics.get("tcp_retransmits_pm") or 0) > 20:
        add("congestion", "medium", "Queue or memory drops together with TCP retransmits point to congestion on the uplink or a slow consumer.",
            [f"drop reasons {', '.join(reasons)}", f"retransmits/min {metrics.get('tcp_retransmits_pm')}"])
    elif (metrics.get("tcp_retransmits_pm") or 0) > 100:
        add("path-loss", "low", "High TCP retransmits without local queue drops suggest loss on the path or an overloaded peer.",
            [f"retransmits/min {metrics.get('tcp_retransmits_pm')}"])
    if (metrics.get("tcp_resets_pm") or 0) > 50 and iso.get("mode") != "enforce":
        add("resets", "low", "Many TCP resets: peers refusing connections (closed ports, restarted services) or a client retry storm.",
            [f"resets/min {metrics.get('tcp_resets_pm')}"])
    if e.get("stale"):
        recent_job = any(j.get("created", 0) >= inc["opened"] - EVIDENCE_WINDOW for j in ev.get("jobs") or [])
        add("agent-restart" if recent_job else "agent-down", "medium",
            "The eBPF agent stopped reporting shortly after a change on this device; it may be restarting." if recent_job else
            "The eBPF agent stopped reporting: the pod or process is down, or it cannot reach the control plane.",
            [f"sensor age {e.get('age', 0)} s"])
    if inc["rule"] == "job-failed":
        job = next((j for j in ev.get("jobs") or [] if j.get("id") == inc["target"]), None)
        last = ((job or {}).get("events") or [{}])[-1].get("message") if job else None
        add("job-error", "high", f"The operation failed{': ' + last if last else ''}.", ["job state failed"])
    if inc["rule"] == "temperature-high" or any(a["metric"] == "temperature_c" for a in ev.get("anomalies") or []):
        add("thermal", "medium", "Temperature is above its normal range: check airflow, fan health and sustained load.",
            [f"temperature_c {metrics.get('temperature_c')}"])
    for a in ev.get("anomalies") or []:
        if a["metric"] != "temperature_c":
            add(f"anomaly-{a['metric']}", "medium", f"{a['metric']} is {abs(a['z'])} standard deviations "
                f"{'above' if a['z'] > 0 else 'below'} its learned baseline ({a['baseline']}).", [f"z {a['z']}"])
    if inc["rule"] == "health-degraded":
        add("source-degraded", "medium", "The observation source reports degraded health: check the device's readiness in its source "
            "(DPF, PCI inventory or eBPF attachment) and any change made just before.", [f"health {d.get('health')}"])
    if inc["rule"] == "packet-drops" and not any(h["id"] in {"closed-port", "congestion"} for h in out):
        add("drops", "low", "Packet drops are reported" + (f"; the top kernel reasons are {', '.join(reasons)}" if reasons else "")
            + ". Compare with throughput: drops that rise with load point to capacity, steady drops to configuration.",
            [f"drops {metrics.get('drops')}"])
    if inc["rule"] == "device-stale" and not e.get("stale"):
        add("agent-silent", "medium", "The device agent stopped reporting: check that it runs and can reach the control plane "
            "with a valid host-bound key.", [inc.get("detail", "")])
    if inc["rule"] == "new-destination":
        add("new-destination", "low", "This node started talking to destinations not seen in the previous 24 hours. "
            "Confirm they are expected before enforcing isolation.", [inc.get("detail", "")])
    if inc["rule"] == "forecast-breach":
        add("trend", "medium", "The metric is trending toward its threshold; act before it is crossed.", [inc.get("detail", "")])
    if not out:
        add("none", "low", "No rule-based explanation matched; review the evidence below.", [])
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda h: rank[h["confidence"]])


def template_narrative(ev, hyps):
    inc = ev["incident"]
    lines = [f"{inc['title']} ({inc['severity']}, {inc['state']}): {inc['detail']}."]
    lead = hyps[0]
    lines.append(f"Most likely: {lead['text']}" if lead["id"] != "none" else lead["text"])
    if len(hyps) > 1:
        lines.append("Also consider: " + " ".join(h["text"] for h in hyps[1:3]))
    if ev.get("related"):
        lines.append(f"{len(ev['related'])} related incident(s) opened within 30 minutes: "
                     + "; ".join(r["title"] for r in ev["related"][:3]) + ".")
    return " ".join(lines)


class InsightsMixin:
    def init_insights(self):
        self.db.executescript(SCHEMA)
        self.baselines = {}
        for r in self.db.execute("SELECT device, metric, body FROM baselines"):
            self.baselines[(r["device"], r["metric"])] = json.loads(r["body"])
        self.destinations = {r["device"]: json.loads(r["body"]) for r in self.db.execute("SELECT device, body FROM destinations")}
        self.forecast_cache = {}
        self.last_dest_persist = time.time()

    def anomaly_threshold(self):
        row = self.db.execute("SELECT body FROM alert_rules WHERE id='anomaly'").fetchone()
        return json.loads(row[0]).get("threshold", DEFAULT_Z) if row else DEFAULT_Z

    def update_baselines(self, device, metrics):
        threshold = self.anomaly_threshold()
        for metric, floor in BASELINE_METRICS.items():
            value = metrics.get(metric)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                continue
            state = ewma_update({**self.baselines.get((device, metric), {}), "floor": floor}, float(value), threshold)
            self.baselines[(device, metric)] = state
            self.db.execute("INSERT INTO baselines VALUES(?,?,?) ON CONFLICT(device, metric) DO UPDATE SET body=excluded.body",
                            (device, metric, canonical(state)))

    def anomalies(self, device=None, threshold=None):
        threshold = threshold or self.anomaly_threshold()
        out = []
        for (dev, metric), s in sorted(self.baselines.items()):
            if (device is None or dev == device) and is_anomalous(s, threshold):
                out.append({"device": dev, "metric": metric, "value": s["value"], "baseline": round(s["mean"], 2),
                            "std": round(max(math.sqrt(s["var"]), s.get("floor", 0)), 2), "z": s["z"], "samples": s["n"]})
        return out

    def observe_destinations(self, device, flows, now):
        """Remember every egress (peer, port, protocol) seen per device; mark first sightings."""
        seen = self.destinations.setdefault(device, {"since": now, "peers": {}})
        peers = seen["peers"]
        for r in _egress(flows):
            ts = _parse_time(r.get("observedAt")) or now
            key = f"{_peer(r)}|{r.get('port') if isinstance(r.get('port'), int) else 0}|{str(r.get('protocol') or '').lower()}"
            entry = peers.get(key)
            if entry is None:
                if len(peers) >= DEST_CAP:
                    continue
                # A destination last seen more than a day ago counts as new again.
                entry = peers[key] = {"first": ts, "last": ts, "bytes": 0}
            elif ts - entry["last"] > DEST_MEMORY:
                entry["first"] = ts
            entry["last"] = max(entry["last"], ts)
            entry["bytes"] += r.get("bytes") or 0

    def new_destinations(self, device=None, now=None):
        now = now or time.time()
        out = []
        for dev, seen in sorted(self.destinations.items()):
            if device is not None and dev != device or now - seen.get("since", now) < DEST_WARMUP:
                continue
            for key, e in seen["peers"].items():
                if now - e["first"] <= NEW_WINDOW and e["first"] - seen["since"] >= DEST_WARMUP and e["bytes"] >= DEST_FLOOR:
                    peer, port, proto = key.split("|")
                    out.append({"device": dev, "peer": peer, "port": int(port), "protocol": proto, "first_seen": e["first"], "bytes": e["bytes"]})
        return sorted(out, key=lambda x: -x["bytes"])

    def persist_destinations(self, now=None, force=False):
        now = now or time.time()
        if not force and now - self.last_dest_persist < DEST_PERSIST:
            return
        self.last_dest_persist = now
        with self.transaction():
            for dev, seen in self.destinations.items():
                seen["peers"] = {k: v for k, v in seen["peers"].items() if now - v["last"] <= DEST_RETENTION}
                self.db.execute("INSERT INTO destinations VALUES(?,?) ON CONFLICT(device) DO UPDATE SET body=excluded.body", (dev, canonical(seen)))

    def forecast(self, device_id, now=None, cached=False):
        now = now or time.time()
        hit = self.forecast_cache.get(device_id)
        if cached and hit and now - hit[0] < FORECAST_CACHE:
            return hit[1]
        d = self.device(device_id)
        points = self.history(device_id, "24h")["points"]
        rule = next((r for r in self.alert_rules() if r["id"] == "temperature-high"), {})
        targets = {"temperature_c": rule.get("threshold", 80)}
        if (d.get("metrics") or {}).get("link_gbps"):
            targets["throughput_gbps"] = round(0.9 * d["metrics"]["link_gbps"], 2)
        out = []
        for metric, threshold in targets.items():
            series = [((p["ts"] - now) / 3600, p[metric]) for p in points if isinstance(p.get(metric), (int, float))]
            item = {"metric": metric, "threshold": threshold, "points": len(series), "current": series[-1][1] if series else None,
                    "slope_per_hour": None, "r2": None, "eta_hours": None, "reliable": False}
            fit = linear_fit(series) if len(series) >= FORECAST_MIN_POINTS else None
            if fit:
                a, b, r2 = fit
                item.update(slope_per_hour=round(b, 4), r2=round(r2, 3), reliable=r2 >= FORECAST_MIN_R2)
                fitted_now = a
                if item["reliable"] and b > 0 and fitted_now < threshold:
                    item["eta_hours"] = round((threshold - fitted_now) / b, 2)
            out.append(item)
        result = {"device": device_id, "generated": now, "forecasts": out}
        self.forecast_cache[device_id] = (now, result)
        return result

    def forecast_breaches(self, hours, now=None):
        out = []
        for d in self.rows("devices"):
            for f in self.forecast(d["id"], now, cached=True)["forecasts"]:
                if f["eta_hours"] is not None and f["eta_hours"] <= hours:
                    out.append({"device": d["id"], **f})
        return out

    def insights(self):
        rules = {r["id"]: r for r in self.alert_rules()}
        hours = rules.get("forecast-breach", {}).get("threshold", 6)
        forecasts = []
        for d in self.rows("devices"):
            for f in self.forecast(d["id"], cached=True)["forecasts"]:
                if f["reliable"]:
                    forecasts.append({"device": d["id"], **f})
        return {"generated": time.time(), "anomalies": self.anomalies(), "new_destinations": self.new_destinations()[:50],
                "forecasts": sorted(forecasts, key=lambda f: (f["eta_hours"] is None, f["eta_hours"] or 0)),
                "forecast_horizon_hours": hours,
                "baselines": {"tracked": len(self.baselines), "warm": sum(s["n"] >= WARMUP for s in self.baselines.values()), "warmup": WARMUP}}

    def suggest_allowlist(self, device_id):
        with self.lock:
            d = self.device(device_id)
            flows = list(self.netra_flows.get(device_id, []))
        result = suggest_policies(flows)
        for c in result["candidates"]:
            c["policy"] = {"name": "allow-observed", "tenant": "ops", "cidr": c["cidr"], "ports": c["ports"]}
        return {"device": d["id"], "source": "observed egress flow records" if flows else "no flow records yet",
                "note": "A policy is one CIDR plus ports; destinations outside the chosen CIDR stay blocked.", **result}

    def incident_evidence(self, ident):
        with self.lock:
            row = self.db.execute("SELECT body FROM incidents WHERE id=?", (ident,)).fetchone()
            if not row:
                raise Problem("Incident not found", 404)
            inc = json.loads(row[0])
            lo, hi = inc["opened"] - EVIDENCE_WINDOW, inc["opened"] + EVIDENCE_WINDOW
            d = None
            drow = self.db.execute("SELECT body FROM devices WHERE id=?", (inc["target"],)).fetchone()
            if drow:
                d = json.loads(drow[0])
            jobs = [j for j in self.rows("jobs") if lo <= j["created"] <= hi and
                    (j["id"] == inc["target"] or inc["target"] in j["spec"].get("devices", []))]
            if d is None:
                job = next((j for j in self.rows("jobs") if j["id"] == inc["target"]), None)
                if job:
                    jobs = [job] + [j for j in jobs if j["id"] != job["id"]]
            samples = []
            if d:
                for r in self.db.execute("SELECT ts, metrics FROM samples WHERE device=? AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 60",
                                         (d["id"], lo, hi)):
                    samples.append({"ts": r["ts"], **json.loads(r["metrics"])})
            audit = []
            for r in self.db.execute("SELECT body FROM audit WHERE json_extract(body,'$.time') BETWEEN ? AND ? ORDER BY seq DESC LIMIT 400", (lo, hi)):
                body = json.loads(r[0])
                if inc["target"] in canonical(body.get("detail")):
                    audit.append(body)
            hosts = {d["host"]} if d else set()
            related = []
            for r in self.db.execute("SELECT body FROM incidents WHERE opened BETWEEN ? AND ? AND id!=?", (lo, hi, ident)):
                other = json.loads(r[0])
                odev = self.db.execute("SELECT body FROM devices WHERE id=?", (other["target"],)).fetchone()
                if other["target"] == inc["target"] or (odev and json.loads(odev[0])["host"] in hosts):
                    related.append({k: other[k] for k in ("id", "rule", "target", "title", "severity", "state", "opened")})
        e = (d or {}).get("ebpf") or {}
        ev = {"incident": inc,
              "device": {k: d.get(k) for k in ("id", "host", "site", "source", "health", "metrics", "metrics_source", "mode")} if d else None,
              "ebpf": {"provider": e.get("provider"), "stale": e.get("stale"), "age": e.get("age"), "attached": e.get("attached"),
                       "drop_reasons": (e.get("drop_reasons") or [])[:5], "talkers": (e.get("talkers") or [])[:5],
                       "isolation": e.get("isolation")} if e else None,
              "samples": samples[::-1], "jobs": [{k: j.get(k) for k in ("id", "action", "state", "created", "mode", "events")} | {"stage": j["spec"].get("stage")} for j in jobs[:10]],
              "audit": audit[:20], "related": related[:10],
              "anomalies": self.anomalies(d["id"]) if d else []}
        ev["hypotheses"] = hypotheses(ev)
        ev["narrative"] = template_narrative(ev, ev["hypotheses"])
        ev["narrative_source"] = "template"
        return ev

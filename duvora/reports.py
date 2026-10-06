"""Read-only scorecard, shift briefing, and fleet topology derived from current state."""
import time

from . import __version__

PENALTY = {"critical": 10, "warning": 4, "info": 1}


def grade(score):
    if score is None:
        return "No devices"
    return "Excellent" if score >= 90 else "Good" if score >= 75 else "Needs attention" if score >= 50 else "At risk"


class ReportsMixin:
    def scorecard(self):
        snap = self.snapshot()
        devices, jobs = snap["devices"], snap["jobs"]
        incidents = self.incidents("active")
        n = len(devices)
        healthy = sum(d["health"] == "healthy" for d in devices)
        stale = sum(d["health"] == "stale" for d in devices)
        day = time.time() - 86400
        recent = [j for j in jobs if j["created"] >= day]
        failed = sum(j["state"] == "failed" for j in recent)
        penalty = min(20, sum(PENALTY.get(i["severity"], 1) for i in incidents))
        parts = [
            {"name": "Device health", "weight": 50, "score": round(50 * healthy / n, 1) if n else 0, "detail": f"{healthy} of {n} healthy"},
            {"name": "Observation freshness", "weight": 20, "score": round(20 * (1 - stale / n), 1) if n else 0, "detail": f"{stale} stale"},
            {"name": "Open incidents", "weight": 20, "score": 20 - penalty, "detail": f"{len(incidents)} active"},
            {"name": "Operations", "weight": 10, "score": round(10 * (1 - failed / len(recent)), 1) if recent else 10, "detail": f"{failed} of {len(recent)} failed in 24 h"},
        ]
        score = round(sum(p["score"] for p in parts)) if n else None
        posture = self.ai_posture()
        return {"score": score, "grade": grade(score), "parts": parts, "devices": n, "generated": time.time(),
                "ai_posture": {"score": posture["score"], "grade": posture["grade"]}}

    def ai_posture(self):
        """AI security posture: inspection coverage, findings, shadow AI, artifact scans, threat intel and
        agent identity. Each check explains its score and the next step."""
        now = time.time()
        traffic = self.ai_traffic()
        assets, coverage, counts = traffic["assets"], traffic["coverage"]["overall"], traffic["counts_24h"]
        week = [s for s in self.scans(limit=200) if now - (s.get("finished") or s.get("started") or 0) <= 7 * 86400]
        failed = [s for s in week if s["status"] == "failed"]
        intel = self.intel_overview()
        idents = self.agent_identities()
        native = [i for i in idents["identities"] if i["known_device"]]
        weak = [i["host"] for i in native if i["static_key"] and not i["tokens"]]
        unknown = [i["host"] for i in idents["identities"] if i["unknown"]]
        with self.lock:
            devices = self.rows("devices")
        steering = [d.get("steering") or {} for d in devices]

        def check(name, weight, fraction, detail, action=""):
            fraction = max(0.0, min(1.0, fraction))
            status = "pass" if fraction >= 0.99 else "warn" if fraction >= 0.5 else "fail"
            return {"name": name, "weight": weight, "score": round(weight * fraction, 1), "status": status, "detail": detail,
                    "action": action if status != "pass" else ""}

        checks = [
            check("Inspection coverage", 25, 1.0 if coverage is None else coverage,
                  "No LLM-bound traffic observed" if coverage is None else f"{round(coverage * 100)}% of LLM-bound bytes are inspected",
                  "Add inspect rules for LLM endpoints (duvoractl steer-suggest <device>)"),
            check("LLM findings (24 h)", 25, 1 - min(1, 0.5 * counts.get("prompt-injection", 0) + 0.5 * counts.get("secret", 0) + 0.1 * counts.get("pii", 0)),
                  f"{counts.get('prompt-injection', 0)} prompt injection, {counts.get('secret', 0)} secret, {counts.get('pii', 0)} sensitive data",
                  "Review AI traffic findings and the incidents they opened"),
            check("Shadow AI", 15, (1 - min(1, assets["unsanctioned"] / 5)) if assets["policy_active"] else 0.5,
                  f"{assets['unsanctioned']} unsanctioned of {len(assets['assets'])} AI assets" if assets["policy_active"]
                  else f"{len(assets['assets'])} AI assets, no sanctioned list",
                  "Sanction expected AI services (duvoractl assets sanction) so new ones stand out"),
            check("Artifact scans (7 d)", 15, 0.5 if not week else 1 - len(failed) / len(week),
                  f"{len(failed)} of {len(week)} scans failed" if week else "No images or models scanned this week",
                  "Scan images before deploy (duvoractl scan --image) and fix failed artifacts"),
            check("Threat intel", 10, (1 - min(1, len(intel["matches"]) / 3)) if intel["feeds"] else 0.5,
                  f"{len(intel['matches'])} indicator matches across {len(intel['feeds'])} feeds" if intel["feeds"] else "No threat-intel feeds",
                  "Investigate matches; drop indicators with duvoractl intel ruleset" if intel["feeds"] else "Add a feed (duvoractl intel add-feed)"),
            check("Agent identity", 10, 1 - min(1, (len(weak) + 2 * len(unknown)) / max(1, len(native))),
                  f"{len(native)} agents; {len(weak)} on static keys only; {len(unknown)} unknown" if native or unknown else "No native agents",
                  "Enable token rotation on agents and investigate unknown agent credentials"),
        ]
        score = round(sum(c["score"] for c in checks))
        return {"generated": now, "score": score, "grade": grade(score), "checks": checks,
                "steering": {"shadow": sum(s.get("stage") == "shadow" for s in steering), "enforce": sum(s.get("stage") == "enforce" for s in steering),
                             "bypass": sum(bool((s.get("bypass") or {}).get("engaged")) for s in steering), "devices": len(devices)},
                "note": "Host-kernel eBPF steering and payload sampling on nodes; no DPU offload."}

    def topology(self):
        snap = self.snapshot()
        nodes, edges, seen = [], [], set()

        def add(node):
            if node["id"] not in seen:
                seen.add(node["id"])
                nodes.append(node)

        for d in snap["devices"]:
            site, host = f"site:{d['site']}", f"host:{d['site']}/{d['host']}"
            add({"id": site, "kind": "site", "label": d["site"]})
            add({"id": host, "kind": "host", "label": d["host"], "site": d["site"]})
            add({"id": f"dpu:{d['id']}", "kind": "dpu", "label": d["id"], "health": d["health"], "mode": d["mode"], "source": d["source"]})
            edges.append({"from": site, "to": host, "kind": "contains"})
            edges.append({"from": host, "to": f"dpu:{d['id']}", "kind": "hosts"})
        for p in snap["policies"]:
            add({"id": f"policy:{p['id']}", "kind": "policy", "label": p["name"], "tenant": p["tenant"]})
            for dev in p["devices"]:
                edges.append({"from": f"policy:{p['id']}", "to": f"dpu:{dev}", "kind": "isolates"})
        return {"nodes": nodes, "edges": edges}

    def briefing(self, ai=False):
        snap = self.snapshot()
        card = self.scorecard()
        incidents = self.incidents("active")
        day = time.time() - 86400
        jobs = sorted((j for j in snap["jobs"] if j["created"] >= day), key=lambda j: -j["created"])
        by = lambda key: {v: sum(d[key] == v for d in snap["devices"]) for v in sorted({d[key] for d in snap["devices"]})}
        steps = []
        for inc in incidents:
            if inc["rule"] == "temperature-high":
                steps.append(f"Check airflow and load on {inc['target']} before scheduling changes.")
            elif inc["rule"] == "device-stale":
                steps.append(f"Confirm the agent for {inc['target']} is running and can reach the control plane.")
            elif inc["rule"] == "health-degraded":
                steps.append(f"Inspect {inc['target']} in DPU fleet and review its source readiness.")
            elif inc["rule"] == "packet-drops":
                steps.append(f"Review drop counters on {inc['target']} in Telemetry.")
            elif inc["rule"] in ("tcp-retransmits", "tcp-resets"):
                steps.append(f"Check path loss and peer health for {inc['target']} (kernel TCP events).")
            elif inc["rule"] == "ebpf-detached":
                steps.append(f"Check the eBPF agent and program attachment on {inc['target']}.")
            elif inc["rule"] == "anomaly":
                steps.append(f"Compare {inc['target']} against its baseline in Insights; open Explain on the incident.")
            elif inc["rule"] == "new-destination":
                steps.append(f"Confirm the new egress destinations on {inc['target']} are expected.")
            elif inc["rule"] == "forecast-breach":
                steps.append(f"Plan capacity or cooling for {inc['target']} before the forecast threshold is crossed.")
            elif inc["rule"] == "isolation-would-block":
                steps.append(f"Review would-block destinations on {inc['target']} before enforcing isolation.")
            elif inc["rule"] == "isolation-blocked":
                steps.append(f"Check the destinations enforced isolation drops on {inc['target']}; engage the kill switch if they are needed.")
            elif inc["rule"] == "steering-bypass":
                steps.append(f"Find out why steering is bypassed on {inc['target']} and resume it when safe.")
            elif inc["rule"] in ("steering-drop", "steering-would-drop"):
                steps.append(f"Review steering drop verdicts on {inc['target']} before enforcing or keeping the rule set.")
            elif inc["rule"] in ("llm-prompt-injection", "llm-secret-leak", "llm-sensitive-data"):
                steps.append(f"Review the AI traffic findings on {inc['target']} and the workload that sent them.")
            elif inc["rule"] in ("llm-new-endpoint", "unsanctioned-ai"):
                steps.append(f"Confirm the AI service or endpoint on {inc['target']} is approved; sanction it or remove it.")
            elif inc["rule"] == "intel-match":
                steps.append(f"Investigate the threat-intel match on {inc['target']}; check the drafted playbook plan before applying.")
            elif inc["rule"] == "scan-failed":
                steps.append(f"Fix or replace the artifact from scan {inc['target']} before deploying it.")
            elif inc["rule"] in ("agent-identity-stale", "agent-identity-unknown"):
                steps.append(f"Check the agent credential for {inc['target']}: token rotation, mTLS certificate and device mapping.")
            else:
                steps.append(f"Review incident {inc['id']}: {inc['title']}.")
        if not steps:
            steps.append("No active incidents. Continue routine review.")
        insight = self.insights()
        suggestions = []
        for d in snap["devices"]:
            if ((d.get("ebpf") or {}).get("isolation") or {}).get("mode") == "shadow":
                best = (self.suggest_allowlist(d["id"])["candidates"] or [None])[0]
                if best:
                    suggestions.append({"device": d["id"], "cidr": best["cidr"], "ports": best["ports"], "coverage_bytes": best["coverage_bytes"]})
        body = {"generated": time.time(), "version": __version__, "demo": snap["demo"], "scorecard": card,
                "fleet": {"total": len(snap["devices"]), "by_health": by("health"), "by_source": by("source"), "by_site": by("site")},
                "incidents": incidents, "jobs": jobs[:50], "playbook": list(dict.fromkeys(steps)),
                "ebpf": [{"device": d["id"], "node": d["ebpf"].get("node"), "provider": d["ebpf"].get("provider") or "netra",
                          "drop_reasons": (d["ebpf"].get("drop_reasons") or [])[:3],
                          "talkers": (d["ebpf"].get("talkers") or [])[:3]}
                         for d in snap["devices"] if d.get("ebpf")],
                "anomalies": insight["anomalies"][:20],
                "forecasts": [f for f in insight["forecasts"] if f["eta_hours"] is not None][:20],
                "new_destinations": insight["new_destinations"][:10],
                "allowlist_suggestions": suggestions, "ai_posture": self.ai_posture(), "summary": None, "summary_source": None}
        if ai:
            body["summary"], body["summary_source"] = self.ai_summary(body)
        body["markdown"] = markdown(body)
        return body


def markdown(r):
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(r["generated"]))
    score = "n/a" if r["scorecard"]["score"] is None else r["scorecard"]["score"]
    lines = [f"# Duvora shift briefing — {when}", "",
             f"Score: **{score}** ({r['scorecard']['grade']}) · {r['fleet']['total']} devices" + (" · simulation enabled" if r["demo"] else ""), ""]
    if r.get("summary"):
        lines += ["## Summary" + (" (AI-written, review before acting)" if r.get("summary_source") == "llm" else ""), "", r["summary"], ""]
    lines += ["## Fleet", ""]
    lines += [f"- {k}: {v}" for k, v in r["fleet"]["by_health"].items()] or ["- No devices"]
    lines += ["", "## Active incidents", ""]
    lines += [f"- [{i['severity']}] {i['title']} — {i['detail']} ({i['state']})" for i in r["incidents"]] or ["- None"]
    lines += ["", "## Operations in the last 24 hours", ""]
    lines += [f"- {j['action']} on {', '.join(j['spec']['devices'])}: {j['state']}" for j in r["jobs"]] or ["- None"]
    if r.get("ebpf"):
        lines += ["", "## Kernel observations (eBPF)", ""]
        for e in r["ebpf"]:
            reasons = ", ".join(f"{x['reason']} ({x['count']})" for x in e["drop_reasons"]) or "none"
            talkers = ", ".join(f"{t['peer']}:{t['port']}/{t['protocol']}" for t in e["talkers"]) or "none"
            lines.append(f"- {e['device']} ({'native agent' if e.get('provider') == 'native' else 'Netra'}): drop reasons {reasons}; top talkers {talkers}")
    if r.get("anomalies") or r.get("forecasts") or r.get("new_destinations"):
        lines += ["", "## Insights", ""]
        lines += [f"- Anomaly on {a['device']}: {a['metric']} {a['value']} vs baseline {a['baseline']} (z {a['z']})" for a in r.get("anomalies", [])]
        lines += [f"- Forecast on {f['device']}: {f['metric']} crosses {f['threshold']} in about {f['eta_hours']} h" for f in r.get("forecasts", [])]
        lines += [f"- New destination on {x['device']}: {x['peer']}:{x['port']}/{x['protocol']}" for x in r.get("new_destinations", [])]
    if r.get("allowlist_suggestions"):
        lines += ["", "## Suggested allow-lists for shadow isolation", ""]
        lines += [f"- {s['device']}: {s['cidr']} ports {', '.join(map(str, s['ports'])) or 'any'} covers {round(s['coverage_bytes'] * 100, 1)}% of observed bytes"
                  for s in r["allowlist_suggestions"]]
    if r.get("ai_posture"):
        p = r["ai_posture"]
        s = p["steering"]
        lines += ["", f"## AI security posture: {p['score']} ({p['grade']})", "",
                  f"- Steering: {s['shadow']} shadow, {s['enforce']} enforce, {s['bypass']} bypassed of {s['devices']} devices"]
        lines += [f"- {c['name']}: {c['status']} — {c['detail']}" + (f". {c['action']}" if c["action"] else "") for c in p["checks"]]
    lines += ["", "## Suggested next steps (review only)", ""]
    lines += [f"- {s}" for s in r["playbook"]]
    return "\n".join(lines) + "\n"

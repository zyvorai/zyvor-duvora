"""Ops copilot: an LLM tool loop over read-only fleet tools. The only state it can create is a plan
preview (admins only); applying still needs the plan's typed confirmation through the normal API."""
import json
import time
from collections import deque

from .common import Problem, canonical
from .llm import SYSTEM, LlmError

MAX_STEPS = 6
MAX_MESSAGES = 20
MAX_CHARS = 4096
RATE = 20
TOOL_RESULT_LIMIT = 12000


def _fn(name, description, properties=None, required=()):
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {
        "type": "object", "properties": properties or {}, "required": list(required)}}}


DEVICE = {"device": {"type": "string", "description": "Device id, for example netra-node-1 or bf3-01"}}
TOOLS = [
    _fn("fleet_summary", "Devices with health, source, eBPF provider, mode and current metrics; open incident count; kill switch."),
    _fn("list_incidents", "Incidents, newest first.", {"state": {"type": "string", "enum": ["active", "open", "acknowledged", "resolved"]}}),
    _fn("device_details", "One device: inventory, metrics, eBPF probe, drop reasons, TCP, top talkers, isolation state.", DEVICE, ["device"]),
    _fn("metric_history", "Telemetry history for a device.", {**DEVICE, "window": {"type": "string", "enum": ["1h", "24h", "7d"]},
        "metric": {"type": "string", "description": "Optional metric name such as pps or temperature_c"}}, ["device"]),
    _fn("forecast", "Linear forecast of temperature and throughput against their thresholds.", DEVICE, ["device"]),
    _fn("anomalies", "Fleet insights: metric anomalies against learned baselines, reliable forecasts, new egress destinations."),
    _fn("explain_incident", "Evidence bundle and rule-based hypotheses for an incident.", {"incident": {"type": "string"}}, ["incident"]),
    _fn("suggest_allowlist", "Ranked allow-list (CIDR + ports) candidates from a device's observed egress, with coverage.", DEVICE, ["device"]),
    _fn("steering_state", "Traffic steering: rule sets, and per device the stage (shadow/enforce), bypass, rule hit counters. "
        "Host-kernel eBPF on nodes or simulation; never DPU offload.", {"device": {"type": "string", "description": "Optional device id"}}),
    _fn("list_verdicts", "Recent steering verdicts (flow samples with the matching rule).", {"device": {"type": "string"},
        "action": {"type": "string", "enum": ["allow", "inspect", "drop"]}}),
    _fn("explain_verdict", "Which steering rule matches a flow on a device, with a trace of the rules before it.", {**DEVICE,
        "direction": {"type": "string", "enum": ["ingress", "egress"]}, "src": {"type": "string"}, "dst": {"type": "string"},
        "protocol": {"type": "string"}, "sport": {"type": "integer"}, "dport": {"type": "integer"}}, ["device"]),
    _fn("suggest_steering", "Steering rule candidates (inspect LLM endpoints, bypass storage/RDMA, drop intel matches) from observed traffic.", DEVICE, ["device"]),
    _fn("ai_traffic", "LLM endpoints and providers seen by inspection, finding counts (prompt injection, secrets, sensitive data), coverage."),
    _fn("ai_assets", "Discovered AI services and endpoints, and whether each is sanctioned."),
    _fn("scan_results", "Recent image and model artifact scans with findings."),
    _fn("intel_matches", "Threat-intel feeds and flows that matched an indicator."),
    _fn("posture", "AI security posture score with per-check detail and next steps."),
    _fn("draft_plan", "Create a plan PREVIEW (admins only). It is never applied; the operator reviews it and types the confirmation. "
        "spec is a Duvora plan body, for example {\"action\":\"isolate\",\"devices\":[\"d1\"],\"stage\":\"shadow\","
        "\"policy\":{\"name\":\"egress\",\"tenant\":\"ops\",\"cidr\":\"10.0.0.0/8\",\"ports\":[443]}}, {\"action\":\"release\",\"devices\":[\"d1\"]}, "
        "{\"action\":\"steer\",\"devices\":[\"d1\"],\"ruleset\":\"ai-gateway\",\"stage\":\"shadow\"} or {\"action\":\"unsteer\",\"devices\":[\"d1\"]}.",
        {"spec": {"type": "object"}}, ["spec"]),
]


def _compact_device(d):
    e = d.get("ebpf") or {}
    return {"id": d["id"], "host": d["host"], "site": d["site"], "source": d["source"], "health": d["health"], "mode": d["mode"],
            "provider": e.get("provider") if e else None, "metrics": d.get("metrics"), "metrics_source": d.get("metrics_source"),
            "isolation": (e.get("isolation") or {}).get("mode") if e else None}


class CopilotMixin:
    def tool(self, actor, role, name, args):
        if not isinstance(args, dict):
            raise Problem("Tool arguments must be an object")
        if name == "fleet_summary":
            snap = self.snapshot()
            return {"devices": [_compact_device(d) for d in snap["devices"]][:100], "open_incidents": snap["open_incidents"],
                    "kill_switch": bool(snap["netra"].get("kill_switch", {}).get("engaged")), "policies": len(snap["policies"])}
        if name == "list_incidents":
            return [{k: i.get(k) for k in ("id", "rule", "target", "severity", "title", "detail", "state", "opened")}
                    for i in self.incidents(args.get("state") or "active")[:30]]
        if name == "device_details":
            with self.lock:
                d = self.device(str(args.get("device")))
            out = _compact_device(d)
            if d.get("ebpf"):
                e = self.device_ebpf(d["id"])
                out["ebpf"] = {k: e.get(k) for k in ("provider", "kernel", "attached", "programs", "drop_reasons", "talkers", "isolation", "stale", "errors")}
            return out
        if name == "metric_history":
            h = self.history(str(args.get("device")), args.get("window") or "1h")
            metric = args.get("metric")
            points = h["points"][-60:]
            if metric:
                points = [{"ts": p["ts"], metric: p.get(metric)} for p in points]
            return {**h, "points": points}
        if name == "forecast":
            return self.forecast(str(args.get("device")))
        if name == "anomalies":
            return self.insights()
        if name == "explain_incident":
            ev = self.explain_incident(str(args.get("incident")), use_llm=False)
            return {k: ev[k] for k in ("incident", "device", "ebpf", "related", "anomalies", "hypotheses")}
        if name == "suggest_allowlist":
            return self.suggest_allowlist(str(args.get("device")))
        if name == "steering_state":
            if args.get("device"):
                return self.device_steering(str(args["device"]))
            return self.steering_overview()
        if name == "list_verdicts":
            return self.verdicts(args.get("device"), args.get("action"), None, 50)
        if name == "explain_verdict":
            flow = {k: args[k] for k in ("direction", "src", "dst", "protocol", "sport", "dport") if args.get(k) is not None}
            return self.explain_verdict({"device": str(args.get("device")), "flow": flow}, use_llm=False)
        if name == "suggest_steering":
            return self.suggest_steering(str(args.get("device")))
        if name == "ai_traffic":
            t = self.ai_traffic()
            return {k: t[k] for k in ("endpoints", "findings", "counts_24h", "coverage", "note")} | {"endpoints": t["endpoints"][:50], "findings": t["findings"][:30]}
        if name == "ai_assets":
            return self.ai_assets()
        if name == "scan_results":
            return [{k: s.get(k) for k in ("id", "kind", "target", "status", "findings", "finished")} for s in self.scans(limit=20)]
        if name == "intel_matches":
            v = self.intel_overview()
            return {"feeds": [{k: f.get(k) for k in ("id", "description", "count", "last_fetch", "error", "enabled")} for f in v["feeds"]],
                    "matches": v["matches"][:50]}
        if name == "posture":
            return self.ai_posture()
        if name == "draft_plan":
            if role != "admin":
                raise Problem("Drafting plans requires an admin", 403)
            p = self.plan(actor, args.get("spec"))
            with self.transaction():
                self.event(actor, "copilot.plan-drafted", {"plan": p["id"], "action": p["spec"]["action"], "devices": p["spec"]["devices"]})
            return {k: p.get(k) for k in ("id", "spec", "mode", "blockers", "confirmation", "effects", "shadow", "expires")}
        raise Problem(f"Unknown tool {name}", 404)

    def copilot(self, actor, role, body):
        messages = body.get("messages") if isinstance(body, dict) else None
        if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
            raise Problem(f"messages must be a list of 1–{MAX_MESSAGES} items")
        for m in messages:
            if not isinstance(m, dict) or m.get("role") not in {"user", "assistant"} or not isinstance(m.get("content"), str) \
                    or not m["content"].strip() or len(m["content"]) > MAX_CHARS:
                raise Problem(f"Each message needs role user or assistant and 1–{MAX_CHARS} characters of content")
        if messages[-1]["role"] != "user":
            raise Problem("The last message must come from the user")
        if not self.llm:
            raise Problem("The copilot needs an LLM; set DUVORA_AI_URL and DUVORA_AI_MODEL", 503)
        now = time.time()
        with self.lock:
            calls = self.copilot_calls.setdefault(actor, deque())
            while calls and now - calls[0] > 60:
                calls.popleft()
            if len(calls) >= RATE:
                raise Problem("Copilot rate limit reached; try again in a minute", 429)
            calls.append(now)
        red = self.redactor()
        convo = [{"role": "system", "content": SYSTEM + f" The operator's role is {role}."
                  + (" Only admins can draft plans; do not offer to." if role != "admin" else "")}]
        convo += [{"role": m["role"], "content": red.redact(m["content"])} for m in messages]
        used, plans, reply = [], [], None
        for _ in range(MAX_STEPS):
            try:
                msg = self.llm.chat(convo, tools=TOOLS)
            except LlmError as exc:
                raise Problem(str(exc), 503) from None
            calls = msg.get("tool_calls") or []
            if not calls:
                reply = msg.get("content") if isinstance(msg.get("content"), str) else ""
                break
            convo.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for call in calls[:8]:
                fn = (call or {}).get("function") or {}
                name = fn.get("name")
                try:
                    args = fn.get("arguments") or {}
                    args = red.restore_value(json.loads(args) if isinstance(args, str) else args)
                    result, ok = self.tool(actor, role, name, args), True
                    if name == "draft_plan":
                        plans.append(result)
                except (Problem, ValueError, TypeError) as exc:
                    result, ok = {"error": str(exc)}, False
                used.append({"name": name, "ok": ok})
                text = red.redact(canonical(result))
                convo.append({"role": "tool", "tool_call_id": call.get("id") or name, "name": name,
                              "content": "<data>" + (text if len(text) <= TOOL_RESULT_LIMIT else text[:TOOL_RESULT_LIMIT] + " …truncated") + "</data>"})
        if reply is None:
            reply = "I could not finish within the tool budget; try a narrower question."
        with self.transaction():
            self.event(actor, "copilot.asked", {"chars": len(messages[-1]["content"]), "tools": [u["name"] for u in used]})
        return {"reply": red.restore(reply).strip()[:8000], "tools": used, "plans": plans, "model": self.llm.model}

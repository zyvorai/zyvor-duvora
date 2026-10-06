"""AI features: local analytics, the optional LLM client (against a fake OpenAI-compatible server) and the copilot."""
import json
import os
import random
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from duvora.common import Problem
from duvora.core import Store
from duvora.ebpf import replay
from duvora.insights import WARMUP, ewma_update, hypotheses, is_anomalous, linear_fit, suggest_policies
from duvora.llm import LlmClient, Redactor
from duvora.server import Application


class FakeModel:
    """A scripted /v1/chat/completions endpoint that records every request."""

    def __init__(self):
        self.replies, self.requests, self.status = [], [], 200
        model = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                model.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                if model.status != 200:
                    self.send_response(model.status)
                    self.end_headers()
                    return
                message = model.replies.pop(0) if model.replies else {"role": "assistant", "content": "ok"}
                data = json.dumps({"choices": [{"message": message}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def client(self, **kw):
        return LlmClient(self.url, key="sk-test", model="fake-1", timeout=5, **kw)

    def sent_text(self, i=-1):
        return json.dumps(self.requests[i]["body"]["messages"])


def tool_call(name, args, ident="c1"):
    return {"role": "assistant", "content": "", "tool_calls": [{"id": ident, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


def device(ident="dev-1", host="node-a", **extra):
    d = {"id": ident, "model": "x", "host": host, "site": "lab", "source": "linux-pci", "firmware": "x", "health": "healthy",
         "metrics": {}, "interfaces": [], "last_seen": time.time(), "version": 1, "mode": "observe", "services": [],
         "policy_ids": [], "capabilities": ["read-only"]}
    d.update(extra)
    return d


class Base(unittest.TestCase):
    demo = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"), demo=self.demo)
        self.app = Application(self.store, {})

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def add(self, d):
        with self.store.transaction():
            self.store.put("devices", d["id"], d)

    def samples(self, ident, values, metric="pps", start=None, step=15):
        start = start or time.time() - step * len(values)
        with self.store.transaction():
            for i, v in enumerate(values):
                self.store.record_sample(ident, {metric: v}, start + i * step)


class BaselineMathTests(unittest.TestCase):
    def feed(self, values, floor=1.0):
        s = {"floor": floor}
        for v in values:
            s = ewma_update(s, v)
        return s

    def test_streak_and_warmup(self):
        normal = [10 + (i % 3) for i in range(WARMUP + 10)]
        s = self.feed(normal + [60, 60])
        self.assertFalse(is_anomalous(s))
        s = ewma_update(s, 60)
        self.assertTrue(is_anomalous(s))
        self.assertGreater(s["z"], 4)
        # A spike up then down is two blips, not a shift.
        self.assertFalse(is_anomalous(self.feed(normal + [60, 60, -40])))
        # Not before the warm-up completes.
        self.assertFalse(is_anomalous(self.feed([10] * 5 + [500] * 3)))

    def test_floor_stops_flat_series_from_alarming(self):
        s = self.feed([100.0] * 50 + [100.5] * 3, floor=5.0)
        self.assertFalse(is_anomalous(s))

    def test_linear_fit(self):
        a, b, r2 = linear_fit([(x, 2 * x + 1) for x in range(10)])
        self.assertAlmostEqual(a, 1)
        self.assertAlmostEqual(b, 2)
        self.assertAlmostEqual(r2, 1)
        self.assertIsNone(linear_fit([(1, 1)]))


class AnomalyRuleTests(Base):
    def test_anomaly_fires_and_resolves(self):
        self.add(device())
        self.samples("dev-1", [100 + (i % 5) for i in range(40)])
        self.store.evaluate_alerts(force=True)
        self.assertFalse([i for i in self.store.incidents("active") if i["rule"] == "anomaly"])
        self.samples("dev-1", [900, 950, 920], start=time.time())
        self.store.evaluate_alerts(force=True)
        inc = [i for i in self.store.incidents("active") if i["rule"] == "anomaly"]
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["target"], "dev-1")
        self.assertIn("pps", inc[0]["title"])
        self.assertEqual(self.store.anomalies()[0]["metric"], "pps")
        self.samples("dev-1", [101, 102, 100], start=time.time() + 60)
        self.store.evaluate_alerts(force=True)
        self.assertFalse([i for i in self.store.incidents("active") if i["rule"] == "anomaly"])

    def test_threshold_comes_from_the_rule(self):
        self.add(device())
        self.samples("dev-1", [100 + (i % 5) for i in range(40)] + [140, 140, 140])
        self.assertTrue(self.store.anomalies())
        self.store.update_rule("admin", "anomaly", {"threshold": 50})
        self.assertFalse(self.store.anomalies())

    def test_baselines_survive_restart(self):
        self.add(device())
        self.samples("dev-1", [100] * 10)
        path = os.path.join(self.tmp.name, "t.db")
        self.store.close()
        self.store = Store(path)
        self.assertEqual(self.store.baselines[("dev-1", "pps")]["n"], 10)


class DestinationTests(Base):
    def flow(self, peer, ts, port=443, size=5000):
        return {"peer": peer, "port": port, "protocol": "tcp", "packets": 5, "bytes": size,
                "observedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))}

    def test_new_destination_after_warmup(self):
        now = time.time()
        self.add(device())
        self.store.observe_destinations("dev-1", [self.flow("1.1.1.1", now - 7200)], now - 7200)
        self.store.observe_destinations("dev-1", [self.flow("1.1.1.1", now), self.flow("9.9.9.9", now), self.flow("8.8.4.4", now, size=10)], now)
        new = self.store.new_destinations(now=now)
        self.assertEqual([(x["peer"], x["port"]) for x in new], [("9.9.9.9", 443)])
        self.store.evaluate_alerts(now, force=True)
        inc = [i for i in self.store.incidents("active") if i["rule"] == "new-destination"]
        self.assertEqual(len(inc), 1)
        self.assertIn("9.9.9.9:443/tcp", inc[0]["detail"])
        # Not new any more after the 15-minute window.
        self.assertEqual(self.store.new_destinations(now=now + 1200), [])

    def test_no_alerts_during_warmup_and_persisted(self):
        now = time.time()
        self.store.observe_destinations("dev-1", [self.flow("9.9.9.9", now)], now - 600)
        self.assertEqual(self.store.new_destinations(now=now), [])
        self.store.persist_destinations(now, force=True)
        row = self.store.db.execute("SELECT body FROM destinations WHERE device='dev-1'").fetchone()
        self.assertIn("9.9.9.9|443|tcp", json.loads(row[0])["peers"])

    def test_destination_seen_long_ago_is_new_again(self):
        now = time.time()
        self.store.observe_destinations("dev-1", [self.flow("9.9.9.9", now - 3 * 86400)], now - 3 * 86400)
        self.store.observe_destinations("dev-1", [self.flow("9.9.9.9", now)], now)
        self.assertEqual(len(self.store.new_destinations(now=now)), 1)


class ForecastTests(Base):
    def test_rising_temperature_forecast_and_alert(self):
        self.add(device())
        now = time.time()
        # 6 hours of 5-minute samples rising 3 °C per hour from 50 °C.
        self.samples("dev-1", [50 + 3 * (i * 5 / 60) for i in range(72)], "temperature_c", start=now - 72 * 300, step=300)
        f = next(x for x in self.store.forecast("dev-1")["forecasts"] if x["metric"] == "temperature_c")
        self.assertTrue(f["reliable"])
        self.assertAlmostEqual(f["slope_per_hour"], 3, places=1)
        self.assertGreater(f["r2"], 0.99)
        self.assertAlmostEqual(f["eta_hours"], (80 - 68) / 3, delta=0.6)
        self.store.evaluate_alerts(force=True)
        inc = [i for i in self.store.incidents("active") if i["rule"] == "forecast-breach"]
        self.assertEqual(len(inc), 1)
        self.store.update_rule("admin", "forecast-breach", {"threshold": 1})
        self.store.forecast_cache.clear()
        self.store.evaluate_alerts(force=True)
        self.assertFalse([i for i in self.store.incidents("active") if i["rule"] == "forecast-breach"])

    def test_noise_is_not_a_forecast(self):
        self.add(device(metrics={"link_gbps": 100}))
        rnd = random.Random(7)
        now = time.time()
        self.samples("dev-1", [60 + rnd.uniform(-10, 10) for _ in range(72)], "throughput_gbps", start=now - 72 * 300, step=300)
        f = next(x for x in self.store.forecast("dev-1")["forecasts"] if x["metric"] == "throughput_gbps")
        self.assertEqual(f["threshold"], 90)
        self.assertFalse(f["reliable"])
        self.assertIsNone(f["eta_hours"])

    def test_too_few_points(self):
        self.add(device())
        self.samples("dev-1", [50, 51, 52], "temperature_c", step=300)
        f = self.store.forecast("dev-1")["forecasts"][0]
        self.assertEqual((f["reliable"], f["eta_hours"]), (False, None))


class SuggestionTests(Base):
    FLOWS = [{"peer": f"10.0.0.{i}", "port": 443, "protocol": "tcp", "packets": 10, "bytes": 1000 * i} for i in range(1, 20)] + \
            [{"peer": "1.1.1.1", "port": 53, "protocol": "udp", "packets": 2, "bytes": 200},
             {"peer": "not-an-ip", "port": 1, "bytes": 99999}]

    def test_ranked_by_coverage_then_narrowness(self):
        out = suggest_policies(self.FLOWS)
        best = out["candidates"][0]
        self.assertEqual((best["cidr"], best["ports"]), ("10.0.0.0/24", [443]))
        total = sum(r["bytes"] for r in self.FLOWS[:-1])
        self.assertEqual(out["bytes"], total)
        self.assertAlmostEqual(best["coverage_bytes"], round(1 - replay(self.FLOWS, best["cidr"], best["ports"])["would_block_bytes"] / total, 4))
        self.assertEqual(best["would_block_top"][0]["peer"], "1.1.1.1")
        self.assertLessEqual(len(out["candidates"]), 5)
        widths = [c["addresses"] for c in out["candidates"] if round(c["coverage_bytes"], 2) == round(best["coverage_bytes"], 2)]
        self.assertEqual(widths, sorted(widths))

    def test_empty_and_store_endpoint(self):
        self.assertEqual(suggest_policies([])["candidates"], [])
        self.add(device())
        self.store.netra_flows["dev-1"] = self.FLOWS
        out = self.app.dispatch("GET", "/api/v1/devices/dev-1/allowlist-suggestions", "viewer", "viewer")
        self.assertEqual(out["candidates"][0]["policy"], {"name": "allow-observed", "tenant": "ops", "cidr": "10.0.0.0/24", "ports": [443]})
        # The suggestion is a valid plan policy.
        self.assertEqual(self.store.validate_spec({"action": "isolate", "devices": ["dev-1"], "policy": out["candidates"][0]["policy"]})["policy"]["cidr"], "10.0.0.0/24")


def evidence(rule="packet-drops", **ebpf):
    inc = {"id": "i1", "rule": rule, "target": "dev-1", "title": "t", "detail": "d", "severity": "warning", "state": "open", "opened": time.time()}
    return {"incident": inc, "device": {"metrics": {"tcp_retransmits_pm": 0}, "health": "healthy"}, "ebpf": ebpf, "jobs": [], "related": [], "anomalies": []}


class HypothesisTests(Base):
    def test_rules(self):
        h = hypotheses(evidence("isolation-blocked", isolation={"mode": "enforce", "blocked_delta": 5, "top": [{"address": "9.9.9.9", "port": 53}]}))
        self.assertEqual((h[0]["id"], h[0]["confidence"]), ("isolation-blocking", "high"))
        self.assertIn("9.9.9.9:53", h[0]["text"])
        self.assertIn("closed-port", [x["id"] for x in hypotheses(evidence(drop_reasons=[{"reason": "NO_SOCKET", "count": 3}]))])
        self.assertEqual(hypotheses(evidence("ebpf-detached", stale=True, age=300))[0]["id"], "agent-down")
        self.assertEqual(hypotheses(evidence("other"))[0]["id"], "none")

    def test_explain_without_model(self):
        self.add(device(ebpf={"provider": "native", "node": "node-a", "stale": False, "drop_reasons": [], "talkers": [],
                              "isolation": {"mode": "enforce", "blocked_delta": 7, "top": [{"address": "9.9.9.9", "port": 443}]}}))
        self.store.evaluate_alerts(force=True)
        inc = next(i for i in self.store.incidents("active") if i["rule"] == "isolation-blocked")
        ev = self.app.dispatch("GET", f"/api/v1/incidents/{inc['id']}/explain", "viewer", "viewer", query={})
        self.assertEqual(ev["hypotheses"][0]["id"], "isolation-blocking")
        self.assertEqual(ev["narrative_source"], "template")
        self.assertIn("Enforced node isolation", ev["narrative"])
        with self.assertRaises(Problem):
            self.store.explain_incident("missing")


class RedactorTests(unittest.TestCase):
    def test_roundtrip(self):
        r = Redactor(["node-a", "dev-1"])
        text = r.redact("dev-1 on node-a sends to 10.1.2.3 and 2001:db8::1, not node-ab; 12:30:45")
        self.assertNotIn("10.1.2.3", text)
        self.assertEqual(r.restore(r.redact("top 10.9.8.7:443")), "top 10.9.8.7:443")
        self.assertNotIn("10.9.8.7", r.redact("top 10.9.8.7:443 and 192.0.2.0/24."))
        self.assertNotIn("2001:db8::1", text)
        self.assertNotIn("node-a ", text)
        self.assertIn("node-ab", text)
        self.assertIn("12:30:45", text)
        self.assertEqual(r.restore(text), "dev-1 on node-a sends to 10.1.2.3 and 2001:db8::1, not node-ab; 12:30:45")
        self.assertEqual(r.restore_value({"device": r.redact("dev-1")}), {"device": "dev-1"})
        self.assertEqual(Redactor(["node-a"], enabled=False).redact("node-a 10.0.0.1"), "node-a 10.0.0.1")


class LlmTests(Base):
    def setUp(self):
        super().setUp()
        self.model = FakeModel()
        self.addCleanup(self.model.close)

    def test_client_config(self):
        with self.assertRaises(ValueError):
            LlmClient("http://llm.example.com/v1", model="m")
        with self.assertRaises(ValueError):
            LlmClient("https://llm.example.com/v1")
        self.assertEqual(LlmClient("http://ollama.ai.svc:11434/v1", model="m", allow_http=True).url, "http://ollama.ai.svc:11434/v1")

    def incident(self):
        self.add(device(ebpf={"provider": "native", "node": "node-a", "stale": False, "drop_reasons": [], "talkers": [],
                              "isolation": {"mode": "enforce", "blocked_delta": 7, "top": [{"address": "10.9.8.7", "port": 443}]}}))
        self.store.evaluate_alerts(force=True)
        return next(i for i in self.store.incidents("active") if i["rule"] == "isolation-blocked")

    def test_explain_with_model_redacted_and_cached(self):
        self.store.init_ai(self.model.client(redact=True))
        inc = self.incident()
        self.model.replies.append({"role": "assistant", "content": "host-1 is dropping traffic to ip-1; check the allow-list."})
        ev = self.store.explain_incident(inc["id"])
        sent = self.model.sent_text()
        self.assertEqual(self.model.requests[0]["path"], "/v1/chat/completions")
        self.assertEqual(self.model.requests[0]["auth"], "Bearer sk-test")
        self.assertNotIn("10.9.8.7", sent)
        self.assertNotIn("node-a", sent)
        self.assertIn("<data>", sent)
        self.assertEqual(ev["narrative_source"], "llm")
        self.assertIn("10.9.8.7", ev["narrative"])
        self.store.explain_incident(inc["id"])
        self.assertEqual(len(self.model.requests), 1)

    def test_model_failure_falls_back(self):
        self.store.init_ai(self.model.client())
        self.model.status = 500
        inc = self.incident()
        ev = self.store.explain_incident(inc["id"])
        self.assertEqual(ev["narrative_source"], "template")
        self.assertIn("HTTP 500", ev["narrative_error"])
        b = self.store.briefing(ai=True)
        self.assertEqual(b["summary_source"], "template")
        self.assertIn("Fleet score", b["summary"])

    def test_briefing_summary(self):
        self.store.init_ai(self.model.client())
        self.model.replies.append({"role": "assistant", "content": "All quiet."})
        b = self.app.dispatch("GET", "/api/v1/report", "viewer", "viewer", query={"ai": "1"})
        self.assertEqual((b["summary"], b["summary_source"]), ("All quiet.", "llm"))
        self.assertIn("AI-written", b["markdown"])
        self.assertIsNone(self.store.briefing()["summary"])
        self.assertTrue(self.app.dispatch("GET", "/api/v1/ai", "viewer", "viewer")["llm"])


class CopilotTests(Base):
    demo = True

    def setUp(self):
        super().setUp()
        self.model = FakeModel()
        self.addCleanup(self.model.close)
        self.store.init_ai(self.model.client())
        self.spec = {"action": "isolate", "devices": ["bf3-01"], "policy": {"name": "egress", "tenant": "ops", "cidr": "10.0.0.0/8", "ports": [443]}}

    def ask(self, role="admin", text="isolate bf3-01 to 10/8 on 443"):
        return self.app.dispatch("POST", "/api/v1/copilot", "alice", role, {"messages": [{"role": "user", "content": text}]})

    def test_tool_loop_drafts_but_never_applies(self):
        self.model.replies += [tool_call("fleet_summary", {}), tool_call("draft_plan", {"spec": self.spec}, "c2"),
                               {"role": "assistant", "content": "Drafted; review and confirm it."}]
        out = self.ask()
        self.assertEqual(out["reply"], "Drafted; review and confirm it.")
        self.assertEqual([t["name"] for t in out["tools"]], ["fleet_summary", "draft_plan"])
        self.assertTrue(all(t["ok"] for t in out["tools"]))
        self.assertEqual(len(out["plans"]), 1)
        self.assertEqual(out["plans"][0]["confirmation"], "APPLY SIMULATION")
        self.assertEqual(self.store.rows("jobs"), [])
        self.assertEqual(len(self.model.requests), 3)
        self.assertEqual(self.model.requests[0]["body"]["model"], "fake-1")
        self.assertIn("draft_plan", json.dumps(self.model.requests[0]["body"]["tools"]))
        tool_msg = self.model.requests[1]["body"]["messages"][-1]
        self.assertEqual((tool_msg["role"], tool_msg["tool_call_id"]), ("tool", "c1"))
        self.assertTrue(tool_msg["content"].startswith("<data>"))
        actions = [a["action"] for a in self.store.snapshot()["audit"]]
        self.assertIn("copilot.asked", actions)
        self.assertIn("copilot.plan-drafted", actions)
        # The drafted plan is applied only through the normal API with its confirmation.
        job = self.store.apply("alice", out["plans"][0]["id"], "APPLY SIMULATION")
        self.assertEqual(job["state"], "queued")

    def test_viewer_cannot_draft(self):
        self.model.replies += [tool_call("draft_plan", {"spec": self.spec}), {"role": "assistant", "content": "I can't."}]
        out = self.ask("viewer")
        self.assertEqual(out["tools"], [{"name": "draft_plan", "ok": False}])
        self.assertEqual(out["plans"], [])
        self.assertIn("requires an admin", self.model.requests[1]["body"]["messages"][-1]["content"])
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM plans").fetchone()[0], 0)

    def test_tool_errors_and_budget(self):
        self.model.replies += [tool_call("device_details", {"device": "nope"})] * 6
        out = self.ask()
        self.assertIn("tool budget", out["reply"])
        self.assertEqual(len(out["tools"]), 6)
        self.assertFalse(any(t["ok"] for t in out["tools"]))

    def test_validation_rate_limit_and_unconfigured(self):
        for body in ({}, {"messages": []}, {"messages": [{"role": "system", "content": "x"}]},
                     {"messages": [{"role": "user", "content": "x" * 5000}]},
                     {"messages": [{"role": "user", "content": "q"}, {"role": "assistant", "content": "a"}]}):
            with self.assertRaises(Problem):
                self.app.dispatch("POST", "/api/v1/copilot", "alice", "admin", body)
        self.store.copilot_calls["alice"] = __import__("collections").deque([time.time()] * 20)
        with self.assertRaises(Problem) as ctx:
            self.ask()
        self.assertEqual(ctx.exception.status, 429)
        self.store.init_ai(None)
        self.store.llm = None
        with self.assertRaises(Problem) as ctx:
            self.ask("viewer")
        self.assertEqual(ctx.exception.status, 503)
        with self.assertRaises(Problem):
            self.app.dispatch("POST", "/api/v1/copilot", "agent:x", "agent", {"messages": [{"role": "user", "content": "q"}]})

    def test_redaction_restores_tool_arguments(self):
        self.store.llm.redact = True
        self.model.replies += [tool_call("fleet_summary", {}), {"role": "assistant", "content": "x"}]
        self.ask(text="how is gpu-01?")
        self.assertNotIn("gpu-01", self.model.sent_text(0))
        # bf3-01 is the first name in the question, so the model sees it as host-1 and calls back with that token.
        self.model.replies += [tool_call("device_details", {"device": "host-1"}), {"role": "assistant", "content": "fine"}]
        out = self.ask(text="how is bf3-01?")
        self.assertIn("host-1", self.model.sent_text(-2))
        self.assertTrue(out["tools"][0]["ok"])


class RoutesTests(Base):
    demo = True

    def test_insight_routes(self):
        call = lambda path, **q: self.app.dispatch("GET", path, "viewer", "viewer", query=q)
        self.assertFalse(call("/api/v1/ai")["llm"])
        self.assertIn("anomalies", call("/api/v1/insights"))
        self.assertEqual(call("/api/v1/devices/bf3-01/forecast")["device"], "bf3-01")
        b = call("/api/v1/report")
        for key in ("anomalies", "forecasts", "new_destinations", "allowlist_suggestions"):
            self.assertIn(key, b)
        self.assertIn("duvora_anomalies", self.app.metrics(None))
        rules = {r["id"] for r in self.store.alert_rules()}
        self.assertTrue({"anomaly", "new-destination", "forecast-breach"} <= rules)


if __name__ == "__main__":
    unittest.main()

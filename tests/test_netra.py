# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from duvora.core import Store
from duvora.ebpf import replay
from duvora.netra import NetraClient, NetraError, collect, summarize, top_talkers

from fake_netra import API_KEY, FakeNetra


class NetraBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.netra = FakeNetra()
        self.client = NetraClient(self.netra.url, API_KEY)
        with patch.dict(os.environ, {"DUVORA_NETRA_DISCOVER": "1"}):
            self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.store.configure_netra(self.netra.url)

    def tearDown(self):
        self.store.close()
        self.netra.close()
        self.tmp.cleanup()

    def sync(self, now):
        raw = collect(self.client, self.store.netra_wanted_nodes())
        raw["fetched"] = now
        return self.store.ingest_netra(raw, now)

    def test_client_validation_and_auth(self):
        with self.assertRaises(ValueError):
            NetraClient("http://netra.example:30870", API_KEY)
        with self.assertRaises(ValueError):
            NetraClient(self.netra.url, "")
        with self.assertRaises(NetraError) as ctx:
            NetraClient(self.netra.url, "wrong-key").get("/fleet")
        self.assertEqual(ctx.exception.status, 401)

    def test_discovery_rates_and_probe(self):
        status = self.sync(1000.0)
        self.assertTrue(status["connected"])
        device = self.store.device("netra-dpu-node-1")
        self.assertEqual(device["source"], "netra-ebpf")
        self.assertEqual(device["ebpf"]["kernel"], "6.8.0-test")
        self.assertTrue(device["ebpf"]["nodeiso_available"])
        self.assertNotIn("pps", device["metrics"])  # first pass has no delta
        self.netra.advance(bytes=1_250_000_000, packets=100_000, drops=4, retransmits=300, resets=60)
        self.sync(1010.0)
        device = self.store.device("netra-dpu-node-1")
        self.assertEqual(device["metrics_source"], "netra-ebpf")
        self.assertEqual(device["metrics"]["throughput_gbps"], 1.0)
        self.assertEqual(device["metrics"]["pps"], 10000.0)
        self.assertEqual(device["metrics"]["drops"], 4)
        self.assertEqual(device["metrics"]["tcp_retransmits_pm"], 1800.0)
        self.assertEqual(device["ebpf"]["drop_reasons"][0]["reason"], "NO_SOCKET")
        self.assertEqual(device["ebpf"]["talkers"][0]["peer"], "10.0.0.5")
        row = self.store.db.execute("SELECT metrics FROM samples WHERE device=? ORDER BY ts DESC LIMIT 1",
                                    ("netra-dpu-node-1",)).fetchone()
        self.assertIn('"pps"', row["metrics"])

    def test_counter_reset_skips_interval(self):
        self.sync(1000.0)
        self.netra.counters["bytes"] = 10
        self.netra.counters["packets"] = 1
        self.sync(1010.0)
        self.assertNotIn("throughput_gbps", self.store.device("netra-dpu-node-1")["metrics"])

    def test_alerts_from_ebpf(self):
        self.sync(1000.0)
        self.netra.advance(drops=9, retransmits=600)
        self.sync(1010.0)
        self.store.evaluate_alerts(force=True)
        incidents = {i["rule"]: i for i in self.store.incidents("active")}
        self.assertIn("tcp-retransmits", incidents)
        self.assertIn("NO_SOCKET", incidents["packet-drops"]["detail"])

    def test_simulated_devices_are_never_matched(self):
        with patch.dict(os.environ, {"DUVORA_NETRA_NODE_MAP": '{"bf3-01": "dpu-node-1"}'}):
            store = Store(str(Path(self.tmp.name) / "demo.db"), demo=True)
        try:
            raw = collect(self.client, [])
            store.ingest_netra(raw, 1000.0)
            self.assertNotIn("ebpf", store.device("bf3-01"))
            self.assertEqual(store.netra["unmatched"], ["dpu-node-1"])
        finally:
            store.close()

    def test_observed_device_matched_by_host_keeps_ebpf_through_reports(self):
        with patch.dict(os.environ, {"DUVORA_NETRA_NODE_MAP": '{"gpu-01": "dpu-node-1"}'}):
            store = Store(str(Path(self.tmp.name) / "obs.db"))
        try:
            store.report("agent:gpu-01", {"id": "pci-1", "host": "gpu-01", "source": "linux-pci", "metrics": {"temperature_c": 50}})
            store.ingest_netra(collect(self.client, []), 1000.0)
            self.netra.advance(bytes=125_000_000, packets=1000)
            store.ingest_netra(collect(self.client, store.netra_wanted_nodes()), 1010.0)
            store.report("agent:gpu-01", {"id": "pci-1", "host": "gpu-01", "source": "linux-pci", "metrics": {"temperature_c": 51}})
            d = store.device("pci-1")
            self.assertEqual(d["ebpf"]["node"], "dpu-node-1")
            self.assertEqual(d["metrics"]["temperature_c"], 51)
            self.assertEqual(d["metrics"]["throughput_gbps"], 0.1)
        finally:
            store.close()

    def test_unreachable_netra_reports_disconnected(self):
        client = NetraClient("http://127.0.0.1:9", API_KEY, timeout=1)
        status = self.store.ingest_netra(collect(client, []), 1000.0)
        self.assertFalse(status["connected"])
        self.assertIn("unreachable", status["error"])

    def test_isolation_unsupported_on_older_netra(self):
        self.netra.isolation_enabled = False
        status = self.sync(1000.0)
        self.assertFalse(status["isolation_supported"])
        self.assertFalse(self.store.device("netra-dpu-node-1")["ebpf"]["nodeiso_available"])

    def test_replay_and_talkers_helpers(self):
        result = replay(self.netra.flows, "10.0.0.0/8", [443])
        self.assertEqual(result["flows"], 2)
        self.assertEqual(result["would_block_flows"], 1)
        self.assertEqual(result["top"][0]["peer"], "8.8.8.8")
        self.assertEqual(result["unresolved"], 1)
        self.assertEqual(top_talkers(self.netra.flows, now=4070908800.0)[0]["bytes"], 50_000)
        self.assertEqual(summarize({"fleet": {"nodes": [{"node": "x"}]}})["x"]["drops"], 0)


if __name__ == "__main__":
    unittest.main()


class NetraEnforcementTests(unittest.TestCase):
    DEVICE = "netra-dpu-node-1"
    POLICY = {"name": "egress", "tenant": "ops", "cidr": "10.0.0.0/8", "ports": [443, 444, 445, 8443]}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.netra = FakeNetra()
        self.client = NetraClient(self.netra.url, API_KEY)
        with patch.dict(os.environ, {"DUVORA_NETRA_DISCOVER": "1"}):
            self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.store.configure_netra(self.netra.url, True, self.client)
        self.sync()

    def tearDown(self):
        self.store.close()
        self.netra.close()
        self.tmp.cleanup()

    def sync(self):
        self.store.ingest_netra(collect(self.client, self.store.netra_wanted_nodes()))

    def run_plan(self, stage="shadow", action="isolate"):
        spec = {"action": action, "devices": [self.DEVICE]}
        if action == "isolate":
            spec.update(policy=self.POLICY, stage=stage)
        plan = self.store.plan("admin", spec)
        self.assertEqual(plan["blockers"], [])
        job = self.store.apply("admin", plan["id"], plan["confirmation"])
        self.assertEqual(job["mode"], "netra")
        self.store.netra_duties()
        return plan, self.store.db.execute("SELECT body FROM jobs WHERE id=?", (job["id"],)).fetchone()[0]

    def iso(self):
        return self.store.device(self.DEVICE).get("netra_isolation")

    def test_shadow_then_enforce_then_release(self):
        plan, _ = self.run_plan()
        self.assertEqual(plan["mode"], "netra-shadow")
        self.assertIn("shadow", plan)
        put = self.netra.isolations["dpu-node-1"]
        self.assertEqual(put["mode"], "shadow")
        self.assertIsNone(put["leaseUntil"])
        self.assertEqual(put["rules"], [{"cidr": "10.0.0.0/8", "portFrom": 443, "portTo": 445},
                                        {"cidr": "10.0.0.0/8", "portFrom": 8443, "portTo": 8443}])
        self.assertEqual(self.iso()["stage"], "shadow")
        self.assertEqual(self.store.device(self.DEVICE)["mode"], "shadow")

        plan, _ = self.run_plan("enforce")
        self.assertEqual(plan["confirmation"], f"ENFORCE ON {self.DEVICE}")
        self.assertEqual(self.netra.isolations["dpu-node-1"]["mode"], "enforce")
        self.assertEqual(self.netra.isolations["dpu-node-1"]["leaseUntil"], "900s")
        self.assertEqual(self.store.device(self.DEVICE)["mode"], "isolated")
        policies = [p for p in self.store.rows("policies") if self.DEVICE in p["devices"]]
        self.assertEqual([p["mode"] for p in policies], ["netra-enforce"])

        self.run_plan(action="release")
        self.assertNotIn("dpu-node-1", self.netra.isolations)
        self.assertIsNone(self.iso())
        self.assertEqual(self.store.device(self.DEVICE)["mode"], "observe")

    def test_enforce_gates(self):
        spec = {"action": "isolate", "devices": [self.DEVICE], "policy": self.POLICY, "stage": "enforce"}
        self.assertTrue(any("shadow first" in b for b in self.store.plan("admin", spec)["blockers"]))
        self.run_plan()
        self.store.netra["enforce_allowed"] = False
        self.assertTrue(any("disabled" in b for b in self.store.plan("admin", spec)["blockers"]))
        self.store.netra["enforce_allowed"] = True
        plan = self.store.plan("admin", spec)
        self.assertEqual(plan["blockers"], [])
        with self.assertRaises(Exception):
            self.store.apply("admin", plan["id"], "APPLY SIMULATION")
        self.store.kill_switch("admin", True)
        with self.assertRaisesRegex(Exception, "kill switch"):
            self.store.apply("admin", plan["id"], plan["confirmation"])

    def test_kill_switch_demotes_and_persists(self):
        self.run_plan()
        self.run_plan("enforce")
        out = self.store.kill_switch("admin", True)
        self.assertEqual(out["demoted"], [self.DEVICE])
        self.assertEqual(self.netra.isolations["dpu-node-1"]["mode"], "shadow")
        self.assertEqual(self.iso()["stage"], "shadow")
        self.store.close()
        self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.assertTrue(self.store.killed())
        self.store.kill_switch("admin", False)
        self.assertFalse(self.store.killed())

    def test_rollback_never_reenforces(self):
        self.run_plan()
        self.run_plan("enforce")
        _, release = self.run_plan(action="release")
        job = json.loads(release)
        self.store.rollback("admin", job["id"])
        self.assertEqual(self.netra.isolations["dpu-node-1"]["mode"], "shadow")
        self.assertEqual(self.iso()["stage"], "shadow")

    def test_rollback_of_first_shadow_deletes(self):
        _, job = self.run_plan()
        self.store.rollback("admin", json.loads(job)["id"])
        self.assertNotIn("dpu-node-1", self.netra.isolations)
        self.assertIsNone(self.iso())

    def test_failed_put_fails_job(self):
        self.netra.refuse = True
        _, job = self.run_plan()
        self.assertEqual(json.loads(job)["state"], "failed")
        self.assertIsNone(self.iso())

    def test_lease_renewal(self):
        self.run_plan()
        self.run_plan("enforce")
        before = self.netra.isolations["dpu-node-1"]["revision"]
        ni = self.iso()
        ni["lease_until"] = 0
        d = self.store.device(self.DEVICE)
        d["netra_isolation"] = ni
        self.store.put("devices", self.DEVICE, d)
        self.store.netra_duties()
        self.assertEqual(self.netra.isolations["dpu-node-1"]["revision"], before + 1)
        self.assertGreater(self.iso()["lease_until"], 0)

    def test_drift_when_netra_removes_or_demotes(self):
        self.run_plan()
        self.run_plan("enforce")
        self.netra.isolations["dpu-node-1"]["mode"] = "shadow"
        self.netra.isolations["dpu-node-1"]["effectiveMode"] = "shadow"
        self.sync()
        self.assertEqual(self.iso()["stage"], "shadow")
        self.netra.isolations.clear()
        self.sync()
        self.assertIsNone(self.iso())
        self.assertEqual(self.store.device(self.DEVICE)["mode"], "observe")

    def test_enforced_drops_raise_alert(self):
        self.run_plan()
        self.run_plan("enforce")
        self.sync()
        self.netra.isolations["dpu-node-1"].update(blockedPackets=25, top=[{"address": "8.8.8.8", "port": 53}])
        self.sync()
        self.store.evaluate_alerts(force=True)
        incidents = {i["rule"]: i for i in self.store.incidents("active")}
        self.assertIn("isolation-blocked", incidents)
        self.assertIn("8.8.8.8:53", incidents["isolation-blocked"]["detail"])

    def test_invalid_stage_rejected(self):
        spec = {"action": "isolate", "devices": [self.DEVICE], "policy": self.POLICY, "stage": "bogus"}
        with self.assertRaises(Exception):
            self.store.plan("admin", spec)

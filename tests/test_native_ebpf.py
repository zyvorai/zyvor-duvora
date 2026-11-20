# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

"""Native eBPF: encoding, parsing, agent safety logic and the control-plane flow. Runs on any OS."""
import ipaddress
import json
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from duvora.bpf import nodeiso
from duvora.bpf.libbpf import percpu_size, sum_percpu
from duvora.bpf.runtime import EbpfAgent, decide
from duvora.bpf.sensors import default_route_interfaces, flow_records, parse_drop_reasons
from duvora.common import Problem
from duvora.core import Store
from duvora.ebpf import native_summary
from duvora.server import Application, load_keys

HOST = "node-a"
ACTOR = f"agent:{HOST}"
POLICY = {"name": "egress", "tenant": "ops", "cidr": "10.0.0.0/8", "ports": [53, 443]}

DROP_FORMAT = '''name: kfree_skb
print fmt: "skbaddr=%p reason: %s", REC->skbaddr, __print_symbolic(REC->reason, { 2, "NOT_SPECIFIED" }, { 3, "NO_SOCKET" }, { 77, "QUEUE_PURGE" })
'''
ROUTE4 = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eno1\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eno1\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
cilium_host\t0000000A\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0
"""
ROUTE6 = ("00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eno2\n"
          "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n")


def summary(**extra):
    s = {"hostname": HOST, "kernel": "7.0.0", "btf": True, "programs": ["duvora_iface_egress", "duvora_kfree_skb"],
         "program_count": 3, "attached": 6, "interfaces": {"eno1": {"packets": 1000, "bytes": 500000, "blocked": 0}},
         "drops": 1, "drop_reasons": [{"reason": "NO_SOCKET", "count": 4}], "tcp": {"retransmits": 2, "resets": 3},
         "flows": [{"peer": "1.1.1.1", "port": 443, "protocol": "tcp", "packets": 4, "bytes": 272,
                    "observedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}],
         "nodeiso_available": True, "isolation": None, "drop_info_unavailable": "", "tcp_unavailable": ""}
    s.update(extra)
    return s


class EncodingTests(unittest.TestCase):
    def test_rule_roundtrip_v4_v6(self):
        raw = nodeiso.encode_rule("10.1.2.0/24", 443, 445, 6)
        self.assertEqual(len(raw), 40)
        self.assertEqual(nodeiso.decode_rule(raw), {"cidr": "10.1.2.0/24", "protocol": 6, "portFrom": 443, "portTo": 445})
        family, _, _, _, _, addr, mask = nodeiso.RULE.unpack(raw)
        self.assertEqual((family, addr[:4], mask[:4], mask[4:]), (4, bytes([10, 1, 2, 0]), b"\xff\xff\xff\0", b"\0" * 12))
        self.assertEqual(nodeiso.decode_rule(nodeiso.encode_rule("2001:db8::/32"))["cidr"], "2001:db8::/32")
        # Host bits are masked off so (daddr & mask) == addr can match.
        self.assertEqual(nodeiso.decode_rule(nodeiso.encode_rule("10.1.2.3/8"))["cidr"], "10.0.0.0/8")

    def test_rule_validation(self):
        with self.assertRaises(ValueError):
            nodeiso.encode_rule("10.0.0.0/8", 0, 80)
        with self.assertRaises(ValueError):
            nodeiso.encode_rule("10.0.0.0/8", 90, 80)
        with self.assertRaises(ValueError):
            nodeiso.build_rules([{"cidr": "10.0.0.0/8"}] * 65)

    def test_build_rules_adds_controller(self):
        rules = nodeiso.build_rules([{"cidr": "10.0.0.0/8", "portFrom": 53, "portTo": 53}], ["192.0.2.7", "2001:db8::1"])
        decoded = [nodeiso.decode_rule(r) for r in rules]
        self.assertEqual(decoded[0], {"cidr": "10.0.0.0/8", "protocol": 0, "portFrom": 53, "portTo": 53})
        self.assertIn({"cidr": "192.0.2.7/32", "protocol": 6, "portFrom": 0, "portTo": 0}, decoded)
        self.assertIn({"cidr": "2001:db8::1/128", "protocol": 6, "portFrom": 0, "portTo": 0}, decoded)

    def test_percpu_sums(self):
        raw = b"".join(struct.pack("<QQ", cpu + 1, 10 * (cpu + 1)) for cpu in range(3))
        self.assertEqual(sum_percpu(raw, 16, "<QQ"), (6, 60))
        self.assertEqual(percpu_size(4), 8)
        padded = b"".join(struct.pack("<I4x", n) for n in (5, 7))
        self.assertEqual(sum_percpu(padded, 4, "<I"), (12,))

    def test_dest_decoding(self):
        key = nodeiso.DEST_KEY.pack(4, 17, 53, ipaddress.ip_address("8.8.8.8").packed.ljust(16, b"\0"))
        self.assertEqual(nodeiso.decode_dest(key, nodeiso.DEST_VALUE.pack(3, 210)),
                         {"address": "8.8.8.8", "port": 53, "protocol": "udp", "packets": 3, "bytes": 210})

    def test_drop_reasons_and_routes(self):
        self.assertEqual(parse_drop_reasons(DROP_FORMAT), {2: "NOT_SPECIFIED", 3: "NO_SOCKET", 77: "QUEUE_PURGE"})
        self.assertEqual(parse_drop_reasons(""), {})
        self.assertEqual(default_route_interfaces(ROUTE4, ROUTE6), ["eno1", "eno2"])

    def test_flow_deltas(self):
        key = (4, 6, 443, "1.1.1.1")
        first = flow_records({key: (4, 272)}, {}, 0)
        self.assertEqual((first[0]["peer"], first[0]["protocol"], first[0]["packets"]), ("1.1.1.1", "tcp", 4))
        self.assertEqual(flow_records({key: (4, 272)}, {key: (4, 272)}, 0), [])
        self.assertEqual(flow_records({key: (6, 400)}, {key: (4, 272)}, 0)[0]["bytes"], 128)
        # An LRU eviction resets the counter; the new value counts from zero.
        self.assertEqual(flow_records({key: (2, 100)}, {key: (4, 272)}, 0)[0]["packets"], 2)


class DecideTests(unittest.TestCase):
    def test_modes(self):
        now = 1000
        self.assertEqual(decide(None, now, now, 60), ("off", ""))
        self.assertEqual(decide({"mode": "shadow"}, now, None, 60), ("shadow", ""))
        enforce = {"mode": "enforce", "leaseUntil": now + 300}
        self.assertEqual(decide(enforce, now, now - 10, 60), ("enforce", ""))
        self.assertEqual(decide(enforce, now, now - 61, 60), ("shadow", "control plane unreachable"))
        self.assertEqual(decide(enforce, now, None, 60), ("shadow", "control plane unreachable"))
        self.assertEqual(decide({"mode": "enforce", "leaseUntil": now - 1}, now, now, 60), ("shadow", "lease expired"))
        self.assertEqual(decide({"mode": "enforce", "leaseUntil": None}, now, now, 60), ("shadow", "lease expired"))
        self.assertEqual(decide(enforce, now, now, 60, override=True), ("off", "local override"))


class FakeSensors:
    def snapshot(self, host, now=None):
        return {k: v for k, v in summary().items() if k not in {"nodeiso_available", "isolation"}}


class FakeIsolation:
    def __init__(self):
        self.applied = []

    def apply(self, mode, rules):
        self.applied.append((mode, [nodeiso.decode_rule(r) for r in rules]))

    def stats(self, top=5):
        return {"allowed": 5, "would_block": 2, "would_block_bytes": 120, "blocked": 0, "blocked_bytes": 0, "exempt": 1,
                "top": [{"address": "8.8.8.8", "port": 53, "protocol": "udp", "packets": 2, "bytes": 120}]}


class NativeControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {"DUVORA_EBPF_ENFORCE": "1", "DUVORA_CONTROLLER_ADDRESSES": "192.0.2.10"}):
            self.store = Store(str(Path(self.tmp.name) / "t.db"))
        self.app = Application(self.store, {})
        self.override = Path(self.tmp.name) / "isolation-off"
        self.isolation = FakeIsolation()
        self.offline = False
        self.agent = EbpfAgent(HOST, "http://127.0.0.1:8787", self.call, FakeSensors(), self.isolation,
                               failsafe=60, override_path=str(self.override))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def call(self, method, path, body):
        if self.offline:
            raise OSError("connection refused")
        return self.app.dispatch(method, path, ACTOR, "agent", body)

    @property
    def device(self):
        return self.store.device(f"ebpf-{HOST}")

    def run_plan(self, stage="shadow", action="isolate"):
        spec = {"action": action, "devices": [f"ebpf-{HOST}"]}
        if action == "isolate":
            spec.update(policy=POLICY, stage=stage)
        plan = self.store.plan("admin", spec)
        self.assertEqual(plan["blockers"], [])
        job = self.store.apply("admin", plan["id"], plan["confirmation"])
        self.store.netra_duties()
        return plan, json.loads(self.store.db.execute("SELECT body FROM jobs WHERE id=?", (job["id"],)).fetchone()[0])

    def test_report_creates_device(self):
        self.agent.step()
        d = self.device
        self.assertEqual((d["source"], d["ebpf"]["provider"], d["ebpf"]["node"]), ("duvora-ebpf", "native", HOST))
        self.assertTrue(d["ebpf"]["nodeiso_available"])
        self.assertEqual(d["interfaces"], ["eno1"])
        self.assertEqual(d["ebpf"]["talkers"][0]["peer"], "1.1.1.1")
        overview = self.store.ebpf_overview()
        self.assertEqual((overview["source"], overview["native"]["agents"]), ("auto", 1))
        self.assertEqual(overview["devices"][0]["provider"], "native")
        self.assertEqual(self.store.snapshot()["capabilities"]["ebpf_telemetry"], "native")

    def test_identity_and_source_gates(self):
        with self.assertRaises(Problem) as ctx:
            self.store.ingest_native("agent:other", {"host": HOST, "summary": summary()})
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(Problem):
            self.app.dispatch("POST", "/api/v1/agent/ebpf", "admin", "admin", {"host": HOST, "summary": summary()})
        with self.assertRaises(Problem):
            self.app.dispatch("GET", "/api/v1/agent/isolation", "viewer", "viewer")
        self.store.ebpf_source = "netra"
        with self.assertRaises(Problem) as ctx:
            self.store.ingest_native(ACTOR, {"host": HOST, "summary": summary()})
        self.assertEqual(ctx.exception.status, 409)

    def test_summary_is_sanitized(self):
        s = native_summary(HOST, summary(interfaces={"eno1": {"packets": -5, "bytes": "x"}, "bad name!": {}},
                                         flows=[{"peer": "not-an-ip"}, {"peer": "8.8.8.8", "port": 99999, "packets": True}],
                                         programs=["a" * 500], extra="ignored"))
        self.assertEqual(s["interfaces"], {"eno1": {"packets": 0, "bytes": 0, "blocked": 0}})
        self.assertEqual(s["flows"][0]["peer"], "8.8.8.8")
        self.assertEqual((s["flows"][0]["port"], s["flows"][0]["packets"]), (0, 0))
        self.assertEqual(len(s["programs"][0]), 64)
        self.assertNotIn("extra", s)
        with self.assertRaises(Problem):
            native_summary(HOST, {"interfaces": ["eno1"]})

    def test_merges_into_existing_host_device(self):
        self.store.put("devices", "pci-1", {"id": "pci-1", "model": "BlueField-3", "host": HOST, "site": "lab", "source": "linux-pci",
                                            "firmware": "x", "health": "healthy", "metrics": {}, "interfaces": [], "last_seen": time.time(),
                                            "version": 1, "mode": "observe", "services": [], "policy_ids": [], "capabilities": ["read-only"]})
        out = self.store.ingest_native(ACTOR, {"host": HOST, "summary": summary()})
        self.assertEqual(out["device"], "pci-1")
        self.assertEqual(self.store.device("pci-1")["ebpf"]["provider"], "native")

    def test_shadow_enforce_kill_release_rollback(self):
        self.agent.step()
        plan, _ = self.run_plan()
        self.assertEqual((plan["mode"], plan["confirmation"]), ("native-shadow", "APPLY SHADOW"))
        desired = self.store.agent_isolation(ACTOR)
        self.assertEqual(desired["controller"], ["192.0.2.10"])
        self.assertEqual(desired["isolation"]["mode"], "shadow")
        self.assertEqual(desired["isolation"]["rules"], [{"cidr": "10.0.0.0/8", "portFrom": 53, "portTo": 53},
                                                         {"cidr": "10.0.0.0/8", "portFrom": 443, "portTo": 443}])
        self.assertIsNone(desired["isolation"]["leaseUntil"])
        self.assertEqual(self.device["netra_isolation"]["provider"], "native")

        applied = self.agent.step()
        self.assertEqual(applied["mode"], "shadow")
        mode, rules = self.isolation.applied[-1]
        self.assertEqual(mode, "shadow")
        self.assertIn({"cidr": "192.0.2.10/32", "protocol": 6, "portFrom": 0, "portTo": 0}, rules)
        count = len(self.isolation.applied)
        self.agent.step()
        self.assertEqual(len(self.isolation.applied), count, "unchanged desired state is not re-applied")
        st = self.device["ebpf"]["isolation"]
        self.assertEqual((st["mode"], st["would_block_packets"], st["top"][0]["address"]), ("shadow", 2, "8.8.8.8"))

        plan, _ = self.run_plan("enforce")
        self.assertEqual((plan["mode"], plan["confirmation"]), ("native-enforce", f"ENFORCE ON ebpf-{HOST}"))
        lease = self.store.agent_isolation(ACTOR)["isolation"]["leaseUntil"]
        self.assertGreater(lease, time.time() + 800)
        self.assertEqual(self.agent.step()["mode"], "enforce")
        self.assertEqual(self.device["mode"], "isolated")

        out = self.store.kill_switch("admin", True)
        self.assertEqual(out["demoted"], [f"ebpf-{HOST}"])
        self.assertEqual(self.store.agent_isolation(ACTOR)["isolation"]["mode"], "shadow")
        self.assertEqual(self.agent.step()["mode"], "shadow")
        self.store.kill_switch("admin", False)

        _, job = self.run_plan(action="release")
        self.assertIsNone(self.store.agent_isolation(ACTOR)["isolation"])
        self.assertEqual(self.agent.step()["mode"], "off")
        self.assertEqual(self.isolation.applied[-1], ("off", []))

        self.store.rollback("admin", job["id"])
        restored = self.store.agent_isolation(ACTOR)["isolation"]
        self.assertEqual(restored["mode"], "shadow", "rollback restores shadow, never enforce")

    def test_agent_failsafe_and_override(self):
        self.agent.step()
        self.run_plan()
        self.run_plan("enforce")
        now = time.time()
        self.assertEqual(self.agent.step(now)["mode"], "enforce")
        self.offline = True
        self.assertEqual(self.agent.step(now + 30)["mode"], "enforce")
        applied = self.agent.step(now + 61)
        self.assertEqual((applied["mode"], applied["demoted"]), ("shadow", "control plane unreachable"))
        self.assertTrue(any("connection refused" in e for e in self.agent.errors))
        self.offline = False
        self.assertEqual(self.agent.step(now + 70)["mode"], "enforce")
        self.override.touch()
        applied = self.agent.step(now + 80)
        self.assertEqual((applied["mode"], applied["demoted"]), ("off", "local override"))
        self.assertEqual(self.isolation.applied[-1], ("off", []))
        self.override.unlink()
        self.assertEqual(self.agent.step(now + 90)["mode"], "enforce")
        # Past the lease with no renewal, the agent demotes by itself.
        lease = self.store.agent_isolation(ACTOR)["isolation"]["leaseUntil"]
        self.assertEqual(self.agent.step(lease + 1)["demoted"], "lease expired")

    def test_stale_agent_blocks_plans(self):
        self.agent.step()
        d = self.device
        d["ebpf"]["updated"] = time.time() - 600
        self.store.put("devices", d["id"], d)
        plan = self.store.plan("admin", {"action": "isolate", "devices": [d["id"]], "policy": POLICY, "stage": "shadow"})
        self.assertTrue(any("has not reported" in b for b in plan["blockers"]))

    def test_agent_keys_env(self):
        token = "t" * 32
        with patch.dict(os.environ, {"DUVORA_KEYS": "", "DUVORA_AGENT_KEYS": json.dumps({HOST: token})}):
            self.assertEqual(load_keys(), {ACTOR: ("agent", token)})


if __name__ == "__main__":
    unittest.main()

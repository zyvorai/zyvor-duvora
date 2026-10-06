"""Kernel tests for duvora_steer. Linux only, as root, with DUVORA_BPF_TESTS=1 (make bpf-test).
Verdicts run through BPF_PROG_TEST_RUN; no interface is attached."""
import unittest

from test_bpf_kernel import ACK, ENABLED, NEXT, SHOT, SYN, eth, ipv4, ipv6, tcp, udp

if ENABLED:
    from duvora.bpf import OBJ_DIR, steer
    from duvora.bpf.libbpf import Libbpf


def rule(action, direction="both", src="any", dst="any", protocol="any", sport="any", dport="any"):
    return {"action": action, "direction": direction, "src": src, "dst": dst, "protocol": protocol, "sport": sport, "dport": dport}


@unittest.skipUnless(ENABLED, "set DUVORA_BPF_TESTS=1 and run as root on Linux (make bpf-test)")
class SteeringVerdictTests(unittest.TestCase):
    def setUp(self):
        self.bpf = Libbpf()
        self.st = steer.Steering(self.bpf, OBJ_DIR / "duvora_steer.o", [])
        self.egress = self.st.obj.prog_fd("duvora_steer_egress")
        self.ingress = self.st.obj.prog_fd("duvora_steer_ingress")

    def tearDown(self):
        self.st.close()

    def out(self, packet):
        return self.bpf.test_run(self.egress, packet)[0]

    def inn(self, packet):
        return self.bpf.test_run(self.ingress, packet)[0]

    def test_off_and_shadow_never_drop(self):
        rules = [rule("drop", dst="8.8.8.8/32")]
        self.st.apply("off", rules)
        self.assertEqual(self.out(ipv4("8.8.8.8", 17, udp(53))), NEXT)
        self.st.apply("shadow", rules)
        self.assertEqual(self.out(ipv4("8.8.8.8", 17, udp(53))), NEXT)
        stats = self.st.stats()
        self.assertEqual((stats["would_drop"], stats["dropped"], stats["matched"]), (1, 0, 1))
        flows = self.st.drain_flows()
        self.assertEqual((flows[0]["dst"], flows[0]["action"], flows[0]["direction"]), ("8.8.8.8", "drop", "egress"))
        self.assertEqual(self.st.drain_flows(), [], "draining empties the sample map")

    def test_first_match_wins_and_default(self):
        rules = [rule("allow", dst="10.1.0.0/16", protocol="tcp", dport="443"), rule("drop", dst="10.1.0.0/16"),
                 rule("drop", direction="ingress", src="203.0.113.0/24")]
        self.st.apply("enforce", rules)
        self.assertEqual(self.out(ipv4("10.1.2.3", 6, tcp(443, SYN))), NEXT)
        self.assertEqual(self.out(ipv4("10.1.2.3", 6, tcp(443, ACK))), NEXT)
        self.assertEqual(self.out(ipv4("10.1.2.3", 6, tcp(80, ACK))), SHOT, "drop applies to every packet, not only SYN")
        self.assertEqual(self.out(ipv4("10.9.9.9", 17, udp(53))), NEXT, "default bypass")
        self.st.apply("enforce", rules, default="drop")
        self.assertEqual(self.out(ipv4("10.9.9.9", 17, udp(53))), SHOT, "default drop")
        counters = {c["index"]: c["packets"] for c in self.st.rule_counters()}
        self.assertEqual(counters.get(len(rules)), 1, "default slot counted")

    def test_direction(self):
        # Packets from these helpers come from 10.0.0.1; an ingress rule on src matches only on ingress.
        self.st.apply("enforce", [rule("drop", direction="ingress", src="10.0.0.1/32")])
        self.assertEqual(self.out(ipv4("10.1.2.3", 17, udp(53))), NEXT)
        self.assertEqual(self.inn(ipv4("10.1.2.3", 17, udp(53))), SHOT)

    def test_bypass_flag_passes_everything(self):
        self.st.apply("enforce", [rule("drop")], bypass=True)
        self.assertEqual(self.out(ipv4("8.8.8.8", 17, udp(53))), NEXT)
        self.assertGreater(self.st.stats()["bypassed"], 0)

    def test_exempt(self):
        self.st.apply("enforce", [rule("drop")], controller=["192.0.2.10"], controller_ports=[8787])
        self.assertEqual(self.out(ipv4("8.8.8.8", 17, udp(53))), SHOT)
        self.assertEqual(self.out(ipv4("8.8.8.8", 6, tcp(22, SYN))), NEXT, "SSH")
        self.assertEqual(self.out(ipv4("192.0.2.10", 6, tcp(8787, SYN))), NEXT, "control plane")
        self.assertEqual(self.out(ipv4("192.0.2.10", 6, tcp(80, SYN))), SHOT, "other ports on the controller address are steered")
        self.assertEqual(self.out(eth(0x0806) + b"\0" * 28), NEXT, "ARP is not parsed")
        self.assertGreater(self.st.stats()["exempt"], 0)

    def test_ipv6(self):
        self.st.apply("enforce", [rule("drop", dst="2001:db8:1::/48", protocol="tcp", dport="443")])
        self.assertEqual(self.out(ipv6("2001:db8:1::5", 6, tcp(443, SYN))), SHOT)
        self.assertEqual(self.out(ipv6("2001:db8:2::5", 6, tcp(443, SYN))), NEXT)
        self.assertEqual(self.out(ipv4("10.0.0.5", 6, tcp(443, SYN))), NEXT, "an IPv6 rule never matches IPv4")

    def test_thousand_rules(self):
        rules = [rule("allow", dst=f"10.{i // 256}.{i % 256}.0/24") for i in range(999)] + [rule("drop", dst="8.8.8.8/32")]
        self.st.apply("enforce", rules)
        self.assertEqual(self.st.config()["rule_count"], 1000)
        self.assertEqual(self.out(ipv4("8.8.8.8", 17, udp(53))), SHOT, "the last of 1000 rules still matches")
        self.assertEqual(self.out(ipv4("10.3.7.9", 17, udp(53))), NEXT)

    def test_generations_swap_halves(self):
        self.st.apply("enforce", [rule("drop", dst="8.8.8.8/32")])
        self.st.apply("enforce", [rule("allow", dst="8.8.8.8/32")])
        self.assertEqual(self.out(ipv4("8.8.8.8", 17, udp(53))), NEXT)
        self.assertEqual(self.st.config()["generation"], 2)

    def test_inspect_captures_payload(self):
        self.st.apply("shadow", [rule("inspect", protocol="tcp", dport="80")])
        body = b"POST /v1/chat/completions HTTP/1.1\r\nHost: vllm.local\r\n\r\n"
        packet = ipv4("10.1.2.3", 6, tcp(80, ACK) + body)
        self.assertEqual(self.out(packet), NEXT)
        payloads = self.st.drain_payloads()
        self.assertEqual(len(payloads), 1)
        flow, data = payloads[0]
        self.assertEqual((flow["dst"], flow["dport"]), ("10.1.2.3", 80))
        self.assertTrue(data.startswith(b"POST /v1/chat/completions"))
        self.assertEqual(self.st.stats()["inspected"], 1)


if __name__ == "__main__":
    unittest.main()

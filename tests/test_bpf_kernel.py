"""Kernel tests for the native eBPF objects. Linux only, as root, with DUVORA_BPF_TESTS=1 (make bpf-test).

They load every object, run node-isolation verdicts through BPF_PROG_TEST_RUN, and send real UDP
over a veth pair into a scratch network namespace. Nothing touches the host's real interfaces."""
import json
import os
import socket
import struct
import subprocess
import sys
import time
import unittest

ENABLED = os.environ.get("DUVORA_BPF_TESTS") == "1" and sys.platform.startswith("linux") and os.geteuid() == 0

if ENABLED:
    from duvora.bpf import OBJ_DIR, nodeiso
    from duvora.bpf.libbpf import Libbpf
    from duvora.bpf.sensors import Sensors

NEXT, SHOT = 0xFFFFFFFF, 2
NS, HOST_IF, NS_IF = "dvbpftest", "dvbpf0", "dvbpf1"
HOST_IP, NS_IP = "10.199.77.1", "10.199.77.2"


def eth(proto):
    return b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + struct.pack("!H", proto)


def ipv4(dst, proto, l4, frag=0):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, frag, 64, proto, 0,
                      socket.inet_aton("10.0.0.1"), socket.inet_aton(dst))
    return eth(0x0800) + hdr + l4 + b"\0" * 16


def ipv6(dst, proto, l4):
    hdr = struct.pack("!IHBB16s16s", 6 << 28, len(l4), proto, 64, socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
                      socket.inet_pton(socket.AF_INET6, dst))
    return eth(0x86DD) + hdr + l4 + b"\0" * 16


def udp(dport, sport=40000):
    return struct.pack("!HHHH", sport, dport, 8, 0)


def tcp(dport, flags, sport=40000):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0, 0, 0)


SYN, ACK = 0x02, 0x10


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


@unittest.skipUnless(ENABLED, "set DUVORA_BPF_TESTS=1 and run as root on Linux (make bpf-test)")
class KernelLoadTests(unittest.TestCase):
    def setUp(self):
        self.bpf = Libbpf()

    def test_libbpf_version(self):
        self.assertGreaterEqual(self.bpf.version(), (1, 3))

    def test_every_object_loads(self):
        objects = sorted(OBJ_DIR.glob("duvora_*.o"))
        self.assertEqual([o.name for o in objects], ["duvora_drops.o", "duvora_iface.o", "duvora_nodeiso.o", "duvora_steer.o", "duvora_tcp.o"])
        for path in objects:
            obj = self.bpf.open(path)
            obj.close()

    def test_tracing_sensors_attach(self):
        s = Sensors(self.bpf, [], "auto")
        try:
            self.assertNotIn("drops", s.unavailable)
            self.assertNotIn("tcp", s.unavailable)
            snap = s.snapshot("test")
            self.assertIn("retransmits", snap["tcp"])
            self.assertIsInstance(snap["drop_reasons"], list)
        finally:
            s.close()


@unittest.skipUnless(ENABLED, "set DUVORA_BPF_TESTS=1 and run as root on Linux (make bpf-test)")
class NodeIsolationVerdictTests(unittest.TestCase):
    def setUp(self):
        self.bpf = Libbpf()
        self.iso = nodeiso.NodeIsolation(self.bpf, OBJ_DIR / "duvora_nodeiso.o", [])
        self.fd = self.iso.obj.prog_fd("duvora_nodeiso_egress")

    def tearDown(self):
        self.iso.close()

    def verdict(self, packet):
        return self.bpf.test_run(self.fd, packet)[0]

    def apply(self, mode, rules, controller=()):
        self.iso.apply(mode, nodeiso.build_rules(rules, controller))

    def test_modes(self):
        rules = [{"cidr": "10.1.0.0/16", "portFrom": 53, "portTo": 53}]
        allowed, denied = ipv4("10.1.2.3", 17, udp(53)), ipv4("8.8.8.8", 17, udp(53))
        self.apply("off", rules)
        self.assertEqual((self.verdict(allowed), self.verdict(denied)), (NEXT, NEXT))
        self.apply("shadow", rules)
        self.assertEqual((self.verdict(allowed), self.verdict(denied)), (NEXT, NEXT))
        stats = self.iso.stats()
        self.assertEqual((stats["allowed"], stats["would_block"], stats["blocked"]), (1, 1, 0))
        self.assertEqual(stats["top"][0]["address"], "8.8.8.8")
        self.apply("enforce", rules)
        self.assertEqual((self.verdict(allowed), self.verdict(denied)), (NEXT, SHOT))
        self.assertEqual(self.verdict(ipv4("10.1.2.3", 17, udp(54))), SHOT, "port outside the range")
        self.assertEqual(self.iso.stats()["blocked"], 2)

    def test_always_allowed(self):
        self.apply("enforce", [{"cidr": "10.1.0.0/16"}], ["192.0.2.10"])
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 6, tcp(443, SYN))), SHOT)
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 6, tcp(443, ACK))), NEXT, "established TCP")
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 6, tcp(443, SYN | ACK))), NEXT, "reply to an inbound connection")
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 1, b"\x08\0\0\0\0\0\0\0")), NEXT, "ICMP")
        self.assertEqual(self.verdict(ipv4("255.255.255.255", 17, udp(67, 68))), NEXT, "DHCP")
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 17, udp(53), frag=5)), NEXT, "non-first fragment")
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 17, udp(5000, 22))), NEXT, "local port 22")
        self.assertEqual(self.verdict(ipv4("192.0.2.10", 6, tcp(8787, SYN))), NEXT, "control plane")
        self.assertEqual(self.verdict(ipv4("192.0.2.10", 17, udp(53))), SHOT, "control plane rule is TCP only")
        self.assertEqual(self.verdict(eth(0x0806) + b"\0" * 28), NEXT, "ARP")
        self.assertEqual(self.verdict(ipv6("2001:db8::99", 58, b"\x80\0\0\0\0\0\0\0")), NEXT, "ICMPv6")
        self.assertGreater(self.iso.stats()["exempt"], 0)

    def test_ipv6_rules(self):
        self.apply("enforce", [{"cidr": "2001:db8:1::/48", "portFrom": 443, "portTo": 443}])
        self.assertEqual(self.verdict(ipv6("2001:db8:1::5", 6, tcp(443, SYN))), NEXT)
        self.assertEqual(self.verdict(ipv6("2001:db8:2::5", 6, tcp(443, SYN))), SHOT)
        self.assertEqual(self.verdict(ipv4("10.0.0.5", 6, tcp(443, SYN))), SHOT, "an IPv6 rule never matches IPv4")

    def test_generation_swap(self):
        self.apply("enforce", [{"cidr": "10.1.0.0/16"}])
        first = self.iso.generation
        self.apply("enforce", [{"cidr": "8.8.8.0/24"}])
        self.assertEqual(self.iso.generation, first + 1)
        self.assertEqual(self.verdict(ipv4("8.8.8.8", 17, udp(53))), NEXT)
        self.assertEqual(self.verdict(ipv4("10.1.2.3", 17, udp(53))), SHOT)
        gens = {nodeiso.RULE_KEY.unpack(k)[0] for k in self.bpf.keys(self.iso.fds["iso_rules"], nodeiso.RULE_KEY.size)}
        self.assertEqual(gens, {first + 1}, "old generations are purged")
        self.assertEqual(self.iso.config(), {"generation": first + 1, "mode": "enforce", "rule_count": 1})
        self.apply("off", [])
        self.assertEqual(self.iso.config()["generation"], 0)
        self.assertEqual(self.bpf.keys(self.iso.fds["iso_rules"], nodeiso.RULE_KEY.size), [])


LISTENER = r"""
import json, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 0)); port = s.getsockname()[1]
socks = []
for p in (9000, 9001):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", p)); u.settimeout(0.05); socks.append((p, u))
print("ready", flush=True)
got = {9000: 0, 9001: 0}
end = time.time() + float(sys.argv[1])
while time.time() < end:
    for p, u in socks:
        try:
            u.recv(2048); got[p] += 1
        except socket.timeout:
            pass
print(json.dumps(got), flush=True)
"""


@unittest.skipUnless(ENABLED, "set DUVORA_BPF_TESTS=1 and run as root on Linux (make bpf-test)")
class VethTrafficTests(unittest.TestCase):
    """Real packets: host side dvbpf0 (10.199.77.1) -> netns side dvbpf1 (10.199.77.2)."""

    def setUp(self):
        self.cleanup()
        sh("ip", "netns", "add", NS)
        sh("ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF)
        sh("ip", "link", "set", NS_IF, "netns", NS)
        sh("ip", "addr", "add", f"{HOST_IP}/24", "dev", HOST_IF)
        sh("ip", "link", "set", HOST_IF, "up")
        sh("ip", "netns", "exec", NS, "ip", "addr", "add", f"{NS_IP}/24", "dev", NS_IF)
        sh("ip", "netns", "exec", NS, "ip", "link", "set", NS_IF, "up")
        sh("ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up")
        self.bpf = Libbpf()
        self.ifindex = socket.if_nametoindex(HOST_IF)

    def tearDown(self):
        self.cleanup()

    @staticmethod
    def cleanup():
        sh("ip", "link", "del", HOST_IF, check=False)
        sh("ip", "netns", "del", NS, check=False)

    def send_and_count(self, ports, packets=5):
        listener = subprocess.Popen(["ip", "netns", "exec", NS, sys.executable, "-c", LISTENER, "2.5"],
                                    stdout=subprocess.PIPE, text=True)
        self.assertEqual(listener.stdout.readline().strip(), "ready")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(packets):
            for port in ports:
                try:
                    s.sendto(b"duvora", (NS_IP, port))
                except OSError:
                    pass  # an egress drop may surface as ENOBUFS or EPERM
            time.sleep(0.05)
        s.close()
        out = json.loads(listener.stdout.readline())
        listener.wait(timeout=10)
        listener.stdout.close()
        return {int(k): v for k, v in out.items()}

    def test_shadow_counts_enforce_drops(self):
        iso = nodeiso.NodeIsolation(self.bpf, OBJ_DIR / "duvora_nodeiso.o", [self.ifindex])
        try:
            rules = nodeiso.build_rules([{"cidr": "10.199.77.0/24", "portFrom": 9001, "portTo": 9001}])
            iso.apply("shadow", rules)
            got = self.send_and_count([9000, 9001])
            self.assertEqual(got, {9000: 5, 9001: 5}, "shadow never drops")
            self.assertGreaterEqual(iso.stats()["would_block"], 5)

            iso.apply("enforce", rules)
            got = self.send_and_count([9000, 9001])
            self.assertEqual(got[9000], 0, "outside the allow-list is dropped")
            self.assertEqual(got[9001], 5, "inside the allow-list passes")
            stats = iso.stats()
            self.assertGreaterEqual(stats["blocked"], 5)
            self.assertIn((NS_IP, 9000), {(t["address"], t["port"]) for t in stats["top"]})

            iso.apply("off", [])
            self.assertEqual(self.send_and_count([9000]), {9000: 5, 9001: 0})
        finally:
            iso.close()
        # Closing the object destroys the links: the filter is gone (fail open).
        self.assertEqual(self.send_and_count([9000]), {9000: 5, 9001: 0})

    def test_iface_sensor_counts_and_flows(self):
        sensors = Sensors(self.bpf, [HOST_IF], "required")
        try:
            sensors.snapshot("test")
            self.send_and_count([9000])
            snap = sensors.snapshot("test")
            self.assertGreaterEqual(snap["interfaces"][HOST_IF]["packets"], 5)
            flow = next(f for f in snap["flows"] if f["peer"] == NS_IP and f["port"] == 9000)
            self.assertEqual((flow["protocol"], flow["packets"]), ("udp", 5))
        finally:
            sensors.close()


if __name__ == "__main__":
    unittest.main()

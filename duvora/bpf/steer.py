"""Traffic steering: encode a rule set into duvora_steer's maps, publish it by generation, read
counters, and drain flow samples and inspected payloads.

Encoding is plain Python so it is tested on any OS; Steering needs Linux and libbpf. This is
host-kernel steering on the node's uplinks, not DPU offload."""
import ipaddress
import struct

from .libbpf import BPF_ANY, percpu_size, sum_percpu

MAX_RULES = 1000
SLOTS = MAX_RULES + 1
MODES = {"off": 0, "shadow": 1, "enforce": 2}
ACTIONS = {"bypass": 0, "allow": 1, "inspect": 2, "drop": 3}
ACTION_NAMES = {v: k for k, v in ACTIONS.items()}
DIRECTIONS = {"ingress": 1, "egress": 2, "both": 3}
DIRECTION_NAMES = {1: "ingress", 2: "egress"}
PROTOCOLS = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58}
PROTOCOL_NAMES = {v: k for k, v in PROTOCOLS.items() if v}
FLAG_BYPASS, FLAG_DEFAULT_DROP = 1, 2
STAT_SLOTS = ("matched", "allowed", "dropped", "would_drop", "inspected", "bypassed", "exempt", "dropped_bytes", "would_drop_bytes")

CONFIG = struct.Struct("<IIII")                       # generation, mode, rule_count, flags
RULE = struct.Struct("<BBBBHHHHI16s16s16s16s")        # directions, family, protocol, action, ports, reserved, src, mask, dst, mask
EXEMPT_KEY = struct.Struct("<IBxH16s")                # generation, family, port, address
FLOW_KEY = struct.Struct("<BBBBHH16s16s")             # direction, family, protocol, action, sport, dport, saddr, daddr
FLOW_VALUE = struct.Struct("<IIQQQ")                  # rule, reserved, packets, bytes, last_ns
PAYLOAD = struct.Struct("<II256s")                    # len, rule, data
COUNTER = struct.Struct("<QQ")                        # packets, bytes


def _net(cidr):
    if cidr == "any":
        return 0, bytes(16), bytes(16)
    net = ipaddress.ip_network(cidr, strict=False)
    return net.version, net.network_address.packed.ljust(16, b"\0"), net.netmask.packed.ljust(16, b"\0")


def _range(text):
    if text in (None, "any"):
        return 0, 0
    lo, _, hi = str(text).partition("-")
    return int(lo), int(hi or lo)


def encode_rule(r):
    """One normalized steering rule (steering.normalize_rule shape) as a st_rule."""
    sfam, src, smask = _net(r.get("src", "any"))
    dfam, dst, dmask = _net(r.get("dst", "any"))
    if sfam and dfam and sfam != dfam:
        raise ValueError("src and dst must be the same IP family")
    family = sfam or dfam
    slo, shi = _range(r.get("sport"))
    dlo, dhi = _range(r.get("dport"))
    return RULE.pack(DIRECTIONS[r.get("direction", "both")], family, PROTOCOLS[r.get("protocol", "any")], ACTIONS[r["action"]],
                     slo, shi, dlo, dhi, 0, src, smask, dst, dmask)


def decode_rule(raw):
    directions, family, protocol, action, slo, shi, dlo, dhi, _, src, smask, dst, dmask = RULE.unpack(raw)

    def cidr(addr, mask):
        if not any(mask):
            return "any"
        width = 4 if family == 4 else 16
        return f"{ipaddress.ip_address(addr[:width])}/{sum(bin(b).count('1') for b in mask[:width])}"
    ports = lambda lo, hi: "any" if not hi else str(lo) if lo == hi else f"{lo}-{hi}"
    return {"direction": {1: "ingress", 2: "egress", 3: "both"}[directions], "src": cidr(src, smask), "dst": cidr(dst, dmask),
            "protocol": PROTOCOL_NAMES.get(protocol, "any"), "sport": ports(slo, shi), "dport": ports(dlo, dhi), "action": ACTION_NAMES[action]}


def _address(raw, family):
    return str(ipaddress.ip_address(raw[:4] if family == 4 else raw))


def decode_flow(key, value):
    direction, family, protocol, action, sport, dport, saddr, daddr = FLOW_KEY.unpack(key)
    rule, _, packets, size, last = FLOW_VALUE.unpack(value[:FLOW_VALUE.size])
    return {"direction": DIRECTION_NAMES.get(direction, "egress"), "src": _address(saddr, family), "dst": _address(daddr, family),
            "protocol": PROTOCOL_NAMES.get(protocol, str(protocol)), "sport": sport, "dport": dport,
            "action": ACTION_NAMES.get(action, "allow"), "rule_index": rule, "packets": packets, "bytes": size}


def decode_payload(key, value):
    flow = decode_flow(key, bytes(FLOW_VALUE.size))
    length, rule, data = PAYLOAD.unpack(value[:PAYLOAD.size])
    return {k: flow[k] for k in ("direction", "src", "dst", "protocol", "sport", "dport")} | {"rule_index": rule}, data[:min(length, 256)]


class Steering:
    """duvora_steer.o attached at the head of each interface's TCX ingress and egress chains."""

    MAPS = ("steer_cfg", "steer_rules", "steer_counters", "steer_stats", "steer_exempt", "steer_flows", "steer_payloads")

    def __init__(self, bpf, path, ifindexes):
        self.bpf = bpf
        self.obj = bpf.open(path)
        try:
            self.fds = {m: self.obj.map_fd(m) for m in self.MAPS}
            for ifindex in ifindexes:
                self.obj.attach_tcx("duvora_steer_ingress", ifindex, first=True)
                self.obj.attach_tcx("duvora_steer_egress", ifindex, first=True)
        except Exception:
            self.obj.close()
            raise
        self.generation, self.rule_count, self.mode, self.flags = 0, 0, "off", 0

    def config(self):
        generation, mode, count, flags = CONFIG.unpack(self.bpf.lookup(self.fds["steer_cfg"], struct.pack("<I", 0), CONFIG.size))
        return {"generation": generation, "mode": {v: k for k, v in MODES.items()}.get(mode, "off"), "rule_count": count,
                "bypass": bool(flags & FLAG_BYPASS), "default": "drop" if flags & FLAG_DEFAULT_DROP else "bypass"}

    def apply(self, mode, rules=(), default="bypass", bypass=False, controller=(), controller_ports=(443,)):
        """Write `rules` (normalized dicts) into the inactive half, zero its counters, then publish it.
        TCP/UDP to or from each controller address on `controller_ports` is exempt."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        rules = list(rules)
        if len(rules) > MAX_RULES:
            raise ValueError(f"at most {MAX_RULES} rules")
        key0 = struct.pack("<I", 0)
        if mode == "off":
            self.bpf.update(self.fds["steer_cfg"], key0, CONFIG.pack(0, 0, 0, 0), BPF_ANY)
            self.generation, self.rule_count, self.mode, self.flags = 0, 0, "off", 0
            self._purge_exempt(keep=None)
            return
        encoded = [encode_rule(r) for r in rules]
        gen = (self.generation % 0xFFFFFFFE) + 1
        base = (gen & 1) * MAX_RULES
        for i, raw in enumerate(encoded):
            self.bpf.update(self.fds["steer_rules"], struct.pack("<I", base + i), raw, BPF_ANY)
        zero = bytes(percpu_size(COUNTER.size) * self.bpf.cpus)
        for i in range(SLOTS):
            self.bpf.update(self.fds["steer_counters"], struct.pack("<I", (gen & 1) * SLOTS + i), zero, BPF_ANY)
        for address in sorted(set(controller)):
            ip = ipaddress.ip_address(address)
            for port in sorted(set(controller_ports)):
                self.bpf.update(self.fds["steer_exempt"], EXEMPT_KEY.pack(gen, ip.version, port, ip.packed.ljust(16, b"\0")), b"\1", BPF_ANY)
        flags = (FLAG_BYPASS if bypass else 0) | (FLAG_DEFAULT_DROP if default == "drop" else 0)
        self.bpf.update(self.fds["steer_cfg"], key0, CONFIG.pack(gen, MODES[mode], len(encoded), flags), BPF_ANY)
        self.generation, self.rule_count, self.mode, self.flags = gen, len(encoded), mode, flags
        self._purge_exempt(keep=gen)

    def _purge_exempt(self, keep):
        for key in self.bpf.keys(self.fds["steer_exempt"], EXEMPT_KEY.size):
            if EXEMPT_KEY.unpack(key)[0] != keep:
                self.bpf.delete(self.fds["steer_exempt"], key)

    def stats(self):
        out = {}
        for slot, name in enumerate(STAT_SLOTS):
            raw = self.bpf.lookup(self.fds["steer_stats"], struct.pack("<I", slot), 8 * self.bpf.cpus)
            out[name] = sum_percpu(raw, 8, "<Q")[0] if raw else 0
        return out

    def rule_counters(self):
        """[{index, packets, bytes}] for the published generation; index == rule_count is the default."""
        if not self.generation:
            return []
        out = []
        size = percpu_size(COUNTER.size) * self.bpf.cpus
        for i in list(range(self.rule_count)) + [self.rule_count]:
            slot = (self.generation & 1) * SLOTS + min(i, MAX_RULES)
            raw = self.bpf.lookup(self.fds["steer_counters"], struct.pack("<I", slot), size)
            packets, size_bytes = sum_percpu(raw, COUNTER.size, "<QQ") if raw else (0, 0)
            if packets:
                out.append({"index": i, "packets": packets, "bytes": size_bytes})
        return out

    def drain_flows(self, limit=500):
        """Flow samples since the last drain (non-bypass verdicts), busiest first; the map is emptied."""
        items = self.bpf.items(self.fds["steer_flows"], FLOW_KEY.size, FLOW_VALUE.size)
        for k, _ in items:
            self.bpf.delete(self.fds["steer_flows"], k)
        flows = sorted((decode_flow(k, v) for k, v in items), key=lambda f: -f["bytes"])
        return flows[:limit]

    def drain_payloads(self, limit=100):
        items = self.bpf.items(self.fds["steer_payloads"], FLOW_KEY.size, PAYLOAD.size)
        for k, _ in items:
            self.bpf.delete(self.fds["steer_payloads"], k)
        return [decode_payload(k, v) for k, v in items[:limit]]

    def close(self):
        self.obj.close()

# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

"""Node isolation: encode an allow-list into duvora_nodeiso's maps, publish it by generation, read stats.

Encoding is plain Python so it is tested on any OS; NodeIsolation needs Linux and libbpf."""
import ipaddress
import socket
import struct

from .libbpf import BPF_ANY, sum_percpu

MAX_OPERATOR_RULES = 64
MAX_RULES = 80
MODES = {"off": 0, "shadow": 1, "enforce": 2}
MODE_NAMES = {v: k for k, v in MODES.items()}
PROTOCOLS = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58}
PROTOCOL_NAMES = {v: k for k, v in PROTOCOLS.items() if v}
EXEMPT_PORTS = ((6, 22), (17, 22))
STAT_SLOTS = ("allowed", "would_block", "blocked", "exempt", "would_block_bytes", "blocked_bytes")

CONFIG = struct.Struct("<IIII")          # generation, mode, rule_count, reserved
RULE_KEY = struct.Struct("<II")          # generation, index
RULE = struct.Struct("<BBHHH16s16s")     # family, protocol, port_lo, port_hi, reserved, addr, mask
EXEMPT_KEY = struct.Struct("<IBBH")      # generation, protocol, reserved, port
DEST_KEY = struct.Struct("<BBH16s")      # family, protocol, port, address
DEST_VALUE = struct.Struct("<QQ")        # packets, bytes


def encode_rule(cidr, port_lo=0, port_hi=0, protocol=0):
    """One allow rule. Ports 0/0 = any port; a range only matches TCP and UDP."""
    net = ipaddress.ip_network(cidr, strict=False)
    if (port_lo, port_hi) != (0, 0) and not 1 <= port_lo <= port_hi <= 65535:
        raise ValueError(f"bad port range {port_lo}-{port_hi}")
    addr = net.network_address.packed.ljust(16, b"\0")
    mask = net.netmask.packed.ljust(16, b"\0")
    return RULE.pack(net.version if net.version == 4 else 6, protocol, port_lo, port_hi, 0, addr, mask)


def decode_rule(raw):
    family, protocol, lo, hi, _, addr, mask = RULE.unpack(raw)
    width = 4 if family == 4 else 16
    prefix = sum(bin(b).count("1") for b in mask[:width])
    address = ipaddress.ip_address(addr[:width])
    return {"cidr": f"{address}/{prefix}", "protocol": protocol, "portFrom": lo, "portTo": hi}


def build_rules(rules, controller=()):
    """Operator rules (Netra-style dicts: cidr, portFrom, portTo, protocol) plus TCP to each controller address."""
    if len(rules) > MAX_OPERATOR_RULES:
        raise ValueError(f"at most {MAX_OPERATOR_RULES} allow rules")
    out = []
    for r in rules:
        proto = r.get("protocol") or 0
        proto = PROTOCOLS[proto.lower()] if isinstance(proto, str) else int(proto)
        out.append(encode_rule(r["cidr"], int(r.get("portFrom") or 0), int(r.get("portTo") or 0), proto))
    for address in sorted(set(controller))[:MAX_RULES - len(out)]:
        ip = ipaddress.ip_address(address)
        out.append(encode_rule(f"{ip}/{ip.max_prefixlen}", 0, 0, PROTOCOLS["tcp"]))
    return out


def resolve_controller(url_host):
    """Addresses of the control plane host (the agent must always reach it)."""
    try:
        return sorted({info[4][0].split("%")[0] for info in socket.getaddrinfo(url_host, None, proto=socket.IPPROTO_TCP)})
    except (OSError, UnicodeError):
        return []


def decode_dest(key, value):
    family, protocol, port, address = DEST_KEY.unpack(key)
    packets, size = DEST_VALUE.unpack(value[:DEST_VALUE.size])
    ip = ipaddress.ip_address(address[:4] if family == 4 else address)
    return {"address": str(ip), "port": port, "protocol": PROTOCOL_NAMES.get(protocol, str(protocol)),
            "packets": packets, "bytes": size}


class NodeIsolation:
    """duvora_nodeiso.o loaded and attached at the head of each interface's TCX egress chain."""

    def __init__(self, bpf, path, ifindexes):
        self.bpf = bpf
        self.obj = bpf.open(path)
        try:
            self.fds = {m: self.obj.map_fd(m) for m in ("iso_cfg", "iso_rules", "iso_exempt", "iso_stats", "iso_dests")}
            for ifindex in ifindexes:
                self.obj.attach_tcx("duvora_nodeiso_egress", ifindex, first=True)
        except Exception:
            self.obj.close()
            raise
        self.generation, self.rule_count, self.mode = 0, 0, "off"

    def config(self):
        raw = self.bpf.lookup(self.fds["iso_cfg"], struct.pack("<I", 0), CONFIG.size)
        generation, mode, count, _ = CONFIG.unpack(raw)
        return {"generation": generation, "mode": MODE_NAMES.get(mode, "off"), "rule_count": count}

    def apply(self, mode, rules):
        """Write `rules` (encoded) as a new generation, then publish it; old generations are deleted after."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode}")
        old = self.generation
        if mode == "off":
            self.bpf.update(self.fds["iso_cfg"], struct.pack("<I", 0), CONFIG.pack(0, 0, 0, 0), BPF_ANY)
            self.generation, self.rule_count, self.mode = 0, 0, "off"
        else:
            if len(rules) > MAX_RULES:
                raise ValueError(f"at most {MAX_RULES} rules")
            gen = (old % 0xFFFFFFFE) + 1 if old else 1
            for i, rule in enumerate(rules):
                self.bpf.update(self.fds["iso_rules"], RULE_KEY.pack(gen, i), rule, BPF_ANY)
            for proto, port in EXEMPT_PORTS:
                self.bpf.update(self.fds["iso_exempt"], EXEMPT_KEY.pack(gen, proto, 0, port), b"\1", BPF_ANY)
            self.bpf.update(self.fds["iso_cfg"], struct.pack("<I", 0), CONFIG.pack(gen, MODES[mode], len(rules), 0), BPF_ANY)
            self.generation, self.rule_count, self.mode = gen, len(rules), mode
        self._purge(keep=self.generation)

    def _purge(self, keep):
        for key in self.bpf.keys(self.fds["iso_rules"], RULE_KEY.size):
            if RULE_KEY.unpack(key)[0] != keep:
                self.bpf.delete(self.fds["iso_rules"], key)
        for key in self.bpf.keys(self.fds["iso_exempt"], EXEMPT_KEY.size):
            if EXEMPT_KEY.unpack(key)[0] != keep:
                self.bpf.delete(self.fds["iso_exempt"], key)

    def stats(self, top=5):
        out = {}
        for slot, name in enumerate(STAT_SLOTS):
            raw = self.bpf.lookup(self.fds["iso_stats"], struct.pack("<I", slot), 8 * self.bpf.cpus)
            out[name] = sum_percpu(raw, 8, "<Q")[0] if raw else 0
        dests = [decode_dest(k, v) for k, v in self.bpf.items(self.fds["iso_dests"], DEST_KEY.size, DEST_VALUE.size)]
        out["top"] = sorted(dests, key=lambda d: (-d["bytes"], -d["packets"]))[:top]
        return out

    def close(self):
        self.obj.close()

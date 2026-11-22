# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

"""Load Duvora's observe-only eBPF sensors and read them into the summary shape of netra.summarize()."""
import ipaddress
import os
import re
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from . import OBJ_DIR
from .libbpf import percpu_size, sum_percpu
from .nodeiso import PROTOCOL_NAMES

IFACE_KEY = struct.Struct("<II")        # ifindex, direction
IFACE_VALUE = struct.Struct("<QQ")      # packets, bytes
FLOW_KEY = struct.Struct("<BBH16s")     # family, protocol, port, address
FLOW_VALUE = struct.Struct("<QQQ")      # packets, bytes, last_ns
TCP_SLOTS = ("retransmits", "rst_sent", "rst_received")
DROP_FORMAT = "/sys/kernel/tracing/events/skb/kfree_skb/format"
FLOW_LIMIT = 200


def default_route_interfaces(route4="", route6=""):
    """Interfaces carrying a default route, from /proc/net/route and /proc/net/ipv6_route text."""
    found = []
    for line in route4.splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000" and f[0] not in found:
            found.append(f[0])
    for line in route6.splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo" and f[9] not in found:
            found.append(f[9])
    return found


def uplinks(explicit=""):
    names = [x for x in re.split(r"[\s,]+", explicit or "") if x]
    if names:
        return names
    read = lambda p: Path(p).read_text() if Path(p).exists() else ""
    return default_route_interfaces(read("/proc/net/route"), read("/proc/net/ipv6_route"))


def parse_drop_reasons(text):
    """{reason number: NAME} from the __print_symbolic list in the kfree_skb tracepoint format."""
    return {int(n): name for n, name in re.findall(r'\{\s*(\d+)\s*,\s*"([A-Za-z0-9_]+)"\s*\}', text or "")}


def drop_reason_names(path=DROP_FORMAT):
    try:
        return parse_drop_reasons(Path(path).read_text())
    except OSError:
        return {}


def address(family, raw):
    return str(ipaddress.ip_address(raw[:4] if family == 4 else raw))


def iso_time(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def flow_records(current, previous, now):
    """Egress flow deltas since the previous read, as Netra-style flow-log records (largest first)."""
    records = []
    for key, (packets, size) in current.items():
        old = previous.get(key)
        dp, db = (packets - old[0], size - old[1]) if old and packets >= old[0] and size >= old[1] else (packets, size)
        if dp <= 0:
            continue
        family, protocol, port, peer = key
        records.append({"peer": peer, "port": port, "protocol": PROTOCOL_NAMES.get(protocol, str(protocol)),
                        "packets": dp, "bytes": db, "blocked": 0, "direction": "egress", "observedAt": iso_time(now)})
    return sorted(records, key=lambda r: (-r["bytes"], -r["packets"]))[:FLOW_LIMIT]


class Sensors:
    """Observe-only programs: interface counters and flows (TCX), drop reasons, TCP events.

    mode: "auto" records what fails to load, "required" raises, "off" loads nothing."""

    def __init__(self, bpf, interfaces, mode="auto", obj_dir=OBJ_DIR):
        self.bpf, self.mode, self.interfaces = bpf, mode, list(interfaces)
        self.objects, self.unavailable, self.attached = {}, {}, []
        self.reasons = drop_reason_names()
        self.prev_flows = {}
        if mode == "off":
            return
        self._load("iface", obj_dir / "duvora_iface.o", self._attach_iface)
        self._load("drops", obj_dir / "duvora_drops.o", lambda o: self._attach(o, "duvora_kfree_skb"))
        self._load("tcp", obj_dir / "duvora_tcp.o", lambda o: [self._attach(o, p) for p in
                   ("duvora_tcp_retransmit", "duvora_tcp_send_reset", "duvora_tcp_receive_reset")])

    def _load(self, name, path, attach):
        try:
            obj = self.bpf.open(path)
        except OSError as exc:
            return self._unavailable(name, exc)
        try:
            attach(obj)
        except OSError as exc:
            obj.close()
            return self._unavailable(name, exc)
        self.objects[name] = obj

    def _unavailable(self, name, exc):
        if self.mode == "required":
            raise exc
        self.unavailable[name] = str(exc)[:200]

    def _attach(self, obj, prog):
        obj.attach(prog)
        self.attached.append(prog)

    def _attach_iface(self, obj):
        if not self.interfaces:
            raise OSError(19, "no uplink interfaces (no default route; pass --interfaces)")
        # At the head: a CNI program later in the chain (Cilium's cil_to_netdev) ends it with a verdict.
        for name in self.interfaces:
            index = socket.if_nametoindex(name)
            obj.attach_tcx("duvora_iface_ingress", index, first=True)
            obj.attach_tcx("duvora_iface_egress", index, first=True)
        self.attached += [f"duvora_iface_{d}@{n}" for n in self.interfaces for d in ("ingress", "egress")]

    def _percpu_items(self, obj, map_name, key_size, value_size, fmt):
        fd = obj.map_fd(map_name)
        return [(k, sum_percpu(v, value_size, fmt))
                for k, v in self.bpf.items(fd, key_size, percpu_size(value_size) * self.bpf.cpus)]

    def snapshot(self, host, now=None):
        now = now or time.time()
        s = {"node": host, "hostname": socket.gethostname(), "kernel": os.uname().release, "stale": False, "age": 0,
             "mode": "observe", "programs": sorted(set(p.split("@")[0] for p in self.attached)),
             "program_count": len(self.objects), "attached": len(self.attached), "interfaces": {}, "flows": [],
             "btf": os.path.exists("/sys/kernel/btf/vmlinux"), "drops": 0}
        for name in self.interfaces:
            s["interfaces"][name] = {"packets": 0, "bytes": 0, "blocked": 0}
            stats = Path("/sys/class/net") / name / "statistics"
            for counter in ("rx_dropped", "tx_dropped"):
                try:
                    s["drops"] += int((stats / counter).read_text())
                except (OSError, ValueError):
                    pass
        iface = self.objects.get("iface")
        if iface:
            for k, (packets, size) in self._percpu_items(iface, "iface_stats", IFACE_KEY.size, IFACE_VALUE.size, "<QQ"):
                try:
                    name = socket.if_indextoname(IFACE_KEY.unpack(k)[0])
                except OSError:
                    continue
                entry = s["interfaces"].setdefault(name, {"packets": 0, "bytes": 0, "blocked": 0})
                entry["packets"] += packets
                entry["bytes"] += size
            current = {}
            for k, v in self.bpf.items(iface.map_fd("iface_flows"), FLOW_KEY.size, FLOW_VALUE.size):
                family, protocol, port, raw = FLOW_KEY.unpack(k)
                packets, size, _ = FLOW_VALUE.unpack(v)
                current[(family, protocol, port, address(family, raw))] = (packets, size)
            s["flows"] = flow_records(current, self.prev_flows, now)
            self.prev_flows = current
        drops = self.objects.get("drops")
        if drops:
            counts = [(struct.unpack("<I", k)[0], v[0]) for k, v in self._percpu_items(drops, "drop_reasons", 4, 8, "<Q")]
            s["drop_reasons"] = [{"reason": self.reasons.get(r, str(r)), "count": c}
                                 for r, c in sorted(counts, key=lambda x: -x[1])[:5]]
            s["drop_info_unavailable"] = "" if self.reasons else "tracefs not readable; reasons shown as numbers"
        else:
            s["drop_info_unavailable"] = self.unavailable.get("drops", "not loaded")
        tcp = self.objects.get("tcp")
        if tcp:
            fd = tcp.map_fd("tcp_counts")
            totals = {}
            for slot, name in enumerate(TCP_SLOTS):
                raw = self.bpf.lookup(fd, struct.pack("<I", slot), 8 * self.bpf.cpus)
                totals[name] = sum_percpu(raw, 8, "<Q")[0] if raw else 0
            s["tcp"] = {"retransmits": totals["retransmits"], "resets": totals["rst_sent"] + totals["rst_received"]}
            s["tcp_unavailable"] = ""
        else:
            s["tcp_unavailable"] = self.unavailable.get("tcp", "not loaded")
        return s

    def close(self):
        for obj in self.objects.values():
            obj.close()
        self.objects = {}

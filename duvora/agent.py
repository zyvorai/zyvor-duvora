"""Host agent: read-only Linux PCI discovery and, with --ebpf, Duvora's native eBPF sensors and node
isolation (duvora/bpf). No privileged subprocesses or hardware writes."""
import argparse
import hashlib
import json
import os
import re
import socket
import time
from pathlib import Path

from .cli import request

# NVIDIA/Mellanox BlueField PCI IDs. An ID match proves PCI identity, not DPU mode.
BLUEFIELD = {"0xa2d2": "BlueField-2", "0xa2d3": "BlueField-3", "0xa2d6": "BlueField integrated controller"}


def read(path, default="unknown"):
    try:
        return path.read_text().strip()
    except OSError:
        return default


def discover(root=Path("/sys/bus/pci/devices"), host=None, site="unassigned"):
    host = host or host_slug(socket.gethostname())
    reports = []
    if not root.exists():
        return reports
    for pci in sorted(root.iterdir()):
        vendor, ident = read(pci / "vendor"), read(pci / "device")
        if vendor != "0x15b3" or ident not in BLUEFIELD:
            continue
        uid = hashlib.sha256(f"{host}:{pci.name}".encode()).hexdigest()[:16]
        interfaces = sorted(x.name for x in (pci / "net").iterdir()) if (pci / "net").exists() else []
        reports.append({"id": "pci-" + uid, "host": host, "site": site, "model": BLUEFIELD[ident],
            "source": "linux-pci", "firmware": "unknown", "health": "unknown", "metrics": {}, "interfaces": interfaces})
    return reports


def host_slug(name):
    return re.sub(r"[^a-z0-9._-]", "-", (name or "").lower())[:63]


def host_token(path, host):
    """This host's token from a JSON file of host to token (the Helm DaemonSet's shared key map)."""
    if not path:
        return ""
    try:
        keys = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return ""
    token = keys.get(host) if isinstance(keys, dict) else None
    return token if isinstance(token, str) else ""


class Credential:
    """The agent's bearer: the host-bound bootstrap key, exchanged for a short-lived token (POST /agent/token)
    and rotated at half its lifetime. Falls back to the bootstrap key against servers without tokens."""

    def __init__(self, url, bootstrap, rotate=True):
        self.url, self.bootstrap, self.rotate = url, bootstrap, rotate
        self.token, self.rotate_after, self.supported = "", 0.0, rotate

    def current(self, now=None):
        now = now or time.time()
        if self.supported and (not self.token or now >= self.rotate_after):
            try:
                out = request(self.url, self.token or self.bootstrap, "/api/v1/agent/token", {})
                self.token, self.rotate_after = out["token"], float(out["rotate_after"])
            except OSError as exc:
                if "404" in str(exc) or "405" in str(exc):
                    self.supported = False
                elif self.token and "401" in str(exc):
                    self.token = ""  # expired: mint again from the bootstrap key next time
                if not self.token:
                    return self.bootstrap
        return self.token or self.bootstrap


def start_ebpf(args, credential):
    """Load the native sensors, node isolation and steering. Returns an EbpfAgent, or None when unavailable in auto mode."""
    try:
        from .bpf.libbpf import Libbpf
        from .bpf.nodeiso import NodeIsolation
        from .bpf.runtime import EbpfAgent
        from .bpf.sensors import Sensors, uplinks
        from .bpf.steer import Steering
        from .bpf import OBJ_DIR
        from .aiassets import discover as discover_assets
        bpf = Libbpf()
        interfaces = uplinks(args.interfaces)
        sensors = Sensors(bpf, interfaces, args.ebpf)
    except OSError as exc:
        if args.ebpf == "required":
            raise SystemExit(f"eBPF unavailable: {exc}")
        print(json.dumps({"ebpf": "unavailable", "error": str(exc)}), flush=True)
        return None
    isolation, why = None, "disabled with --no-isolation" if args.no_isolation else ""
    if not args.no_isolation:
        try:
            isolation = NodeIsolation(bpf, OBJ_DIR / "duvora_nodeiso.o", [socket.if_nametoindex(i) for i in interfaces])
        except OSError as exc:
            if args.ebpf == "required":
                raise SystemExit(f"node isolation unavailable: {exc}")
            why = str(exc)[:200]
    steering, steer_why = None, "disabled with --no-steering" if args.no_steering else ""
    if not args.no_steering:
        try:
            steering = Steering(bpf, OBJ_DIR / "duvora_steer.o", [socket.if_nametoindex(i) for i in interfaces])
        except OSError as exc:
            steer_why = str(exc)[:200]
    call = lambda method, path, body: request(args.url, credential.current(), path, body, method=method)
    print(json.dumps({"ebpf": "loaded", "interfaces": interfaces, "programs": sensors.attached,
                      "unavailable": sensors.unavailable, "isolation": why or "attached", "steering": steer_why or "attached"}), flush=True)
    return EbpfAgent(args.host, args.url, call, sensors, isolation, why, steering=steering, steering_error=steer_why,
                     discover_assets=None if args.no_ai_discovery else discover_assets)


def main():
    p = argparse.ArgumentParser(description="Duvora host agent: read-only BlueField PCI inventory and native eBPF")
    p.add_argument("--host", default=host_slug(os.environ.get("DUVORA_HOST") or socket.gethostname()))
    p.add_argument("--site", default="unassigned")
    p.add_argument("--url", default=os.environ.get("DUVORA_URL", "http://127.0.0.1:8787"))
    p.add_argument("--submit", action="store_true")
    p.add_argument("--interval", type=int, default=0, help="0 = once; otherwise repeat every N seconds")
    p.add_argument("--ebpf", choices=("off", "auto", "required"), default=os.environ.get("DUVORA_EBPF", "off"),
                   help="load native eBPF sensors and node isolation (Linux, root or CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON)")
    p.add_argument("--interfaces", default=os.environ.get("DUVORA_EBPF_INTERFACES", ""),
                   help="comma-separated interfaces (default: those carrying a default route)")
    p.add_argument("--no-isolation", action="store_true", default=os.environ.get("DUVORA_EBPF_ISOLATION") == "off")
    p.add_argument("--no-steering", action="store_true", default=os.environ.get("DUVORA_EBPF_STEERING") == "off",
                   help="do not load duvora_steer (host-kernel traffic steering)")
    p.add_argument("--no-ai-discovery", action="store_true", default=os.environ.get("DUVORA_AI_DISCOVERY") == "off",
                   help="do not report local AI services found in /proc")
    p.add_argument("--no-token-rotation", action="store_true", default=os.environ.get("DUVORA_AGENT_ROTATE") == "off",
                   help="use the bootstrap key directly instead of short-lived agent tokens")
    args = p.parse_args()
    if args.interval < 0 or (args.interval and args.interval < 10):
        p.error("Interval must be zero or at least 10 seconds")
    token = os.environ.get("DUVORA_TOKEN", "") or host_token(os.environ.get("DUVORA_AGENT_KEYS_FILE"), args.host)
    if (args.submit or args.ebpf != "off") and not token:
        p.error("Set DUVORA_TOKEN to a host-bound agent key")
    if args.ebpf != "off" and not args.interval:
        args.interval = 15
    credential = Credential(args.url, token, rotate=not args.no_token_rotation and bool(token))
    ebpf = start_ebpf(args, credential) if args.ebpf != "off" else None
    while True:
        reports = discover(host=args.host, site=args.site)
        if args.submit:
            for report in reports:
                try:
                    request(args.url, credential.current(), "/api/v1/reports", report)
                except OSError as exc:
                    print(json.dumps({"report": report["id"], "error": str(exc)}), flush=True)
            print(json.dumps({"submitted": len(reports), "host": args.host}), flush=True)
        elif args.ebpf == "off":
            print(json.dumps(reports, indent=2), flush=True)
        if ebpf:
            applied = ebpf.step()
            print(json.dumps({"ebpf": "reported", "isolation": applied["mode"], "demoted": applied["demoted"],
                              "steering": ebpf.steer_applied["mode"], "steering_demoted": ebpf.steer_applied["demoted"],
                              "errors": ebpf.errors[-3:]}), flush=True)
        if not args.interval:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()


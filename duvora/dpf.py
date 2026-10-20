"""DPF read-only import bridge. Uses kubectl's existing auth/TLS context."""
import argparse
import hashlib
import json
import os
import subprocess

from .cli import request


def convert(items, host, site):
    reports = []
    for item in items:
        meta = item.get("metadata", {})
        status = item.get("status", {})
        uid = meta.get("uid")
        if not uid:
            raise ValueError("DPF object lacks metadata.uid")
        ready = next((c for c in status.get("conditions", []) if c.get("type") == "Ready"), {})
        health = {"Ready": "healthy", "Error": "degraded"}.get(status.get("phase"), {"True": "healthy", "False": "degraded"}.get(ready.get("status"), "unknown"))
        reports.append({"id": "dpf-" + hashlib.sha256(uid.encode()).hexdigest()[:16],
            "host": host, "site": site, "source": "nvidia-dpf", "model": "NVIDIA DPF managed DPU",
            "firmware": "unknown", "health": health, "metrics": {}, "interfaces": []})
    return reports


def main():
    p = argparse.ArgumentParser(description="Import observed DPF DPU objects; no apply/patch/delete operations")
    p.add_argument("--context", required=True)
    p.add_argument("--namespace", default="dpf-operator-system")
    p.add_argument("--host", required=True, help="Bridge identity bound to agent:<host> access key")
    p.add_argument("--site", default="unassigned")
    p.add_argument("--submit", action="store_true")
    p.add_argument("--url", default=os.environ.get("DUVORA_URL", "http://127.0.0.1:8787"))
    args = p.parse_args()
    token = os.environ.get("DUVORA_TOKEN", "")
    if args.submit and not token:
        p.error("Set DUVORA_TOKEN to the bridge's host-bound agent key")
    try:
        proc = subprocess.run(["kubectl", "--context", args.context, "--namespace", args.namespace,
            "--request-timeout=15s", "get", "dpus.provisioning.dpu.nvidia.com", "-o", "json"],
            capture_output=True, text=True, timeout=20, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        detail = (getattr(exc, "stderr", "") or str(exc)).strip()[:300]
        raise SystemExit(f"kubectl failed: {detail}")
    reports = convert(json.loads(proc.stdout)["items"], args.host, args.site)
    if args.submit:
        for report in reports:
            request(args.url, token, "/api/v1/reports", report)
    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()

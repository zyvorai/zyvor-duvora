# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

"""Read-mostly bridge to a Netra controller: eBPF telemetry, drop reasons, TCP events, flows,
capability probes, and (when Netra supports it) node-scoped isolation in shadow or enforce mode."""
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import quote, urlencode, urlsplit

LOOPBACK = {"localhost", "127.0.0.1", "::1"}
FLOW_WINDOW = "1h"
TALKER_WINDOW = 900


class NetraError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class NetraClient:
    def __init__(self, url, api_key, ca_file=None, timeout=10):
        parts = urlsplit(url or "")
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.query or parts.fragment:
            raise ValueError("DUVORA_NETRA_URL must be an http(s) origin")
        if parts.scheme != "https" and parts.hostname not in LOOPBACK:
            raise ValueError("DUVORA_NETRA_URL must use HTTPS unless it is loopback")
        if not api_key:
            raise ValueError("DUVORA_NETRA_API_KEY is required")
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        handlers = [NoRedirect()]
        if parts.scheme == "https":
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file or None)))
        self.opener = urllib.request.build_opener(*handlers)

    @classmethod
    def from_env(cls):
        url = os.environ.get("DUVORA_NETRA_URL", "")
        if not url:
            return None
        return cls(url, os.environ.get("DUVORA_NETRA_API_KEY", ""), os.environ.get("DUVORA_NETRA_CA_FILE") or None)

    def call(self, method, path, query=None, body=None):
        target = self.url + "/api/v1" + path + (("?" + urlencode(query)) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + self.api_key, "Accept": "application/json", "X-Netra-Actor": "duvora"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(target, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(32 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read(65536)).get("error") or exc.reason
            except (ValueError, AttributeError):
                message = exc.reason
            raise NetraError(f"Netra {method} {path}: {exc.code} {message}", exc.code) from None
        except (urllib.error.URLError, OSError) as exc:
            raise NetraError(f"Netra unreachable: {getattr(exc, 'reason', exc)}") from None
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise NetraError(f"Netra {method} {path}: invalid JSON") from None

    def get(self, path, **query):
        return self.call("GET", path, {k: v for k, v in query.items() if v is not None} or None)

    # Node-scoped isolation (requires a Netra build with /ebpf/node-isolation).
    def put_isolation(self, node, body, lease=None):
        return self.call("PUT", f"/ebpf/node-isolation/{quote(node, safe='')}", {"lease": lease} if lease else None, body)

    def delete_isolation(self, node):
        try:
            return self.call("DELETE", f"/ebpf/node-isolation/{quote(node, safe='')}")
        except NetraError as exc:
            if exc.status == 404:
                return {}
            raise


def collect(client, nodes_of_interest=None):
    """Fetch everything the store needs in one pass. Each section fails independently."""
    raw = {"fetched": time.time(), "errors": {}}

    def fetch(key, path, **query):
        try:
            raw[key] = client.get(path, **query)
        except NetraError as exc:
            raw[key] = None
            if key == "isolation" and exc.status in {404, 405}:
                raw["isolation_unsupported"] = True
            else:
                raw["errors"][key] = str(exc)

    fetch("status", "/status")
    fetch("fleet", "/fleet")
    fetch("resources", "/node-resources", limit=200)
    fetch("coverage", "/ebpf/coverage")
    fetch("interfaces", "/ebpf/interfaces", limit=64)
    fetch("drops", "/ebpf/drops", limit=200)
    fetch("flows", "/flows/history", since=FLOW_WINDOW, limit=2000)
    fetch("isolation", "/ebpf/node-isolation")
    raw["drop_info"], raw["tcp"] = {}, {}
    if nodes_of_interest is None:
        nodes_of_interest = [n.get("node") for n in (raw.get("fleet") or {}).get("nodes") or [] if isinstance(n, dict) and n.get("node")]
    for node in sorted(nodes_of_interest)[:50]:
        for key, path in (("drop_info", "/ebpf/drop-info"), ("tcp", "/ebpf/tcp-events")):
            try:
                raw[key][node] = client.get(path, node=node, top=20)
            except NetraError as exc:
                raw["errors"][f"{key}:{node}"] = str(exc)
    return raw


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else 0


def summarize(raw):
    """Reduce Netra responses to {node: summary}; tolerant of missing sections and fields."""
    nodes = {}

    def node(name):
        return nodes.setdefault(name, {"node": name, "interfaces": {}, "drops": 0, "programs": [], "flows": []})

    for n in (raw.get("fleet") or {}).get("nodes") or []:
        if isinstance(n, dict) and n.get("node"):
            s = node(n["node"])
            s.update(stale=bool(n.get("stale")), age=_num(n.get("ageSeconds")), mode=n.get("mode") or "observe",
                     program_count=_num(n.get("programs")), attached=_num(n.get("attached")))
    for n in (raw.get("resources") or {}).get("nodes") or []:
        if isinstance(n, dict) and n.get("node"):
            host = n.get("host") or {}
            node(n["node"]).update(hostname=host.get("hostname") or "", kernel=host.get("kernelRelease") or "")
    for n in (raw.get("coverage") or {}).get("nodes") or []:
        if isinstance(n, dict) and n.get("node"):
            node(n["node"])["programs"] = sorted({p.get("name") for p in n.get("programs") or [] if isinstance(p, dict) and p.get("name") and p.get("attached")})
    for n in (raw.get("interfaces") or {}).get("nodes") or []:
        if isinstance(n, dict) and n.get("node"):
            s = node(n["node"])
            for i in n.get("interfaces") or []:
                if isinstance(i, dict) and i.get("interface"):
                    s["interfaces"][str(i["interface"])] = {k: _num(i.get(k)) for k in ("packets", "bytes", "blocked")}
    for n in (raw.get("drops") or {}).get("nodes") or []:
        if isinstance(n, dict) and n.get("node"):
            stack = (n.get("stack") or {}).get("interfaces") or []
            node(n["node"])["drops"] = sum(_num(i.get("rxDropped")) + _num(i.get("txDropped")) for i in stack if isinstance(i, dict))
    for r in (raw.get("flows") or {}).get("records") or []:
        if isinstance(r, dict) and r.get("node"):
            node(r["node"])["flows"].append(r)
    for name, info in (raw.get("drop_info") or {}).items():
        s = node(name)
        state = next((x for x in info.get("nodes") or [] if isinstance(x, dict) and x.get("node") == name), {})
        s["drop_info_unavailable"] = state.get("unavailable") or ("" if state.get("reporting") else "not reporting")
        s["drop_reasons"] = [{"reason": x.get("reason", "unknown"), "count": _num(x.get("count"))}
                             for x in (info.get("reasons") or [])[:5] if isinstance(x, dict)]
    for name, info in (raw.get("tcp") or {}).items():
        s = node(name)
        state = next((x for x in info.get("nodes") or [] if isinstance(x, dict) and x.get("node") == name), {})
        totals = info.get("totals") or {}
        s["tcp_unavailable"] = "" if state.get("reporting") else (", ".join(state.get("skipped") or []) or "not reporting")
        s["tcp"] = {"retransmits": _num(totals.get("retransmits")),
                    "resets": _num(totals.get("rstSent")) + _num(totals.get("rstReceived"))}
    for item in (raw.get("isolation") or {}).get("items") or []:
        if isinstance(item, dict) and item.get("node"):
            node(item["node"])["isolation"] = item
    for s in nodes.values():
        s["btf"] = None if "drop_info_unavailable" not in s else ("btf" not in (s["drop_info_unavailable"] or "").lower())
        s["nodeiso_available"] = not raw.get("isolation_unsupported") and (
            "netra_nodeiso" in " ".join(s["programs"]) or bool((s.get("isolation") or {}).get("attached")))
    return nodes


def top_talkers(flows, now=None, window=TALKER_WINDOW, limit=5):
    """Aggregate recent flow-log records by (peer, port, protocol)."""
    now = now or time.time()
    totals = {}
    for r in flows:
        ts = _parse_time(r.get("observedAt"))
        if ts and now - ts > window:
            continue
        key = (str(r.get("peer") or "unknown"), int(_num(r.get("port"))), str(r.get("protocol") or "").lower())
        t = totals.setdefault(key, {"peer": key[0], "port": key[1], "protocol": key[2], "packets": 0, "bytes": 0, "blocked": 0})
        for k in ("packets", "bytes", "blocked"):
            t[k] += _num(r.get(k))
    return sorted(totals.values(), key=lambda t: (-t["bytes"], -t["packets"]))[:limit]


def _parse_time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None

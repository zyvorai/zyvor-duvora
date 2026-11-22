# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

"""A minimal in-process stand-in for the Netra controller API used by Duvora's bridge."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

API_KEY = "netra-test-key-0123456789abcdef"


class FakeNetra:
    def __init__(self, node="dpu-node-1", isolation=True, port=0):
        self.node = node
        self.isolation_enabled = isolation
        self.counters = {"bytes": 1_000_000, "packets": 10_000, "blocked": 0, "drops": 5, "retransmits": 10, "resets": 2}
        self.isolations = {}
        self.refuse = False
        self.calls = []
        self.flows = [
            {"observedAt": "2099-01-01T00:00:00Z", "node": node, "peer": "10.0.0.5", "port": 443, "protocol": "TCP",
             "direction": "egress", "packets": 100, "bytes": 50_000, "blocked": 0},
            {"observedAt": "2099-01-01T00:00:00Z", "node": node, "peer": "8.8.8.8", "port": 53, "protocol": "UDP",
             "direction": "egress", "packets": 40, "bytes": 4_000, "blocked": 0},
            {"observedAt": "2099-01-01T00:00:00Z", "node": node, "peer": "api.example", "port": 443, "protocol": "TCP",
             "direction": "egress", "packets": 3, "bytes": 300, "blocked": 0},
        ]
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def handle_any(self, method):
                parts = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                fake.calls.append((method, parts.path, query))
                if self.headers.get("Authorization") != "Bearer " + API_KEY:
                    return self.reply(401, {"error": "unauthorized"})
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                status, payload = fake.route(method, parts.path, query, body)
                self.reply(status, payload)

            def do_GET(self):
                self.handle_any("GET")

            def do_PUT(self):
                self.handle_any("PUT")

            def do_DELETE(self):
                self.handle_any("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def advance(self, **delta):
        for key, value in delta.items():
            self.counters[key] += value

    def route(self, method, path, query, body):
        c, node = self.counters, self.node
        if path == "/api/v1/status":
            return 200, {"version": "test"}
        if path == "/api/v1/fleet":
            return 200, {"nodes": [{"node": node, "mode": "observe", "stale": False, "ageSeconds": 2, "programs": 3, "attached": 3}]}
        if path == "/api/v1/node-resources":
            return 200, {"nodes": [{"node": node, "host": {"hostname": node, "kernelRelease": "6.8.0-test"}}]}
        if path == "/api/v1/ebpf/coverage":
            programs = [{"name": "netra_tc_ingress", "attached": True}]
            if self.isolation_enabled:
                programs.append({"name": "netra_nodeiso_egress", "attached": True})
            return 200, {"nodes": [{"node": node, "programs": programs}]}
        if path == "/api/v1/ebpf/interfaces":
            return 200, {"nodes": [{"node": node, "interfaces": [{"interface": "p0", "packets": c["packets"], "bytes": c["bytes"], "blocked": c["blocked"]}]}]}
        if path == "/api/v1/ebpf/drops":
            return 200, {"nodes": [{"node": node, "stack": {"interfaces": [{"name": "p0", "rxDropped": c["drops"], "txDropped": 0}]}}]}
        if path == "/api/v1/flows/history":
            return 200, {"records": self.flows}
        if path == "/api/v1/ebpf/drop-info":
            return 200, {"nodes": [{"node": node, "reporting": True}], "reasons": [{"reason": "NO_SOCKET", "count": 7}, {"reason": "NETFILTER_DROP", "count": 2}]}
        if path == "/api/v1/ebpf/tcp-events":
            return 200, {"nodes": [{"node": node, "reporting": True}], "totals": {"retransmits": c["retransmits"], "rstSent": c["resets"], "rstReceived": 0}}
        if path == "/api/v1/ebpf/node-isolation" and method == "GET":
            if not self.isolation_enabled:
                return 404, {"error": "not found"}
            return 200, {"items": list(self.isolations.values())}
        if path.startswith("/api/v1/ebpf/node-isolation/") and self.isolation_enabled:
            target = unquote(path.rsplit("/", 1)[1])
            if method == "PUT":
                if self.refuse:
                    return 503, {"error": "refused"}
                item = {**body, "node": target, "leaseUntil": query.get("lease"), "wouldBlockPackets": 0, "blockedPackets": 0,
                        "effectiveMode": body["mode"], "attached": True, "allowedPackets": 0,
                        "revision": self.isolations.get(target, {}).get("revision", 0) + 1}
                self.isolations[target] = item
                return 200, item
            if method == "DELETE":
                self.isolations.pop(target, None)
                return 200, {"deleted": target}
        return 404, {"error": "not found"}


if __name__ == "__main__":
    import os
    import time

    fake = FakeNetra(port=int(os.environ.get("FAKE_NETRA_PORT", "18870")))
    print(fake.url, flush=True)
    while True:
        time.sleep(5)
        fake.advance(bytes=50_000_000, packets=40_000, retransmits=3)

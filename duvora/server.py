"""HTTP API + bundled console. No runtime third-party dependencies."""
import argparse
import hmac
import json
import mimetypes
import os
import re
import signal
import ssl
import threading
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .auth import DEFAULT_ADMIN_PASSWORD, SESSION_TTL
from .core import Problem, Store
from .netra import NetraClient, collect

STATIC = Path(os.environ.get("DUVORA_WEB_DIR") or Path(__file__).with_name("static"))
SESSION_COOKIE = "duvora_session"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
RANK = {"agent": 0, "viewer": 1, "admin": 2}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
FALLBACK_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Duvora</title></head>
<body><h1>Infrastructure. In your control.</h1><p>The Duvora console has not been built. Run <code>make web</code>
(Node.js 20+), then reload. The API is available at <code>/api/v1</code>.</p></body></html>"""


class Raw:
    """A non-JSON response body (Prometheus text, Markdown, database backup)."""

    def __init__(self, data, content_type, filename=None):
        self.data, self.content_type, self.filename = data, content_type, filename


class Application:
    def __init__(self, store, keys):
        self.store = store
        self.keys = keys
        self.routes = []
        r = self.route
        r("GET", "/session", "agent", lambda c: {"actor": c.actor, "role": c.role, "demo": self.store.demo})
        r("GET", "/whoami", "agent", self.whoami)
        r("POST", "/reports", "agent-only", lambda c: self.store.report(c.actor, c.body))
        r("POST", "/agent/ebpf", "agent-only", lambda c: self.store.ingest_native(c.actor, c.body))
        r("GET", "/agent/isolation", "agent-only", lambda c: self.store.agent_isolation(c.actor))
        r("GET", "/snapshot", "viewer", lambda c: self.store.snapshot())
        r("GET", "/export", "viewer", lambda c: self.store.snapshot())
        r("GET", "/metrics", "viewer", self.metrics)
        r("GET", "/devices/{id}/history", "viewer", lambda c: self.store.history(c.args["id"], c.query.get("window", "1h")))
        r("GET", "/devices/{id}/ebpf", "viewer", lambda c: self.store.device_ebpf(c.args["id"]))
        r("GET", "/ebpf", "viewer", lambda c: self.store.ebpf_overview())
        r("POST", "/ebpf/kill-switch", "admin", lambda c: self.store.kill_switch(c.actor, c.body.get("engaged")))
        r("GET", "/incidents", "viewer", lambda c: self.store.incidents(c.query.get("state")))
        r("POST", "/incidents/{id}/{action}", "admin", lambda c: self.store.incident_action(c.actor, c.args["id"], c.args["action"]))
        r("GET", "/alert-rules", "viewer", lambda c: self.store.alert_rules())
        r("PUT", "/alert-rules/{id}", "admin", lambda c: self.store.update_rule(c.actor, c.args["id"], c.body))
        r("GET", "/scorecard", "viewer", lambda c: self.store.scorecard())
        r("GET", "/report", "viewer", lambda c: self.store.briefing(ai=c.query.get("ai") == "1"))
        r("GET", "/ai", "viewer", lambda c: self.store.ai_status())
        r("GET", "/insights", "viewer", lambda c: self.store.insights())
        r("GET", "/devices/{id}/forecast", "viewer", lambda c: self.store.forecast(c.args["id"]))
        r("GET", "/devices/{id}/allowlist-suggestions", "viewer", lambda c: self.store.suggest_allowlist(c.args["id"]))
        r("GET", "/incidents/{id}/explain", "viewer", lambda c: self.store.explain_incident(c.args["id"], c.query.get("llm") != "0"))
        r("POST", "/copilot", "viewer", lambda c: self.store.copilot(c.actor, c.role, c.body))
        r("GET", "/report.md", "viewer", lambda c: Raw(self.store.briefing()["markdown"], "text/markdown; charset=utf-8", "duvora-briefing.md"))
        r("GET", "/topology", "viewer", lambda c: self.store.topology())
        r("POST", "/plans", "admin", lambda c: self.store.plan(c.actor, c.body))
        r("POST", "/plans/{id}/apply", "admin", lambda c: self.store.apply(c.actor, c.args["id"], c.body.get("confirmation")))
        r("POST", "/jobs/{id}/rollback", "admin", lambda c: self.store.rollback(c.actor, c.args["id"]))
        r("POST", "/evaluate", "admin", lambda c: self.store.evaluate(c.body.get("device"), c.body.get("address", ""), c.body.get("port")))
        r("GET", "/users", "admin", lambda c: self.store.users())
        r("POST", "/users", "admin", lambda c: self.store.create_user(c.actor, c.body))
        r("PATCH", "/users/{id}", "admin", lambda c: self.store.update_user(c.actor, c.args["id"], c.body))
        r("DELETE", "/users/{id}", "admin", lambda c: self.store.delete_user(c.actor, c.args["id"]))
        r("POST", "/me/password", "user", lambda c: self.store.change_password(c.actor, c.body))
        r("GET", "/tokens", "user", lambda c: self.store.tokens(c.actor))
        r("POST", "/tokens", "user", lambda c: self.store.create_token(c.actor, c.body))
        r("DELETE", "/tokens/{id}", "user", lambda c: self.store.revoke_token(c.actor, c.args["id"]))
        r("GET", "/backup", "admin", lambda c: Raw(self.store.backup(c.actor), "application/vnd.sqlite3", "duvora-backup.db"))
        # Traffic steering (host-kernel eBPF or simulation) and bypass.
        r("GET", "/agent/steering", "agent-only", lambda c: self.store.agent_steering(c.actor))
        r("POST", "/agent/token", "agent-only", lambda c: self.store.mint_agent_token(c.actor, c.via))
        r("GET", "/steering", "viewer", lambda c: self.store.steering_overview())
        r("GET", "/steering/sets/{id}", "viewer", lambda c: self.store.steering_set(c.args["id"]))
        r("PUT", "/steering/sets/{id}", "admin", lambda c: self.store.put_steering_set(c.actor, c.args["id"], c.body))
        r("DELETE", "/steering/sets/{id}", "admin", lambda c: self.store.delete_steering_set(c.actor, c.args["id"]))
        r("POST", "/steering/evaluate", "viewer", lambda c: self.store.evaluate_steering(c.body))
        r("POST", "/steering/explain", "viewer", lambda c: self.store.explain_verdict(c.body, c.query.get("llm") != "0"))
        r("GET", "/devices/{id}/steering", "viewer", lambda c: self.store.device_steering(c.args["id"]))
        r("POST", "/devices/{id}/steering/bypass", "admin", lambda c: self.store.set_bypass(
            c.actor, c.args["id"], c.body.get("engaged"), c.body.get("confirmation"), str(c.body.get("reason") or "manual")[:100]))
        r("GET", "/devices/{id}/steering-suggestions", "viewer", lambda c: self.store.suggest_steering(c.args["id"]))
        r("GET", "/verdicts", "viewer", lambda c: self.store.verdicts(c.query.get("device"), c.query.get("action"), c.query.get("rule"), c.query.get("limit", 200)))
        r("GET", "/devices/{id}/budget", "viewer", lambda c: self.store.budget(c.args["id"]))
        # AI protection, discovery, scanning, threat intel, playbooks, SIEM, agent identity.
        r("GET", "/ai-traffic", "viewer", lambda c: self.store.ai_traffic())
        r("GET", "/ai/findings", "viewer", lambda c: self.store.ai_findings(c.query.get("device"), c.query.get("kind"), None, c.query.get("limit", 200)))
        r("GET", "/ai/assets", "viewer", lambda c: self.store.ai_assets())
        r("GET", "/ai/posture", "viewer", lambda c: self.store.ai_posture())
        r("POST", "/ai/sanctioned", "admin", lambda c: self.store.add_sanctioned(c.actor, c.body))
        r("DELETE", "/ai/sanctioned/{id}", "admin", lambda c: self.store.delete_sanctioned(c.actor, c.args["id"]))
        r("GET", "/scans", "viewer", lambda c: self.store.scans(c.query.get("target")))
        r("POST", "/scans", "admin", lambda c: self.store.start_scan(c.actor, c.body))
        r("GET", "/scans/{id}", "viewer", lambda c: self.store.scan(c.args["id"]))
        r("GET", "/intel", "viewer", lambda c: self.store.intel_overview())
        r("PUT", "/intel/feeds/{id}", "admin", lambda c: self.store.put_feed(c.actor, c.args["id"], c.body))
        r("DELETE", "/intel/feeds/{id}", "admin", lambda c: self.store.delete_feed(c.actor, c.args["id"]))
        r("POST", "/intel/refresh", "admin", lambda c: self.store.refresh_feeds(only=c.body.get("feed")))
        r("POST", "/intel/ruleset", "admin", lambda c: self.store.intel_ruleset(c.actor, c.body))
        r("GET", "/playbooks", "viewer", lambda c: self.store.playbooks())
        r("PUT", "/playbooks/{id}", "admin", lambda c: self.store.put_playbook(c.actor, c.args["id"], c.body))
        r("DELETE", "/playbooks/{id}", "admin", lambda c: self.store.delete_playbook(c.actor, c.args["id"]))
        r("POST", "/playbooks/{id}/run", "admin", lambda c: self.store.run_playbook_manual(c.actor, c.args["id"], c.body))
        r("GET", "/playbook-runs", "viewer", lambda c: self.store.playbook_runs(c.query.get("incident"), c.query.get("limit", 100)))
        r("GET", "/siem", "admin", lambda c: self.store.siem_status())
        r("POST", "/siem/test", "admin", lambda c: self.store.siem_test(c.actor))
        r("GET", "/agent-identities", "admin", lambda c: self.store.agent_identities())
        store.agent_key_hosts = {a.split(":", 1)[1] for a in keys if a.startswith("agent:")}

    def route(self, method, pattern, access, fn):
        regex = re.compile("^/api/v1" + re.sub(r"\{(\w+)\}", r"(?P<\1>[A-Za-z0-9._-]{1,128})", re.escape(pattern).replace(r"\{", "{").replace(r"\}", "}")) + "$")
        self.routes.append((method, regex, access, fn))

    def resolve(self, token, client=None):
        """Resolve a bearer: configured access keys, then short-lived agent tokens, then personal user tokens."""
        for actor, (role, secret) in self.keys.items():
            if hmac.compare_digest(token.encode(), secret.encode()):
                return actor, role, "key"
        if token.startswith("dva_"):
            host = self.store.agent_token_user(token)
            if host:
                return f"agent:{host}", "agent", "agent-token"
            if client:
                self.store.note_unknown_agent(client)
            raise Problem("Agent token is unknown or expired", 401)
        user = self.store.token_user(token) if token else None
        if user:
            return user["username"], user["role"], "token"
        raise Problem("Sign in to continue", 401)

    def identity(self, token):
        return self.resolve(token)[:2]

    def authenticate(self, bearer, session, client=None):
        if bearer:
            return self.resolve(bearer, client)
        user = self.store.session_user(session)
        if user:
            return user["username"], user["role"], "session"
        raise Problem("Sign in to continue", 401)

    def whoami(self, c):
        out = {"actor": c.actor, "role": c.role, "via": c.via, "demo": self.store.demo, "version": __version__, "default_password": False}
        if c.via in {"session", "token"}:
            out["default_password"] = self.store.public_user(self.store.user(c.actor))["default_password"]
        return out

    def metrics(self, c):
        snapshot = self.store.snapshot()
        lines = ["# HELP duvora_devices Device inventory by observation source", "# TYPE duvora_devices gauge"]
        for source in ("simulator", "linux-pci", "nvidia-dpf", "netra-ebpf", "duvora-ebpf"):
            lines.append(f'duvora_devices{{source="{source}"}} {sum(d["source"] == source for d in snapshot["devices"])}')
        lines += ["# TYPE duvora_jobs gauge", f'duvora_jobs {len(snapshot["jobs"])}',
                  "# TYPE duvora_open_incidents gauge", f'duvora_open_incidents {snapshot["open_incidents"]}',
                  "# HELP duvora_anomalies Metrics currently deviating from their learned baseline", "# TYPE duvora_anomalies gauge",
                  f'duvora_anomalies {len(self.store.anomalies())}']
        steering = [d.get("steering") or {} for d in snapshot["devices"]]
        lines += ["# HELP duvora_steering_devices Devices with steering by stage", "# TYPE duvora_steering_devices gauge"]
        for stage in ("shadow", "enforce"):
            lines.append(f'duvora_steering_devices{{stage="{stage}"}} {sum(s.get("stage") == stage for s in steering)}')
        lines += ["# TYPE duvora_steering_bypass gauge", f'duvora_steering_bypass {sum(bool((s.get("bypass") or {}).get("engaged")) for s in steering)}']
        siem = self.store.siem_status()
        lines += ["# HELP duvora_siem_dropped Events dropped because the SIEM queue was full", "# TYPE duvora_siem_dropped counter",
                  f'duvora_siem_dropped {siem.get("dropped", 0)}', "# TYPE duvora_siem_queued gauge", f'duvora_siem_queued {siem.get("queued", 0)}']
        return "\n".join(lines) + "\n"

    def dispatch(self, method, path, actor, role, body=None, query=None, via="key"):
        allowed = False
        for m, regex, access, fn in self.routes:
            match = regex.match(path)
            if not match:
                continue
            allowed = True
            if m != method:
                continue
            if access == "agent-only":
                if role != "agent":
                    raise Problem("Only agent keys submit device reports", 403)
            elif role == "agent" and access != "agent":
                raise Problem("Agent keys may only submit device reports", 403)
            elif access == "user":
                if via not in {"session", "token"}:
                    raise Problem("This operation requires a named user, not an access key", 403)
            elif RANK[role] < RANK[access]:
                raise Problem("This operation requires an administrator", 403)
            return fn(Call(actor, role, via, body if body is not None else {}, query or {}, match.groupdict()))
        if allowed:
            raise Problem("Method not allowed", 405)
        raise Problem("Endpoint not found", 404)


class Call:
    def __init__(self, actor, role, via, body, query, args):
        self.actor, self.role, self.via, self.body, self.query, self.args = actor, role, via, body, query, args


def static_file(path):
    """Map a URL path to a file under STATIC; unknown extensionless paths fall back to the SPA shell."""
    root = STATIC.resolve()
    rel = path.lstrip("/") or "index.html"
    if ".." in rel.split("/") or "\\" in rel or "\x00" in rel:
        raise Problem("Page not found", 404)
    candidate = (root / rel).resolve()
    if candidate.is_file() and candidate.is_relative_to(root):
        return candidate
    if "." not in rel.rsplit("/", 1)[-1] and (root / "index.html").is_file():
        return root / "index.html"
    raise Problem("Page not found", 404)


def handler(app, tls=False):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"Duvora/{__version__}"

        def log_message(self, fmt, *args):
            # No query strings, keys, cookies or request bodies in logs.
            print(f"{self.command} {urlsplit(self.path).path} {args[1] if len(args) > 1 else ''}", flush=True)

        def send(self, status, payload, content_type="application/json", cookie=None, filename=None, cache=False):
            if isinstance(payload, bytes):
                data = payload
            elif isinstance(payload, str):
                data = payload.encode()
            else:
                data = json.dumps(payload, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=31536000, immutable" if cache else "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            if tls:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.process("GET")

        def do_POST(self):
            self.process("POST")

        def do_PUT(self):
            self.process("PUT")

        def do_PATCH(self):
            self.process("PATCH")

        def do_DELETE(self):
            self.process("DELETE")

        def secure(self):
            return tls or self.headers.get("X-Forwarded-Proto", "").lower() == "https"

        def session_cookie(self, value, max_age):
            return (f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
                    + ("; Secure" if self.secure() else ""))

        def cookie_session(self):
            try:
                jar = SimpleCookie(self.headers.get("Cookie", ""))
            except CookieError:
                return ""
            return jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else ""

        def cert_names(self):
            """DNS names and common name from a verified client certificate, if any."""
            getpeercert = getattr(self.connection, "getpeercert", None)
            cert = getpeercert() if getpeercert else None
            if not cert:
                return set()
            names = {v for k, v in cert.get("subjectAltName", ()) if k == "DNS"}
            names |= {v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"}
            return names

        def read_body(self, method):
            if method not in {"POST", "PUT", "PATCH"}:
                return None
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise Problem("Content-Type must be application/json", 415)
            if self.headers.get("Transfer-Encoding"):
                raise Problem("Chunked bodies are not supported")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise Problem("Body must contain 1–65536 bytes", 413)
            try:
                body = json.loads(self.rfile.read(length), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
            except (ValueError, UnicodeError):
                raise Problem("Invalid JSON") from None
            if not isinstance(body, dict):
                raise Problem("JSON body must be an object")
            return body

        def process(self, method):
            self.connection.settimeout(10)
            parts = urlsplit(self.path)
            path = parts.path
            try:
                if method == "GET" and path == "/healthz":
                    return self.send(200, {"status": "ok", "version": __version__})
                if method == "GET" and not path.startswith("/api/"):
                    if not STATIC.is_dir():
                        if path in {"/", "/index.html"}:
                            return self.send(200, FALLBACK_PAGE, "text/html; charset=utf-8")
                        raise Problem("Page not found", 404)
                    f = static_file(path)
                    kind = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
                    if kind.startswith("text/") or kind in {"application/javascript", "image/svg+xml"}:
                        kind += "; charset=utf-8"
                    return self.send(200, f.read_bytes(), kind, cache=path.startswith("/assets/"))
                body = self.read_body(method)
                if path == "/api/v1/session" and method == "POST":
                    raw, user = app.store.login(body.get("username"), body.get("password"), self.client_address[0])
                    return self.send(200, {"actor": user["username"], "role": user["role"], "default_password": user["default_password"]},
                                     cookie=self.session_cookie(raw, SESSION_TTL))
                if path == "/api/v1/session" and method == "DELETE":
                    if self.cookie_session():
                        app.store.logout(self.cookie_session())
                    return self.send(200, {"ok": True}, cookie=self.session_cookie("", 0))
                auth = self.headers.get("Authorization", "")
                actor, role, via = app.authenticate(auth[7:] if auth.startswith("Bearer ") else "", self.cookie_session(), self.client_address[0])
                if role == "agent":
                    app.store.check_agent_identity(actor, via, self.cert_names(), path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                result = app.dispatch(method, path, actor, role, body, query, via)
                if isinstance(result, Raw):
                    return self.send(200, result.data, result.content_type, filename=result.filename)
                self.send(200, result, "text/plain; version=0.0.4" if path.endswith("/metrics") else "application/json")
            except Problem as exc:
                self.send(exc.status, {"error": str(exc)})
            except (ValueError, TypeError, AttributeError):
                self.send(400, {"error": "Invalid request"})
            except Exception:
                self.send(500, {"error": "Internal error; request was not completed"})
    return Handler


def load_keys():
    raw = os.environ.get("DUVORA_KEYS", "")
    data = json.loads(raw) if raw else {}
    if raw and (not isinstance(data, dict) or not data):
        raise ValueError("DUVORA_KEYS must be a non-empty JSON object")
    # Host-bound agent keys for a fleet (the Helm agent DaemonSet): {"host": "token"}.
    agents = json.loads(os.environ.get("DUVORA_AGENT_KEYS") or "{}")
    if not isinstance(agents, dict):
        raise ValueError("DUVORA_AGENT_KEYS must be a JSON object of host to token")
    for host, token in agents.items():
        data.setdefault(f"agent:{host}", {"role": "agent", "token": token})
    if not data:
        return {}
    keys = {}
    for actor, value in data.items():
        if not isinstance(actor, str) or len(actor) > 128 or not isinstance(value, dict):
            raise ValueError("Invalid principal")
        role, token = value.get("role"), value.get("token")
        if role not in {"admin", "viewer", "agent"} or not isinstance(token, str) or len(token) < 24 or not token.isascii():
            raise ValueError("Each principal needs a role and a token of at least 24 characters")
        if role == "agent" and not actor.startswith("agent:"):
            raise ValueError("Agent principals must be named agent:<hostname>")
        if any(hmac.compare_digest(token, existing[1]) for existing in keys.values()):
            raise ValueError("Access keys must be unique")
        keys[actor] = (role, token)
    return keys


def netra_sync(store, client, stop, interval=None):
    """Poll Netra (when configured) outside the store lock, then merge; also runs isolation duties
    (jobs, kill switch, lease renewal) for both the native and the Netra provider."""
    interval = interval or max(5, int(os.environ.get("DUVORA_NETRA_INTERVAL", "15") or 15))
    while True:
        try:
            if client:
                store.ingest_netra(collect(client, store.netra_wanted_nodes()))
            store.netra_duties(client)
        except Exception as exc:
            print(f"eBPF sync error: {type(exc).__name__}: {exc}"[:300], flush=True)
        # Applied jobs wake the loop so they do not wait a whole polling interval.
        for _ in range(interval):
            if stop.wait(1):
                return
            if store.netra_wake.is_set():
                store.netra_wake.clear()
                try:
                    store.netra_duties(client)
                except Exception as exc:
                    print(f"eBPF job error: {type(exc).__name__}: {exc}"[:300], flush=True)


def main():
    parser = argparse.ArgumentParser(description="Duvora control plane and console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=int(os.environ.get("DUVORA_PORT", "8787")), type=int)
    parser.add_argument("--db", default=os.environ.get("DUVORA_DB", "dpu.db"))
    parser.add_argument("--demo", action="store_true", default=os.environ.get("DUVORA_DEMO") == "1",
                        help="Enable explicit simulated inventory and mutations")
    parser.add_argument("--tls-cert", default=os.environ.get("DUVORA_TLS_CERT"))
    parser.add_argument("--tls-key", default=os.environ.get("DUVORA_TLS_KEY"))
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be used together")
    # A network listener must not start with an implicit credential nobody chose.
    if args.host not in LOOPBACK and not (os.environ.get("DUVORA_KEYS") or os.environ.get("DUVORA_ADMIN_PASSWORD")):
        parser.error("Network binding requires DUVORA_ADMIN_PASSWORD or DUVORA_KEYS")
    keys = load_keys()
    try:
        netra = NetraClient.from_env()
    except ValueError as exc:
        parser.error(str(exc))
    try:
        store = Store(args.db, args.demo)
    except ValueError as exc:
        parser.error(str(exc))
    if store.mtls_mode != "off" and not (args.tls_cert and os.environ.get("DUVORA_AGENT_CA")):
        parser.error("DUVORA_AGENT_MTLS needs --tls-cert/--tls-key and DUVORA_AGENT_CA")
    if netra:
        store.configure_netra(netra.url, os.environ.get("DUVORA_NETRA_ENFORCE") == "1", netra)
    app = Application(store, keys)
    httpd = ThreadingHTTPServer((args.host, args.port), handler(app, tls=bool(args.tls_cert)))
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        if os.environ.get("DUVORA_AGENT_CA"):
            # Optional at the TLS layer so browsers still connect; agents are checked per request (DUVORA_AGENT_MTLS).
            context.load_verify_locations(os.environ["DUVORA_AGENT_CA"])
            context.verify_mode = ssl.CERT_OPTIONAL
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    stop = threading.Event()

    def reconcile():
        while not stop.wait(1):
            try:
                store.tick()
                store.maintain()
            except Exception as exc:
                print(f"Reconciler error: {type(exc).__name__}", flush=True)

    worker = threading.Thread(target=reconcile, daemon=True)
    worker.start()
    threading.Thread(target=netra_sync, args=(store, netra, stop), daemon=True).start()

    def shutdown(*_):
        threading.Thread(target=httpd.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    scheme = "https" if args.tls_cert else "http"
    print(f"Duvora console: {scheme}://{args.host}:{args.port} | simulation={'on' if args.demo else 'off'}", flush=True)
    admin = store.db.execute("SELECT default_password FROM users WHERE username='admin'").fetchone()
    if admin and admin[0]:
        print(f"Sign in as admin / {DEFAULT_ADMIN_PASSWORD} — the default password; change it under Govern → Users.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        worker.join(timeout=5)
        httpd.server_close()
        store.close()


if __name__ == "__main__":
    main()

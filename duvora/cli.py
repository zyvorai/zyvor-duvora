"""duvoractl — operator CLI, using the same HTTP contract as the console."""
import argparse
import getpass
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit

ENV_FILE = Path(os.environ.get("DUVORA_ENV_FILE") or Path.home() / ".duvora" / "env")
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def read_env_file(path=None):
    """KEY=VALUE lines written by `duvoractl login` or deploy-remote.sh."""
    path = Path(path or ENV_FILE)
    values = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("'\"")
    except OSError:
        pass
    return values


def write_env_file(values, path=None):
    path = Path(path or ENV_FILE)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = "# Written by duvoractl — holds a personal API token; keep private.\n"
    body += "".join(f"{k}={v}\n" for k, v in values.items() if v)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.chmod(path, 0o600)


def setting(name, default=""):
    return os.environ.get(name) or read_env_file().get(name) or default


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def check_url(url):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise ValueError("URL must be an HTTP(S) origin without credentials, query, fragment or path")
    if parts.scheme != "https" and parts.hostname not in LOOPBACK:
        raise ValueError("Remote access requires HTTPS")
    return parts


def open_url(url, path, token="", body=None, method=None, cookie="", ca_file=None, timeout=15):
    parts = check_url(url)
    data = json.dumps(body, allow_nan=False).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url.rstrip("/") + path, data=data, headers=headers, method=method)
    handlers = [NoRedirect()]
    if parts.scheme == "https":
        # A self-signed deployment is trusted by pinning its certificate, never by disabling verification.
        ca = ca_file if ca_file is not None else setting("DUVORA_CA_FILE")
        context = ssl.create_default_context(cafile=ca or None)
        if setting("DUVORA_CLIENT_CERT"):
            # Agent mTLS (DUVORA_AGENT_MTLS on the server): the certificate names this host.
            context.load_cert_chain(setting("DUVORA_CLIENT_CERT"), setting("DUVORA_CLIENT_KEY") or None)
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def decode(response, path):
    data = response.read(64 * 1024 * 1024)
    kind = response.headers.get("Content-Type", "")
    if "application/json" in kind:
        return json.loads(data)
    if kind.startswith("text/"):
        return data.decode()
    return data


def request(url, token, path, body=None, method=None, cookie="", ca_file=None, timeout=15):
    with open_url(url, path, token, body, method, cookie, ca_file, timeout) as response:
        return decode(response, path)


def prompt_password(label="Password"):
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass(f"{label}: ")


def login(args):
    username = args.user or (input("Username [admin]: ").strip() if sys.stdin.isatty() else "") or "admin"
    password = prompt_password()
    with open_url(args.url, "/api/v1/session", body={"username": username, "password": password}) as response:
        cookie = (response.headers.get("Set-Cookie") or "").split(";", 1)[0]
        decode(response, "/api/v1/session")
    try:
        label = f"duvoractl@{socket.gethostname()}"[:64]
        token = request(args.url, "", "/api/v1/tokens", {"name": label}, cookie=cookie)
    finally:
        try:
            request(args.url, "", "/api/v1/session", method="DELETE", cookie=cookie)
        except (urllib.error.URLError, ValueError):
            pass
    values = read_env_file()
    values.update(DUVORA_URL=args.url.rstrip("/"), DUVORA_TOKEN=token["token"], DUVORA_TOKEN_ID=token["id"])
    if os.environ.get("DUVORA_CA_FILE"):
        values["DUVORA_CA_FILE"] = os.environ["DUVORA_CA_FILE"]
    write_env_file(values)
    return {"signed_in": username, "token": token["name"], "saved": str(ENV_FILE)}


def logout(args, token):
    values = read_env_file()
    if values.get("DUVORA_TOKEN_ID") and token:
        try:
            request(args.url, token, f"/api/v1/tokens/{quote(values['DUVORA_TOKEN_ID'])}", method="DELETE")
        except urllib.error.HTTPError as exc:
            if exc.code not in {401, 404}:
                raise
    values.pop("DUVORA_TOKEN", None)
    values.pop("DUVORA_TOKEN_ID", None)
    write_env_file(values)
    return {"signed_out": True, "saved": str(ENV_FILE)}


def build_parser():
    p = argparse.ArgumentParser(description="duvoractl — Duvora operator CLI")
    p.add_argument("--url", default=None, help="Control-plane origin (default: DUVORA_URL or ~/.duvora/env)")
    sub = p.add_subparsers(dest="command", required=True)
    for cmd in ("status", "devices", "jobs", "policies", "audit", "export", "metrics", "whoami", "scorecard", "topology", "logout", "passwd"):
        sub.add_parser(cmd)
    lg = sub.add_parser("login", help="Sign in with a username and password and save a personal API token")
    lg.add_argument("--user", "-u")
    sub.add_parser("plan").add_argument("file", help="JSON plan spec")
    ap = sub.add_parser("apply"); ap.add_argument("plan_id"); ap.add_argument("--confirm", required=True)
    sub.add_parser("rollback").add_argument("job_id")
    ev = sub.add_parser("evaluate"); ev.add_argument("device"); ev.add_argument("address"); ev.add_argument("port", type=int)
    inc = sub.add_parser("incidents"); inc.add_argument("--state", default="active", choices=["active", "open", "acknowledged", "resolved", "all"])
    sub.add_parser("ack").add_argument("incident_id")
    sub.add_parser("resolve").add_argument("incident_id")
    rp = sub.add_parser("report"); rp.add_argument("--markdown", action="store_true")
    hs = sub.add_parser("history"); hs.add_argument("device"); hs.add_argument("--window", default="1h", choices=["1h", "24h", "7d"])
    rules = sub.add_parser("rules")
    rules.add_argument("rule_id", nargs="?")
    rules.add_argument("--threshold", type=float)
    rules.add_argument("--severity", choices=["info", "warning", "critical"])
    rules.add_argument("--enable", dest="enabled", action="store_const", const=True)
    rules.add_argument("--disable", dest="enabled", action="store_const", const=False)
    users = sub.add_parser("users")
    users.add_argument("action", nargs="?", default="list", choices=["list", "add", "role", "disable", "enable", "delete", "reset-password"])
    users.add_argument("username", nargs="?")
    users.add_argument("--role", choices=["admin", "viewer"])
    sub.add_parser("backup").add_argument("file")
    sub.add_parser("ebpf", help="eBPF overview (provider: native agent or Netra), or one device's kernel observations").add_argument("device", nargs="?")
    sh = sub.add_parser("shadow", help="Run an allow-list in kernel shadow mode on a device (counts, never drops)")
    sh.add_argument("device"); sh.add_argument("--cidr", required=True); sh.add_argument("--ports", default="", help="Comma-separated; empty = all")
    sh.add_argument("--name", default="duvoractl"); sh.add_argument("--tenant", default="default")
    sh.add_argument("--yes", action="store_true", help="Apply the shadow plan without a second step")
    en = sub.add_parser("enforce", help="Promote a device's shadow allow-list to enforcement (prints the plan unless --confirm)")
    en.add_argument("device"); en.add_argument("--confirm", help="Must be ENFORCE ON <device>")
    ks = sub.add_parser("kill-switch", help="Engage (on) or release (off) the eBPF enforcement kill switch")
    ks.add_argument("state", choices=["on", "off"])
    sub.add_parser("insights", help="Anomalies, forecasts and new egress destinations (computed locally)")
    sub.add_parser("forecast", help="Temperature and throughput forecast for a device").add_argument("device")
    sub.add_parser("suggest", help="Allow-list candidates from a device's observed egress, ranked by coverage").add_argument("device")
    ex = sub.add_parser("explain", help="Evidence, hypotheses and a written explanation for an incident")
    ex.add_argument("incident_id"); ex.add_argument("--no-llm", action="store_true", help="Rule-based explanation only")
    ask = sub.add_parser("ask", help="Ask the ops copilot (needs DUVORA_AI_URL on the server); it never applies changes")
    ask.add_argument("question", nargs="+")
    st = sub.add_parser("steering", help="Steering overview, a device's steering state, or a rule set (host-kernel eBPF or simulation)")
    st.add_argument("device", nargs="?"); st.add_argument("--set", dest="ruleset", help="Show one rule set")
    st.add_argument("--put", metavar="FILE", help="Create or replace --set from a JSON file ({description, default, rules})")
    st.add_argument("--delete", action="store_true", help="Delete --set (only when no device uses it)")
    sp = sub.add_parser("steer", help="Plan a steering rule set on devices (prints the plan unless --confirm)")
    sp.add_argument("ruleset"); sp.add_argument("devices", nargs="+")
    sp.add_argument("--stage", default="shadow", choices=["shadow", "enforce"]); sp.add_argument("--confirm")
    us = sub.add_parser("unsteer", help="Plan removing steering from devices (prints the plan unless --confirm)")
    us.add_argument("devices", nargs="+"); us.add_argument("--confirm")
    bp = sub.add_parser("bypass", help="Engage (on) or release (off) steering bypass on a device")
    bp.add_argument("device"); bp.add_argument("state", choices=["on", "off"])
    bp.add_argument("--confirm", required=True, help="BYPASS <device> or RESUME <device>"); bp.add_argument("--reason", default="manual")
    vd = sub.add_parser("verdicts", help="Recent steering verdicts (flow samples)")
    vd.add_argument("--device"); vd.add_argument("--action", choices=["allow", "inspect", "drop"]); vd.add_argument("--rule"); vd.add_argument("--limit", type=int, default=50)
    fl = sub.add_parser("flow", help="Which steering rule matches a flow, with an explanation")
    fl.add_argument("target", help="A device id or, with --set, a rule set id"); fl.add_argument("--set", dest="by_set", action="store_true")
    fl.add_argument("--direction", default="egress", choices=["ingress", "egress"]); fl.add_argument("--src"); fl.add_argument("--dst")
    fl.add_argument("--protocol", default="tcp"); fl.add_argument("--sport", type=int); fl.add_argument("--dport", type=int)
    fl.add_argument("--no-llm", action="store_true")
    sub.add_parser("steer-suggest", help="Steering rule candidates from a device's observed traffic").add_argument("device")
    sub.add_parser("budget", help="A device's resource capacity, reservations and headroom").add_argument("device")
    sub.add_parser("ai-traffic", help="LLM endpoints, providers and findings seen by inspection")
    af = sub.add_parser("ai-findings", help="Inspection findings (prompt injection, secrets, sensitive data)")
    af.add_argument("--device"); af.add_argument("--kind"); af.add_argument("--limit", type=int, default=50)
    asx = sub.add_parser("assets", help="Discovered AI assets; sanction or unsanction them")
    asx.add_argument("action", nargs="?", default="list", choices=["list", "sanction", "unsanction"])
    asx.add_argument("--kind"); asx.add_argument("--name"); asx.add_argument("--device"); asx.add_argument("--note", default="")
    asx.add_argument("--id", help="Sanctioned entry id (unsanction)")
    sc = sub.add_parser("scan", help="Scan an image or model (server-side), list scans, or scan a local file offline")
    g = sc.add_mutually_exclusive_group()
    g.add_argument("--image", help="Digest-pinned image reference"); g.add_argument("--model-url", help="HTTPS URL of a model file")
    g.add_argument("--file", help="Scan a local file here; nothing is uploaded"); g.add_argument("--id", help="Show one scan")
    it = sub.add_parser("intel", help="Threat-intel feeds and matches")
    it.add_argument("action", nargs="?", default="list", choices=["list", "refresh", "add-feed", "remove-feed", "ruleset"])
    it.add_argument("--feed"); it.add_argument("--url"); it.add_argument("--format", default="plain", choices=["plain", "csv", "stix"])
    it.add_argument("--id", default="threat-intel", help="Rule set id (ruleset)"); it.add_argument("--base", help="Rule set whose rules follow the intel drops")
    pb = sub.add_parser("playbooks", help="Response playbooks (draft-only) and their runs")
    pb.add_argument("action", nargs="?", default="list", choices=["list", "runs", "run", "put", "delete"])
    pb.add_argument("--id"); pb.add_argument("--incident"); pb.add_argument("--file", help="JSON body (put)")
    sub.add_parser("siem", help="SIEM export status (admin)").add_argument("--test", action="store_true", help="Send a test event")
    sub.add_parser("agents", help="Agent identities: tokens, rotation and mTLS (admin)")
    return p


def ports_arg(text):
    try:
        return sorted({int(x) for x in text.split(",") if x.strip()})
    except ValueError:
        raise ValueError("--ports must be comma-separated integers") from None


def run(args, token):
    call = lambda path, body=None, method=None: request(args.url, token, path, body, method)
    c = args.command
    if c == "plan":
        with open(args.file) as f:
            return call("/api/v1/plans", json.load(f))
    if c == "apply":
        return call(f"/api/v1/plans/{quote(args.plan_id)}/apply", {"confirmation": args.confirm})
    if c == "rollback":
        return call(f"/api/v1/jobs/{quote(args.job_id)}/rollback", {})
    if c == "evaluate":
        return call("/api/v1/evaluate", {"device": args.device, "address": args.address, "port": args.port})
    if c in {"export", "metrics", "whoami", "scorecard", "topology"}:
        return call(f"/api/v1/{c}")
    if c == "incidents":
        return call("/api/v1/incidents" + ("" if args.state == "all" else f"?state={args.state}"))
    if c in {"ack", "resolve"}:
        return call(f"/api/v1/incidents/{quote(args.incident_id)}/{c}", {})
    if c == "report":
        return call("/api/v1/report.md") if args.markdown else call("/api/v1/report")
    if c == "history":
        return call(f"/api/v1/devices/{quote(args.device)}/history?window={args.window}")
    if c == "rules":
        changes = {k: v for k, v in {"threshold": args.threshold, "severity": args.severity, "enabled": args.enabled}.items() if v is not None}
        if not args.rule_id:
            return call("/api/v1/alert-rules")
        if not changes:
            raise ValueError("Give --threshold, --severity, --enable or --disable")
        return call(f"/api/v1/alert-rules/{quote(args.rule_id)}", changes, "PUT")
    if c == "users":
        if args.action == "list":
            return call("/api/v1/users")
        if not args.username:
            raise ValueError("A username is required")
        target = f"/api/v1/users/{quote(args.username)}"
        if args.action == "add":
            return call("/api/v1/users", {"username": args.username, "role": args.role or "viewer", "password": prompt_password(f"Password for {args.username}")})
        if args.action == "role":
            if not args.role:
                raise ValueError("Give --role admin or --role viewer")
            return call(target, {"role": args.role}, "PATCH")
        if args.action in {"disable", "enable"}:
            return call(target, {"disabled": args.action == "disable"}, "PATCH")
        if args.action == "reset-password":
            return call(target, {"password": prompt_password(f"New password for {args.username}")}, "PATCH")
        return call(target, method="DELETE")
    if c == "passwd":
        return call("/api/v1/me/password", {"current": prompt_password("Current password"), "new": prompt_password("New password")})
    if c == "backup":
        data = call("/api/v1/backup")
        fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return {"saved": args.file, "bytes": len(data)}
    if c == "ebpf":
        return call(f"/api/v1/devices/{quote(args.device)}/ebpf" if args.device else "/api/v1/ebpf")
    if c == "kill-switch":
        return call("/api/v1/ebpf/kill-switch", {"engaged": args.state == "on"})
    if c == "insights":
        return call("/api/v1/insights")
    if c == "forecast":
        return call(f"/api/v1/devices/{quote(args.device)}/forecast")
    if c == "suggest":
        return call(f"/api/v1/devices/{quote(args.device)}/allowlist-suggestions")
    if c == "explain":
        return call(f"/api/v1/incidents/{quote(args.incident_id)}/explain" + ("?llm=0" if args.no_llm else ""))
    if c == "ask":
        reply = request(args.url, token, "/api/v1/copilot", {"messages": [{"role": "user", "content": " ".join(args.question)}]}, timeout=180)
        lines = [reply["reply"]]
        if reply["tools"]:
            lines.append("\n[tools: " + ", ".join(t["name"] for t in reply["tools"]) + "]")
        for plan in reply["plans"]:
            lines.append(f"\nDrafted plan {plan['id']} ({plan['mode']}); review, then: duvoractl apply {plan['id']} --confirm '{plan['confirmation']}'"
                         + (f"\n  blocked: {'; '.join(plan['blockers'])}" if plan["blockers"] else ""))
        return "\n".join(lines)
    if c in {"steering", "steer", "unsteer", "bypass", "verdicts", "flow", "steer-suggest", "budget"}:
        return run_steering(args, call)
    if c in {"ai-traffic", "ai-findings", "assets", "scan", "intel", "playbooks", "siem", "agents"}:
        return run_ai(args, call)
    if c in {"shadow", "enforce"}:
        if c == "shadow":
            policy = {"name": args.name, "tenant": args.tenant, "cidr": args.cidr, "ports": ports_arg(args.ports)}
        else:
            device = next((d for d in call("/api/v1/snapshot")["devices"] if d["id"] == args.device), None)
            current = (device or {}).get("netra_isolation")
            if not current or current.get("stage") != "shadow":
                raise ValueError(f"{args.device} has no shadow allow-list to promote; run `duvoractl shadow` first")
            policy = current["policy"]
        plan = call("/api/v1/plans", {"action": "isolate", "devices": [args.device], "policy": policy, "stage": c})
        if plan["blockers"] or not (args.yes if c == "shadow" else args.confirm):
            return plan
        return call(f"/api/v1/plans/{quote(plan['id'])}/apply", {"confirmation": plan["confirmation"] if c == "shadow" else args.confirm})
    result = call("/api/v1/snapshot")
    return result if c == "status" else result[c]


def query(**params):
    from urllib.parse import urlencode
    params = {k: v for k, v in params.items() if v not in (None, "")}
    return "?" + urlencode(params) if params else ""


def plan_then_apply(call, spec, confirm):
    """Create a plan; apply it only when `confirm` is given (the server checks it matches)."""
    plan = call("/api/v1/plans", spec)
    if plan["blockers"] or not confirm:
        return plan
    return call(f"/api/v1/plans/{quote(plan['id'])}/apply", {"confirmation": confirm})


def run_steering(args, call):
    c = args.command
    if c == "steering":
        if args.ruleset:
            path = f"/api/v1/steering/sets/{quote(args.ruleset)}"
            if args.put:
                with open(args.put) as f:
                    return call(path, json.load(f), "PUT")
            return call(path, method="DELETE") if args.delete else call(path)
        if args.put or args.delete:
            raise ValueError("--put and --delete need --set <rule set id>")
        return call(f"/api/v1/devices/{quote(args.device)}/steering") if args.device else call("/api/v1/steering")
    if c == "steer":
        return plan_then_apply(call, {"action": "steer", "devices": args.devices, "ruleset": args.ruleset, "stage": args.stage}, args.confirm)
    if c == "unsteer":
        return plan_then_apply(call, {"action": "unsteer", "devices": args.devices}, args.confirm)
    if c == "bypass":
        return call(f"/api/v1/devices/{quote(args.device)}/steering/bypass",
                    {"engaged": args.state == "on", "confirmation": args.confirm, "reason": args.reason})
    if c == "verdicts":
        return call("/api/v1/verdicts" + query(device=args.device, action=args.action, rule=args.rule, limit=args.limit))
    if c == "flow":
        flow = {k: v for k, v in {"direction": args.direction, "src": args.src, "dst": args.dst, "protocol": args.protocol,
                                  "sport": args.sport, "dport": args.dport}.items() if v is not None}
        body = {"ruleset" if args.by_set else "device": args.target, "flow": flow}
        return call("/api/v1/steering/explain" + ("?llm=0" if args.no_llm else ""), body)
    if c == "steer-suggest":
        return call(f"/api/v1/devices/{quote(args.device)}/steering-suggestions")
    return call(f"/api/v1/devices/{quote(args.device)}/budget")


def run_ai(args, call):
    c = args.command
    if c == "ai-traffic":
        return call("/api/v1/ai-traffic")
    if c == "ai-findings":
        return call("/api/v1/ai/findings" + query(device=args.device, kind=args.kind, limit=args.limit))
    if c == "assets":
        if args.action == "list":
            return call("/api/v1/ai/assets")
        if args.action == "unsanction":
            if not args.id:
                raise ValueError("unsanction needs --id (see `duvoractl assets`)")
            return call(f"/api/v1/ai/sanctioned/{quote(args.id)}", method="DELETE")
        entry = {k: v for k, v in {"kind": args.kind, "name": args.name, "device": args.device, "note": args.note}.items() if v}
        return call("/api/v1/ai/sanctioned", entry)
    if c == "scan":
        if args.file:
            from .scanner import scan_file
            return scan_file(args.file)
        if args.id:
            return call(f"/api/v1/scans/{quote(args.id)}")
        if args.image:
            return call("/api/v1/scans", {"image": args.image})
        if args.model_url:
            return call("/api/v1/scans", {"url": args.model_url})
        return call("/api/v1/scans")
    if c == "intel":
        if args.action == "list":
            return call("/api/v1/intel")
        if args.action == "refresh":
            return call("/api/v1/intel/refresh", {"feed": args.feed} if args.feed else {})
        if args.action == "ruleset":
            return call("/api/v1/intel/ruleset", {"id": args.id, **({"base": args.base} if args.base else {})})
        if not args.feed:
            raise ValueError("--feed <id> is required")
        if args.action == "remove-feed":
            return call(f"/api/v1/intel/feeds/{quote(args.feed)}", method="DELETE")
        if not args.url:
            raise ValueError("add-feed needs --url")
        return call(f"/api/v1/intel/feeds/{quote(args.feed)}", {"url": args.url, "format": args.format}, "PUT")
    if c == "playbooks":
        if args.action == "list":
            return call("/api/v1/playbooks")
        if args.action == "runs":
            return call("/api/v1/playbook-runs" + query(incident=args.incident))
        if not args.id:
            raise ValueError("--id <playbook> is required")
        path = f"/api/v1/playbooks/{quote(args.id)}"
        if args.action == "run":
            if not args.incident:
                raise ValueError("run needs --incident")
            return call(path + "/run", {"incident": args.incident})
        if args.action == "delete":
            return call(path, method="DELETE")
        if not args.file:
            raise ValueError("put needs --file")
        with open(args.file) as f:
            return call(path, json.load(f), "PUT")
    if c == "siem":
        return call("/api/v1/siem/test", {}) if args.test else call("/api/v1/siem")
    return call("/api/v1/agent-identities")


def main():
    p = build_parser()
    args = p.parse_args()
    args.url = args.url or setting("DUVORA_URL", "http://127.0.0.1:8787")
    try:
        if args.command == "login":
            result = login(args)
        elif args.command == "scan" and args.file:
            result = run_ai(args, None)
        else:
            token = setting("DUVORA_TOKEN")
            if not token:
                p.error("Run `duvoractl login`, or set DUVORA_TOKEN; secrets are deliberately not accepted as command-line arguments")
            result = logout(args, token) if args.command == "logout" else run(args, token)
        print(result if isinstance(result, str) else json.dumps(result, indent=2))
    except urllib.error.HTTPError as exc:
        print(exc.read().decode(errors="replace"), file=sys.stderr); sys.exit(1)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()

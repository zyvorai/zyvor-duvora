"""AI asset discovery: inference runtimes, vector stores and MCP servers listening on nodes, plus LLM
endpoints seen by inspection, checked against an admin-managed sanctioned list.

discover() runs on the agent and only reads /proc. The control plane merges reports into ai_assets."""
import fnmatch
import json
import os
import re
import secrets
import time
from pathlib import Path

from .common import Problem, canonical

SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_assets(key TEXT PRIMARY KEY, device TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_sanctioned(id TEXT PRIMARY KEY, body TEXT NOT NULL);
"""
# (name, kind, command-line pattern, default ports)
RUNTIMES = [
    ("vllm", "runtime", r"\bvllm\b", (8000,)), ("ollama", "runtime", r"\bollama\b", (11434,)),
    ("triton", "runtime", r"\btritonserver\b", (8000, 8001, 8002)), ("tgi", "runtime", r"text-generation-(launcher|router)", (8080,)),
    ("llama.cpp", "runtime", r"\bllama-server\b|\bllama\.cpp\b", (8080,)), ("sglang", "runtime", r"\bsglang\b", (30000,)),
    ("lm-studio", "runtime", r"\blm-?studio\b|\blms\b", (1234,)), ("ray-serve", "runtime", r"\bray\b.*\bserve\b", (8000,)),
    ("tensorrt-llm", "runtime", r"\btrtllm-serve\b|\btensorrt_llm\b", (8000,)), ("nim", "runtime", r"\bnim\b|/opt/nim/", (8000,)),
    ("open-webui", "app", r"\bopen-webui\b|\bopen_webui\b", (8080, 3000)), ("litellm", "gateway", r"\blitellm\b", (4000,)),
    ("qdrant", "vector-db", r"\bqdrant\b", (6333, 6334)), ("milvus", "vector-db", r"\bmilvus\b", (19530,)),
    ("chroma", "vector-db", r"\bchroma\b", (8000,)), ("weaviate", "vector-db", r"\bweaviate\b", (8080,)),
    ("mcp-server", "mcp", r"\bmcp[-_]server\b|@modelcontextprotocol/|\bmcp\b.*\b(serve|server|stdio|sse)\b|fastmcp", ()),
]
# Port-only guesses when the owning process cannot be read.
PORT_GUESSES = {11434: "ollama", 6333: "qdrant", 19530: "milvus", 30000: "sglang", 1234: "lm-studio"}
ASSET_WINDOW = 3600
ASSET_RETENTION = 30 * 86400
MAX_ASSETS = 50


def listening(proc):
    """{inode: port} of TCP sockets in LISTEN state, IPv4 and IPv6."""
    out = {}
    for table in ("tcp", "tcp6"):
        try:
            lines = (proc / "net" / table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":
                continue
            try:
                out[int(parts[9])] = int(parts[1].rsplit(":", 1)[1], 16)
            except ValueError:
                continue
    return out


def socket_owners(proc, inodes):
    """{inode: (pid, cmdline)} for the listening inodes; processes we may not read are skipped."""
    owners = {}
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            fds = list((pid_dir / "fd").iterdir())
        except OSError:
            continue
        cmd = None
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", target)
            if m and int(m.group(1)) in inodes:
                if cmd is None:
                    try:
                        cmd = (pid_dir / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()[:300]
                    except OSError:
                        cmd = ""
                owners[int(m.group(1))] = (int(pid_dir.name), cmd)
    return owners


def identify(cmd, port):
    for label, kind, pattern, ports in RUNTIMES:
        if cmd and re.search(pattern, cmd, re.I):
            return label, kind, "process"
    if port in PORT_GUESSES:
        label = PORT_GUESSES[port]
        return label, next(k for n, k, _, _ in RUNTIMES if n == label), "port"
    return None


def discover(proc=Path("/proc")):
    """AI services listening on this host, from /proc; read-only."""
    ports = listening(proc)
    owners = socket_owners(proc, set(ports)) if ports else {}
    found = {}
    for inode, port in ports.items():
        pid, cmd = owners.get(inode, (None, ""))
        hit = identify(cmd, port)
        if not hit:
            continue
        label, kind, evidence = hit
        key = (label, port)
        if key not in found:
            found[key] = {"name": label, "kind": kind, "port": port, "evidence": evidence, "pid": pid,
                          "process": re.sub(r"(--?(api[-_]?key|token|password|secret)[= ])\S+", r"\1***", cmd, flags=re.I)[:160] if cmd else ""}
    return sorted(found.values(), key=lambda a: (a["name"], a["port"]))[:MAX_ASSETS]


def matches(rule, asset):
    for field in ("kind", "name", "device"):
        want = rule.get(field)
        if want and not fnmatch.fnmatch(str(asset.get(field) or ""), want):
            return False
    return True


SIM_ASSETS = {1: [("vllm", "runtime", 8000), ("mcp-server", "mcp", 8765)], 2: [("triton", "runtime", 8001)],
              3: [("qdrant", "vector-db", 6333)], 4: [("ollama", "runtime", 11434), ("open-webui", "app", 3000)]}


class AiAssetsMixin:
    def init_aiassets(self):
        self.db.executescript(SCHEMA)

    def record_assets(self, d, assets, now, source):
        """Merge one report of local AI services (caller holds the transaction)."""
        for a in (assets or [])[:MAX_ASSETS]:
            if not isinstance(a, dict) or not isinstance(a.get("port"), int) or not 1 <= a["port"] <= 65535:
                continue
            label = a.get("name") if isinstance(a.get("name"), str) and re.fullmatch(r"[a-z0-9.+-]{1,32}", a.get("name", "")) else None
            kind = a.get("kind") if a.get("kind") in ("runtime", "vector-db", "mcp", "app", "gateway") else None
            if not label or not kind:
                continue
            key = f"{d['id']}|{label}|{a['port']}"
            row = self.db.execute("SELECT body FROM ai_assets WHERE key=?", (key,)).fetchone()
            body = json.loads(row[0]) if row else {"device": d["id"], "host": d["host"], "name": label, "kind": kind, "port": a["port"], "first": now}
            body.update(last=now, source=source, evidence=a.get("evidence") if a.get("evidence") in ("process", "port", "simulation") else "port",
                        process=a.get("process")[:160] if isinstance(a.get("process"), str) else "")
            self.db.execute("INSERT INTO ai_assets VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET body=excluded.body", (key, d["id"], canonical(body)))
            if not row:
                self.event("inspection", "ai.asset-discovered", {"device": d["id"], "name": label, "kind": kind, "port": a["port"]})

    def simulate_assets(self, now):
        if not self.demo:
            return
        with self.transaction():
            for d in self.rows("devices"):
                if d["source"] != "simulator":
                    continue
                try:
                    index = int(d["id"].rsplit("-", 1)[1])
                except (IndexError, ValueError):
                    continue
                self.record_assets(d, [{"name": n, "kind": k, "port": p, "evidence": "simulation"} for n, k, p in SIM_ASSETS.get(index, [])], now, "simulation")

    def sanctioned(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM ai_sanctioned ORDER BY id")]

    def add_sanctioned(self, actor, body):
        if not isinstance(body, dict) or set(body) - {"kind", "name", "device", "note"} or not ({"kind", "name", "device"} & set(body)):
            raise Problem("A sanctioned entry matches on kind, name and/or device (glob patterns allowed), with an optional note")
        for field in ("kind", "name", "device"):
            v = body.get(field)
            if v is not None and (not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9.*?_:+-]{1,253}", v)):
                raise Problem(f"{field} must be a short name or glob pattern")
        note = body.get("note", "")
        if not isinstance(note, str) or len(note) > 200:
            raise Problem("note must be at most 200 characters")
        entry = {"id": secrets.token_hex(6), **{k: body[k] for k in ("kind", "name", "device") if body.get(k)}, "note": note,
                 "created": time.time(), "by": actor}
        with self.transaction():
            self.db.execute("INSERT INTO ai_sanctioned VALUES(?,?)", (entry["id"], canonical(entry)))
            self.event(actor, "ai.sanctioned-added", {k: entry.get(k) for k in ("id", "kind", "name", "device")})
        return entry

    def delete_sanctioned(self, actor, ident):
        with self.transaction():
            if not self.db.execute("DELETE FROM ai_sanctioned WHERE id=?", (ident,)).rowcount:
                raise Problem("Sanctioned entry not found", 404)
            self.event(actor, "ai.sanctioned-removed", {"id": ident})
        return {"deleted": ident}

    def ai_assets(self):
        """Local AI services plus LLM endpoints, each marked sanctioned or not."""
        rules = self.sanctioned()
        with self.lock:
            local = [json.loads(r[0]) for r in self.db.execute("SELECT body FROM ai_assets ORDER BY key")]
        assets = [{**a, "origin": "listening"} for a in local]
        for e in self.llm_endpoints():
            assets.append({"device": e["device"], "name": e["endpoint"], "kind": "mcp" if e["kind"] == "mcp" else "llm-api",
                           "port": e["port"], "provider": e["provider"], "first": e["first"], "last": e["last"], "origin": "inspection"})
        for a in assets:
            hit = next((r for r in rules if matches(r, a)), None)
            a["sanctioned"] = bool(hit)
            a["sanctioned_by"] = hit["id"] if hit else None
        return {"assets": assets, "sanctioned": rules, "policy_active": bool(rules),
                "unsanctioned": sum(not a["sanctioned"] for a in assets) if rules else 0}

    def prune_assets(self, now):
        return self.db.execute("DELETE FROM ai_assets WHERE json_extract(body,'$.last')<?", (now - ASSET_RETENTION,)).rowcount

    def aiassets_conditions(self):
        def unsanctioned(rule, now, firing):
            view = self.ai_assets()
            if not view["policy_active"]:
                return
            by = {}
            for a in view["assets"]:
                if not a["sanctioned"] and now - (a.get("last") or 0) <= ASSET_WINDOW:
                    by.setdefault(a["device"], []).append(a)
            for dev, items in by.items():
                shown = ", ".join(f"{a['name']}:{a['port']}" for a in items[:4])
                firing[f"{rule['id']}:{dev}"] = (rule, dev, f"Unsanctioned AI on {dev}", f"{len(items)} not on the sanctioned list: {shown}")
        return {"unsanctioned-ai": unsanctioned}

"""Agent identity: short-lived, rotating agent tokens and optional mutual TLS binding a client
certificate to the agent's host. Bootstrap host keys (DUVORA_AGENT_KEYS) can be restricted to minting
tokens with DUVORA_AGENT_BOOTSTRAP_ONLY=1, so a leaked long-lived key cannot report or read policy."""
import hashlib
import json
import os
import secrets
import time

from .common import Problem, canonical

SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_tokens(id TEXT PRIMARY KEY, host TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  created REAL NOT NULL, expires REAL NOT NULL, last_used REAL);
CREATE INDEX IF NOT EXISTS agent_tokens_host ON agent_tokens(host);
CREATE TABLE IF NOT EXISTS agent_identity(host TEXT PRIMARY KEY, body TEXT NOT NULL);
"""
AGENT_TOKEN_PREFIX = "dva_"
MAX_TOKENS_PER_HOST = 3
REJECTION_WINDOW = 900
TOUCH_INTERVAL = 60


def token_ttl():
    try:
        return min(30 * 86400, max(600, int(os.environ.get("DUVORA_AGENT_TOKEN_TTL", "86400"))))
    except ValueError:
        return 86400


def _digest(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


class IdentityMixin:
    def init_identity(self):
        self.db.executescript(SCHEMA)
        self.mtls_mode = os.environ.get("DUVORA_AGENT_MTLS", "off")
        if self.mtls_mode not in {"off", "optional", "require"}:
            raise ValueError("DUVORA_AGENT_MTLS must be off, optional or require")
        self.bootstrap_only = os.environ.get("DUVORA_AGENT_BOOTSTRAP_ONLY") == "1"
        self.identity_touched = {}

    def mint_agent_token(self, actor, via):
        """POST /agent/token: a fresh short-lived token for the calling agent's host; older ones beyond three are revoked."""
        host = actor.split(":", 1)[1] if actor.startswith("agent:") else ""
        if not host:
            raise Problem("Only agents mint agent tokens", 403)
        raw = AGENT_TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = time.time()
        ttl = token_ttl()
        with self.transaction():
            self.db.execute("INSERT INTO agent_tokens VALUES(?,?,?,?,?,NULL)", (secrets.token_hex(8), host, _digest(raw), now, now + ttl))
            keep = [r[0] for r in self.db.execute("SELECT id FROM agent_tokens WHERE host=? ORDER BY created DESC LIMIT ?", (host, MAX_TOKENS_PER_HOST))]
            self.db.execute(f"DELETE FROM agent_tokens WHERE host=? AND id NOT IN ({','.join('?' * len(keep))})", (host, *keep))
            self.db.execute("DELETE FROM agent_tokens WHERE expires<?", (now,))
            ident = self._identity(host)
            ident.update(last_rotation=now, rotations=ident.get("rotations", 0) + 1, minted_via=via)
            self._save_identity(host, ident)
            self.event(actor, "agent.token-minted", {"host": host, "via": via, "expires": now + ttl})
        return {"token": raw, "host": host, "expires": now + ttl, "ttl": ttl, "rotate_after": now + ttl / 2}

    def agent_token_user(self, raw):
        """Resolve a short-lived agent token to its host, or None."""
        if not raw.startswith(AGENT_TOKEN_PREFIX):
            return None
        now = time.time()
        with self.lock:
            row = self.db.execute("SELECT id, host, last_used FROM agent_tokens WHERE token_hash=? AND expires>?", (_digest(raw), now)).fetchone()
            if not row:
                return None
            if not row["last_used"] or now - row["last_used"] > TOUCH_INTERVAL:
                self.db.execute("UPDATE agent_tokens SET last_used=? WHERE id=?", (now, row["id"]))
        return row["host"]

    def _identity(self, host):
        row = self.db.execute("SELECT body FROM agent_identity WHERE host=?", (host,)).fetchone()
        return json.loads(row[0]) if row else {"host": host, "first_seen": time.time(), "rejections": []}

    def _save_identity(self, host, body):
        self.db.execute("INSERT INTO agent_identity VALUES(?,?) ON CONFLICT(host) DO UPDATE SET body=excluded.body", (host, canonical(body)))

    def check_agent_identity(self, actor, via, cert_names, path):
        """Enforce mTLS host binding and bootstrap-only keys for an authenticated agent request; record what was seen."""
        host = actor.split(":", 1)[1]
        now = time.time()
        problem = None
        if self.mtls_mode != "off":
            if not cert_names and self.mtls_mode == "require":
                problem = "This server requires a client certificate for agents (DUVORA_AGENT_MTLS=require)"
            elif cert_names and host not in cert_names:
                problem = f"Client certificate names {', '.join(sorted(cert_names))[:100]} do not include host {host}"
        if not problem and self.bootstrap_only and via == "key" and path != "/api/v1/agent/token":
            problem = "Bootstrap agent keys may only mint a short-lived token (DUVORA_AGENT_BOOTSTRAP_ONLY=1)"
        last = self.identity_touched.get(host, 0)
        if problem or now - last >= TOUCH_INTERVAL:
            self.identity_touched[host] = now
            with self.transaction():
                ident = self._identity(host)
                ident.update(last_seen=now, last_via=via, cert_names=sorted(cert_names)[:5] if cert_names else [],
                             mtls_verified=bool(cert_names) and host in cert_names)
                if problem:
                    ident["rejections"] = [r for r in ident.get("rejections", []) if now - r["time"] < 86400][-19:] + [{"time": now, "reason": problem[:200]}]
                    self.event(actor, "agent.rejected", {"host": host, "reason": problem[:200]})
                self._save_identity(host, ident)
        if problem:
            raise Problem(problem, 403)

    def note_unknown_agent(self, client):
        """A bearer that looked like an agent token was refused: count it per client address."""
        now = time.time()
        with self.transaction():
            ident = self._identity(f"unknown@{client}"[:63])
            ident.update(last_seen=now, unknown=True)
            ident["rejections"] = [r for r in ident.get("rejections", []) if now - r["time"] < 86400][-19:] + [{"time": now, "reason": "unknown or expired agent token"}]
            self._save_identity(f"unknown@{client}"[:63], ident)

    def agent_identities(self):
        now = time.time()
        with self.lock:
            idents = {r["host"]: json.loads(r["body"]) for r in self.db.execute("SELECT host, body FROM agent_identity")}
            tokens = {}
            for r in self.db.execute("SELECT host, created, expires, last_used FROM agent_tokens WHERE expires>?", (now,)):
                tokens.setdefault(r["host"], []).append(dict(r))
            devices = {d["host"] for d in self.rows("devices") if d["source"] != "simulator"}
        static = getattr(self, "agent_key_hosts", set())
        out = []
        for host in sorted(set(idents) | set(tokens) | static):
            ident = idents.get(host, {"host": host})
            toks = sorted(tokens.get(host, []), key=lambda t: -t["created"])
            out.append({"host": host, "static_key": host in static, "tokens": len(toks),
                        "token_expires": toks[0]["expires"] if toks else None, "last_rotation": ident.get("last_rotation"),
                        "last_seen": ident.get("last_seen"), "last_via": ident.get("last_via"), "mtls_verified": ident.get("mtls_verified", False),
                        "cert_names": ident.get("cert_names", []), "known_device": host in devices, "unknown": bool(ident.get("unknown")),
                        "rejections": [r for r in ident.get("rejections", []) if now - r["time"] < 86400][-5:]})
        return {"identities": out, "mtls": self.mtls_mode, "bootstrap_only": self.bootstrap_only, "token_ttl": token_ttl()}

    def prune_identity(self, now):
        return self.db.execute("DELETE FROM agent_tokens WHERE expires<?", (now,)).rowcount

    def identity_conditions(self):
        def stale(rule, now, firing):
            for i in self.agent_identities()["identities"]:
                if i["unknown"] or not i["tokens"] and not i["last_rotation"]:
                    continue
                left = (i["token_expires"] or 0) - now
                if left < rule["threshold"] * 3600:
                    firing[f"{rule['id']}:{i['host']}"] = (rule, i["host"], f"Agent identity for {i['host']} is about to lapse",
                                                           "No valid agent token" if left <= 0 else f"Newest agent token expires in {round(left / 3600, 1)} h; the agent has not rotated it")

        def unknown(rule, now, firing):
            for i in self.agent_identities()["identities"]:
                recent = [r for r in i["rejections"] if now - r["time"] <= REJECTION_WINDOW]
                if recent:
                    firing[f"{rule['id']}:{i['host']}"] = (rule, i["host"], f"Agent identity rejected: {i['host']}",
                                                           f"{len(recent)} refused in 15 min; latest: {recent[-1]['reason']}")
        return {"agent-identity-stale": stale, "agent-identity-unknown": unknown}

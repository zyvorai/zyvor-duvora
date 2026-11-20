# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

"""Named users, revocable browser sessions, and personal API tokens."""
import hashlib
import hmac
import os
import secrets
import threading
import time

from .common import Problem, name

DEFAULT_ADMIN_PASSWORD = "Admin@321"
SESSION_TTL = 12 * 3600
ROLES = ("admin", "viewer")
TOKEN_PREFIX = "dvr_"
LOGIN_WINDOW = 300
LOGIN_FAILURES = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, role TEXT NOT NULL, pw_hash TEXT NOT NULL,
  created REAL NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, default_password INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(id_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS api_tokens(id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created REAL NOT NULL, last_used REAL);
"""


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(digest) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got.hex(), digest)


def digest(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def check_password(password):
    if not isinstance(password, str) or not 8 <= len(password) <= 256:
        raise Problem("Password must contain 8–256 characters")
    return password


def check_role(role):
    if role not in ROLES:
        raise Problem("Role must be admin or viewer")
    return role


class LoginLimiter:
    """Per-client failure window; a burst of wrong passwords is refused with 429."""

    def __init__(self):
        self.lock = threading.Lock()
        self.failures = {}

    def check(self, client):
        now = time.time()
        with self.lock:
            recent = [t for t in self.failures.get(client, []) if now - t < LOGIN_WINDOW]
            self.failures[client] = recent
            if len(recent) >= LOGIN_FAILURES:
                raise Problem("Too many failed sign-in attempts; wait a few minutes", 429)

    def fail(self, client):
        with self.lock:
            self.failures.setdefault(client, []).append(time.time())
            if len(self.failures) > 10000:
                self.failures.clear()

    def succeed(self, client):
        with self.lock:
            self.failures.pop(client, None)


class AuthMixin:
    def init_auth(self):
        self.db.executescript(SCHEMA)
        self.limiter = LoginLimiter()
        with self.transaction():
            if self.db.execute("SELECT count(*) FROM users").fetchone()[0]:
                return
            password = os.environ.get("DUVORA_ADMIN_PASSWORD") or DEFAULT_ADMIN_PASSWORD
            check_password(password)
            self.db.execute("INSERT INTO users VALUES(?,?,?,?,0,?)",
                            ("admin", "admin", hash_password(password), time.time(), int(password == DEFAULT_ADMIN_PASSWORD)))
            self.event("system", "user.bootstrap", {"username": "admin", "default_password": password == DEFAULT_ADMIN_PASSWORD})

    @staticmethod
    def public_user(row):
        return {"username": row["username"], "role": row["role"], "created": row["created"],
                "disabled": bool(row["disabled"]), "default_password": bool(row["default_password"])}

    def user(self, username):
        row = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            raise Problem("User not found", 404)
        return row

    def users(self):
        with self.lock:
            return [self.public_user(r) for r in self.db.execute("SELECT * FROM users ORDER BY username")]

    def login(self, username, password, client="local"):
        self.limiter.check(client)
        if not isinstance(username, str) or not isinstance(password, str):
            raise Problem("Username and password are required")
        username = username.strip()
        with self.lock:
            row = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        # Verify against a dummy hash when the user is missing so timing does not reveal accounts.
        ok = verify_password(password, row["pw_hash"] if row else DUMMY_HASH) and row is not None and not row["disabled"]
        if not ok:
            self.limiter.fail(client)
            with self.transaction():
                self.event(username[:64] or "unknown", "session.failed", {"client": client})
            raise Problem("Wrong username or password.", 401)
        self.limiter.succeed(client)
        with self.transaction():
            raw = secrets.token_urlsafe(32)
            now = time.time()
            self.db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (digest(raw), row["username"], now, now + SESSION_TTL))
            self.event(row["username"], "session.created", {"client": client})
            return raw, self.public_user(row)

    def logout(self, raw):
        with self.transaction():
            self.db.execute("DELETE FROM sessions WHERE id_hash=?", (digest(raw),))

    def session_user(self, raw):
        if not raw:
            return None
        with self.lock:
            row = self.db.execute("SELECT u.* FROM sessions s JOIN users u ON u.username=s.username WHERE s.id_hash=? AND s.expires>? AND u.disabled=0",
                                  (digest(raw), time.time())).fetchone()
            return self.public_user(row) if row else None

    def token_user(self, raw):
        if not raw.startswith(TOKEN_PREFIX):
            return None
        with self.transaction():
            row = self.db.execute("SELECT u.*, t.id AS token_id FROM api_tokens t JOIN users u ON u.username=t.username WHERE t.token_hash=? AND u.disabled=0",
                                  (digest(raw),)).fetchone()
            if not row:
                return None
            self.db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), row["token_id"]))
            return self.public_user(row)

    def admins(self):
        return self.db.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0]

    def create_user(self, actor, body):
        if not isinstance(body, dict) or set(body) - {"username", "role", "password"}:
            raise Problem("User requires username, role and password")
        username = name(body.get("username"), "username")
        role = check_role(body.get("role"))
        password = check_password(body.get("password"))
        with self.transaction():
            if self.db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise Problem("User already exists", 409)
            self.db.execute("INSERT INTO users VALUES(?,?,?,?,0,?)",
                            (username, role, hash_password(password), time.time(), int(password == DEFAULT_ADMIN_PASSWORD)))
            self.event(actor, "user.created", {"username": username, "role": role})
            return self.public_user(self.user(username))

    def update_user(self, actor, username, body):
        if not isinstance(body, dict) or not body or set(body) - {"role", "password", "disabled"}:
            raise Problem("Update may change role, password or disabled")
        with self.transaction():
            row = self.user(username)
            role = check_role(body.get("role", row["role"]))
            disabled = body.get("disabled", bool(row["disabled"]))
            if not isinstance(disabled, bool):
                raise Problem("disabled must be true or false")
            losing_admin = row["role"] == "admin" and not row["disabled"] and (role != "admin" or disabled)
            if losing_admin and self.admins() <= 1:
                raise Problem("At least one active administrator is required", 409)
            pw_hash, default = row["pw_hash"], row["default_password"]
            if "password" in body:
                password = check_password(body["password"])
                pw_hash, default = hash_password(password), int(password == DEFAULT_ADMIN_PASSWORD)
            self.db.execute("UPDATE users SET role=?, disabled=?, pw_hash=?, default_password=? WHERE username=?",
                            (role, int(disabled), pw_hash, default, username))
            if disabled or "password" in body or role != row["role"]:
                self.db.execute("DELETE FROM sessions WHERE username=?", (username,))
            if disabled:
                self.db.execute("DELETE FROM api_tokens WHERE username=?", (username,))
            self.event(actor, "user.updated", {"username": username, "fields": sorted(body)})
            return self.public_user(self.user(username))

    def delete_user(self, actor, username):
        with self.transaction():
            row = self.user(username)
            if row["role"] == "admin" and not row["disabled"] and self.admins() <= 1:
                raise Problem("At least one active administrator is required", 409)
            self.db.execute("DELETE FROM users WHERE username=?", (username,))
            self.event(actor, "user.deleted", {"username": username})
            return {"deleted": username}

    def change_password(self, username, body):
        if not isinstance(body, dict) or set(body) != {"current", "new"}:
            raise Problem("Provide current and new passwords")
        new = check_password(body["new"])
        with self.transaction():
            row = self.user(username)
            if not isinstance(body["current"], str) or not verify_password(body["current"], row["pw_hash"]):
                raise Problem("Current password is incorrect", 403)
            if new == body["current"]:
                raise Problem("Choose a different password")
            self.db.execute("UPDATE users SET pw_hash=?, default_password=? WHERE username=?",
                            (hash_password(new), int(new == DEFAULT_ADMIN_PASSWORD), username))
            self.event(username, "user.password-changed", {"username": username})
            return self.public_user(self.user(username))

    def create_token(self, username, body):
        label = (body or {}).get("name", "api")
        if not isinstance(label, str) or not 1 <= len(label) <= 64:
            raise Problem("Token name must contain 1–64 characters")
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        ident = secrets.token_hex(8)
        with self.transaction():
            self.user(username)
            if self.db.execute("SELECT count(*) FROM api_tokens WHERE username=?", (username,)).fetchone()[0] >= 20:
                raise Problem("A user may hold at most 20 API tokens", 409)
            self.db.execute("INSERT INTO api_tokens VALUES(?,?,?,?,?,NULL)", (ident, username, label, digest(raw), time.time()))
            self.event(username, "token.created", {"id": ident, "name": label})
        return {"id": ident, "name": label, "token": raw}

    def tokens(self, username):
        with self.lock:
            return [{"id": r["id"], "name": r["name"], "created": r["created"], "last_used": r["last_used"]}
                    for r in self.db.execute("SELECT * FROM api_tokens WHERE username=? ORDER BY created", (username,))]

    def revoke_token(self, username, ident):
        with self.transaction():
            if not self.db.execute("DELETE FROM api_tokens WHERE id=? AND username=?", (ident, username)).rowcount:
                raise Problem("Token not found", 404)
            self.event(username, "token.revoked", {"id": ident})
            return {"revoked": ident}


DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

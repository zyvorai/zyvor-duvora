"""Threat-intelligence feeds: IP/CIDR and domain indicators from a URL or pasted inline, matched against
observed flows and inspected server names, and turned into a drop steering rule set on request.

Feeds are fetched in a background thread; nothing is blocked automatically."""
import csv
import io
import ipaddress
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .common import Problem, canonical, name
from .netra import LOOPBACK, NoRedirect

SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_feeds(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS intel_indicators(feed TEXT PRIMARY KEY, body TEXT NOT NULL);
"""
FORMATS = ("plain", "csv", "stix")
MAX_INDICATORS = 100000
MAX_FEED_BYTES = 16 * 1024 * 1024
MATCH_CACHE = 30
INTEL_RULES = 900
DOMAIN = re.compile(r"(?=.{1,253}$)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
STIX_IP = re.compile(r"\[(?:ipv4-addr|ipv6-addr):value\s*=\s*'([^']+)'\]")
STIX_DOMAIN = re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]")


def parse_indicators(text, fmt="plain"):
    """(networks, domains) from feed text. Plain: one indicator per line, # comments. CSV: first column
    that parses. STIX: a bundle's indicator patterns."""
    values = []
    if fmt == "stix":
        try:
            bundle = json.loads(text)
        except ValueError:
            raise Problem("STIX feed is not valid JSON") from None
        for obj in (bundle.get("objects") or []) if isinstance(bundle, dict) else []:
            if isinstance(obj, dict) and obj.get("type") == "indicator" and isinstance(obj.get("pattern"), str):
                values += STIX_IP.findall(obj["pattern"]) + STIX_DOMAIN.findall(obj["pattern"])
    elif fmt == "csv":
        for row in csv.reader(io.StringIO(text)):
            values += [c.strip() for c in row if c.strip() and not c.strip().startswith("#")][:3]
    else:
        for line in text.splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if line:
                values.append(line.split()[0])
    nets, domains = set(), set()
    for v in values:
        v = v.strip().lower()
        try:
            nets.add(str(ipaddress.ip_network(v, strict=False)))
        except ValueError:
            if DOMAIN.fullmatch(v):
                domains.add(v)
        if len(nets) + len(domains) >= MAX_INDICATORS:
            break
    return sorted(nets), sorted(domains)


class Matcher:
    """Longest-prefix-free membership test over many networks, grouped by prefix length."""

    def __init__(self, entries):
        self.by_len = {}
        for net, feed in entries:
            n = ipaddress.ip_network(net)
            self.by_len.setdefault((n.version, n.prefixlen), {})[int(n.network_address)] = (net, feed)

    def find(self, address):
        ip = ipaddress.ip_address(address)
        width = ip.max_prefixlen
        for (version, plen), table in self.by_len.items():
            if version != ip.version:
                continue
            key = (int(ip) >> (width - plen)) << (width - plen) if plen else 0
            hit = table.get(key)
            if hit:
                return hit
        return None


def domain_hit(host, domains):
    host = (host or "").lower().rstrip(".")
    for d, feed in domains:
        if host == d.lstrip("*.") or (d.startswith("*.") and host.endswith(d[1:])) or host.endswith("." + d):
            return d, feed
    return None


class IntelMixin:
    def init_intel(self):
        self.db.executescript(SCHEMA)
        self.intel_cache = (0.0, [])
        self.intel_matcher = None
        self.intel_refreshing = threading.Lock()
        self.last_intel_check = 0.0
        if self.demo:
            with self.transaction():
                if not self.db.execute("SELECT 1 FROM intel_feeds").fetchone():
                    self._store_feed("system", "demo-blocklist", {"description": "Demo indicators (documentation and known-bad ranges)",
                                                                  "format": "plain", "refresh_minutes": 0},
                                     "185.220.101.0/24  # Tor exit relays (example)\n203.0.113.9\nevil-llm-proxy.example\n")

    def _store_feed(self, actor, ident, feed, text=None):
        if text is not None:
            nets, domains = parse_indicators(text, feed["format"])
            feed.update(count=len(nets) + len(domains), networks=len(nets), domains=len(domains), last_fetch=time.time(), error=None)
            self.db.execute("INSERT INTO intel_indicators VALUES(?,?) ON CONFLICT(feed) DO UPDATE SET body=excluded.body",
                            (ident, canonical({"networks": nets, "domains": domains})))
        self.db.execute("INSERT INTO intel_feeds VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", (ident, canonical({"id": ident, **feed})))
        self.intel_matcher = None
        self.intel_cache = (0.0, [])

    def intel_feeds(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM intel_feeds ORDER BY id")]

    def put_feed(self, actor, ident, body):
        name(ident, "feed id")
        if not isinstance(body, dict) or set(body) - {"description", "url", "indicators", "format", "refresh_minutes", "enabled"}:
            raise Problem("A feed has description, url or indicators, format, refresh_minutes and enabled")
        fmt = body.get("format", "plain")
        if fmt not in FORMATS:
            raise Problem("format must be plain, csv or stix")
        url, inline = body.get("url"), body.get("indicators")
        if bool(url) == (inline is not None):
            raise Problem("Give either url or indicators")
        if url:
            parts = urlsplit(url) if isinstance(url, str) else None
            if not parts or parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
                raise Problem("Feed url must be an http(s) URL without credentials")
            if parts.scheme != "https" and parts.hostname not in LOOPBACK and os.environ.get("DUVORA_INTEL_ALLOW_HTTP") != "1":
                raise Problem("Feed url must use HTTPS")
        if inline is not None and (not isinstance(inline, str) or len(inline) > 60000):
            raise Problem("indicators must be text of at most 60,000 characters")
        refresh = body.get("refresh_minutes", 60 if url else 0)
        if type(refresh) is not int or not 0 <= refresh <= 10080:
            raise Problem("refresh_minutes must be 0–10080")
        enabled = body.get("enabled", True)
        if not isinstance(enabled, bool):
            raise Problem("enabled must be true or false")
        description = body.get("description", "")
        if not isinstance(description, str) or len(description) > 200:
            raise Problem("description must be at most 200 characters")
        feed = {"description": description, "format": fmt, "url": url, "refresh_minutes": refresh, "enabled": enabled,
                "updated": time.time(), "updated_by": actor, "count": 0, "last_fetch": None, "error": None}
        with self.transaction():
            row = self.db.execute("SELECT body FROM intel_feeds WHERE id=?", (ident,)).fetchone()
            if row and url:
                old = json.loads(row[0])
                feed.update({k: old.get(k) for k in ("count", "networks", "domains", "last_fetch", "error")} if old.get("url") == url else {})
            self._store_feed(actor, ident, feed, inline)
            self.event(actor, "intel.feed-updated" if row else "intel.feed-created", {"id": ident, "source": "url" if url else "inline", "count": feed["count"]})
        if url:
            threading.Thread(target=self.refresh_feeds, kwargs={"only": ident}, daemon=True).start()
        return {"id": ident, **feed}

    def delete_feed(self, actor, ident):
        with self.transaction():
            if not self.db.execute("DELETE FROM intel_feeds WHERE id=?", (ident,)).rowcount:
                raise Problem("Feed not found", 404)
            self.db.execute("DELETE FROM intel_indicators WHERE feed=?", (ident,))
            self.intel_matcher, self.intel_cache = None, (0.0, [])
            self.event(actor, "intel.feed-deleted", {"id": ident})
        return {"deleted": ident}

    def fetch_feed(self, url):
        handlers = [NoRedirect()]
        if url.startswith("https:"):
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ.get("DUVORA_INTEL_CA_FILE") or None)))
        req = urllib.request.Request(url, headers={"Accept": "text/plain, text/csv, application/json"})
        with urllib.request.build_opener(*handlers).open(req, timeout=30) as response:
            data = response.read(MAX_FEED_BYTES + 1)
        if len(data) > MAX_FEED_BYTES:
            raise ValueError("feed larger than 16 MB")
        return data.decode("utf-8", "replace")

    def refresh_feeds(self, now=None, only=None):
        """Fetch URL feeds that are due (or `only` one, now). Network calls happen outside the store lock."""
        if not self.intel_refreshing.acquire(blocking=False):
            return
        try:
            now = now or time.time()
            due = [f for f in self.intel_feeds() if f.get("url") and f.get("enabled") and (
                f["id"] == only if only else f.get("refresh_minutes") and now - (f.get("last_fetch") or 0) >= f["refresh_minutes"] * 60)]
            for f in due:
                try:
                    text, error = self.fetch_feed(f["url"]), None
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    text, error = None, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"[:200]
                with self.transaction():
                    row = self.db.execute("SELECT body FROM intel_feeds WHERE id=?", (f["id"],)).fetchone()
                    if not row:
                        continue
                    feed = {k: v for k, v in json.loads(row[0]).items() if k != "id"}
                    if error:
                        feed.update(error=error, last_fetch=now)
                        self._store_feed("intel", f["id"], feed)
                    else:
                        self._store_feed("intel", f["id"], feed, text)
                    self.event("intel", "intel.feed-refreshed", {"id": f["id"], "count": feed.get("count"), "error": error})
        finally:
            self.intel_refreshing.release()

    def maybe_refresh_intel(self, now):
        if now - self.last_intel_check >= 60:
            self.last_intel_check = now
            if any(f.get("url") and f.get("enabled") and f.get("refresh_minutes") and now - (f.get("last_fetch") or 0) >= f["refresh_minutes"] * 60
                   for f in self.intel_feeds()):
                threading.Thread(target=self.refresh_feeds, daemon=True).start()

    def _indicators(self):
        enabled = {f["id"] for f in self.intel_feeds() if f.get("enabled", True)}
        nets, domains = [], []
        with self.lock:
            for r in self.db.execute("SELECT feed, body FROM intel_indicators"):
                if r["feed"] in enabled:
                    body = json.loads(r["body"])
                    nets += [(n, r["feed"]) for n in body["networks"]]
                    domains += [(d, r["feed"]) for d in body["domains"]]
        return nets, domains

    def intel_matches(self, now=None):
        now = now or time.time()
        if now - self.intel_cache[0] < MATCH_CACHE:
            return self.intel_cache[1]
        nets, domains = self._indicators()
        if self.intel_matcher is None:
            self.intel_matcher = Matcher(nets)
        out = {}
        if nets:
            with self.lock:
                devices = self.rows("devices")
            for d in devices:
                for r in self.steer_flows(d, now):
                    peer = r.get("peer")
                    try:
                        hit = self.intel_matcher.find(peer)
                    except ValueError:
                        continue
                    if hit:
                        key = (d["id"], peer, r.get("port"))
                        m = out.setdefault(key, {"device": d["id"], "peer": peer, "port": r.get("port"), "protocol": r.get("protocol"),
                                                 "direction": r.get("direction") or "egress", "indicator": hit[0], "feed": hit[1],
                                                 "bytes": 0, "packets": 0, "via": "flow"})
                        m["bytes"] += r.get("bytes") or 0
                        m["packets"] += r.get("packets") or 0
        if domains:
            for e in self.llm_endpoints():
                hit = domain_hit(e["endpoint"], domains)
                if hit:
                    out[(e["device"], e["endpoint"], e["port"])] = {"device": e["device"], "peer": e.get("peer"), "host": e["endpoint"],
                                                                     "port": e["port"], "indicator": hit[0], "feed": hit[1], "via": "inspection",
                                                                     "bytes": 0, "packets": e.get("requests", 0)}
        result = sorted(out.values(), key=lambda m: (-m["bytes"], m["device"]))
        self.intel_cache = (now, result)
        return result

    def intel_overview(self):
        return {"feeds": self.intel_feeds(), "matches": self.intel_matches()[:200]}

    def intel_ruleset(self, actor, body):
        """Create or replace a steering rule set that drops every IP/CIDR indicator (collapsed), optionally
        followed by an existing rule set's rules."""
        from .steering import MAX_RULES
        body = body or {}
        if set(body) - {"id", "base"}:
            raise Problem("Give id and optionally base (a rule set whose rules follow the intel drops)")
        ident = name(body.get("id", "threat-intel"), "rule set id")
        base = self.steering_set(name(body["base"], "base rule set")) if body.get("base") else None
        nets, _ = self._indicators()
        collapsed = []
        for version in (4, 6):
            group = [ipaddress.ip_network(n) for n, _ in nets if ipaddress.ip_network(n).version == version]
            collapsed += list(ipaddress.collapse_addresses(group))
        if not collapsed:
            raise Problem("No IP or CIDR indicators in enabled feeds", 409)
        per_direction = min(INTEL_RULES, MAX_RULES - (len(base["rules"]) if base else 0)) // 2
        if per_direction < 1:
            raise Problem("The base rule set leaves no room for intel rules", 409)
        collapsed = sorted(collapsed, key=lambda n: n.prefixlen)[:per_direction]
        rules = [{"priority": i + 1, "name": f"intel-out-{i + 1}", "action": "drop", "direction": "egress", "dst": str(n),
                  "note": "threat-intel indicator"} for i, n in enumerate(collapsed)]
        rules += [{"priority": len(collapsed) + i + 1, "name": f"intel-in-{i + 1}", "action": "drop", "direction": "ingress", "src": str(n),
                   "note": "threat-intel indicator"} for i, n in enumerate(collapsed)]
        for r in (base or {}).get("rules", []):
            rules.append({**r, "priority": len(rules) + 1})
        return self.put_steering_set(actor, ident, {"description": "Drop threat-intel indicators" + (f", then {base['id']}" if base else ""),
                                                    "default": base["default"] if base else "bypass", "rules": rules[:MAX_RULES]})

    def intel_conditions(self):
        def match(rule, now, firing):
            by = {}
            for m in self.intel_matches(now):
                by.setdefault(m["device"], []).append(m)
            for dev, items in by.items():
                shown = ", ".join(f"{m.get('host') or m['peer']}:{m['port']} ({m['feed']})" for m in items[:3])
                firing[f"{rule['id']}:{dev}"] = (rule, dev, f"Threat-intel match on {dev}", f"{len(items)} indicator hit(s): {shown}")
        return {"intel-match": match}

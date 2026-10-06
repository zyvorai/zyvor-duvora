"""Export audit events, incidents, steering verdicts, AI findings and threat-intel matches to a SIEM:
a JSON webhook (DUVORA_SIEM_URL) and/or syslog RFC 5424 (DUVORA_SIEM_SYSLOG=udp|tcp|tls://host:port).

Events wait in a bounded in-memory queue (oldest dropped first, counted) and are sent in batches from the
background loop, never under the store lock."""
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .common import Problem
from .netra import LOOPBACK, NoRedirect

QUEUE = 10000
BATCH = 500
FLUSH_INTERVAL = 5
CATEGORIES = ("audit", "verdict", "ai-finding", "intel", "playbook")
SEVERITY = {"critical": 2, "warning": 4, "info": 6}


def syslog_line(event, host="duvora"):
    sev = SEVERITY.get(event.get("severity") or ("warning" if event.get("action") == "drop" else "info"), 6)
    pri = 8 * 13 + sev  # facility 13: log audit
    ts = datetime.fromtimestamp(event.get("time") or time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    msgid = str(event.get("category") or "event")[:32].replace(" ", "-")
    return f"<{pri}>1 {ts} {host} duvora - {msgid} - {json.dumps(event, separators=(',', ':'), sort_keys=True, default=str)}"


class SiemExporter:
    def __init__(self, url="", key="", ca_file=None, syslog="", verdicts="drop", categories=CATEGORIES, allow_http=False, timeout=10):
        self.url, self.key, self.syslog, self.verdicts = url.rstrip("/"), key, syslog, verdicts
        self.categories = set(categories)
        self.timeout = timeout
        if url:
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
                raise ValueError("DUVORA_SIEM_URL must be an http(s) URL without credentials")
            if parts.scheme != "https" and parts.hostname not in LOOPBACK and not allow_http:
                raise ValueError("DUVORA_SIEM_URL must use HTTPS unless it is loopback (or set DUVORA_SIEM_ALLOW_HTTP=1)")
            handlers = [NoRedirect()]
            if parts.scheme == "https":
                handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file or None)))
            self.opener = urllib.request.build_opener(*handlers)
        if syslog:
            parts = urlsplit(syslog)
            if parts.scheme not in {"udp", "tcp", "tls"} or not parts.hostname or not parts.port:
                raise ValueError("DUVORA_SIEM_SYSLOG must look like udp://host:514, tcp://host:601 or tls://host:6514")
            self.syslog_target = (parts.scheme, parts.hostname, parts.port)
            self.ssl_context = ssl.create_default_context(cafile=ca_file or None) if parts.scheme == "tls" else None
        if verdicts not in {"all", "drop", "none"}:
            raise ValueError("DUVORA_SIEM_VERDICTS must be all, drop or none")
        self.queue = deque(maxlen=QUEUE)
        self.lock = threading.Lock()
        self.flushing = threading.Lock()
        self.stats = {"sent": 0, "dropped": 0, "errors": 0, "last_error": None, "last_sent": None}
        self.last_flush = 0.0

    @classmethod
    def from_env(cls):
        url, syslog = os.environ.get("DUVORA_SIEM_URL", ""), os.environ.get("DUVORA_SIEM_SYSLOG", "")
        if not url and not syslog:
            return None
        cats = [c.strip() for c in os.environ.get("DUVORA_SIEM_EVENTS", ",".join(CATEGORIES)).split(",") if c.strip()]
        if set(cats) - set(CATEGORIES):
            raise ValueError(f"DUVORA_SIEM_EVENTS may list {', '.join(CATEGORIES)}")
        return cls(url, os.environ.get("DUVORA_SIEM_KEY", ""), os.environ.get("DUVORA_SIEM_CA_FILE") or None, syslog,
                   os.environ.get("DUVORA_SIEM_VERDICTS", "drop"), cats, os.environ.get("DUVORA_SIEM_ALLOW_HTTP") == "1")

    def wants(self, category, event):
        if category not in self.categories:
            return False
        if category == "verdict":
            return self.verdicts == "all" or (self.verdicts == "drop" and event.get("action") == "drop")
        return True

    def put(self, category, event):
        if not self.wants(category, event):
            return
        with self.lock:
            if len(self.queue) == self.queue.maxlen:
                self.stats["dropped"] += 1
            self.queue.append({"category": category, **event})

    def _post(self, batch):
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        body = json.dumps({"source": "duvora", "events": batch}, default=str).encode()
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        with self.opener.open(req, timeout=self.timeout) as response:
            response.read(1024)

    def _syslog(self, batch):
        scheme, host, port = self.syslog_target
        lines = [syslog_line(e).encode() for e in batch]
        if scheme == "udp":
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
                for line in lines:
                    s.sendto(line[:8192], (host, port))
            return
        raw = socket.create_connection((host, port), timeout=self.timeout)
        conn = self.ssl_context.wrap_socket(raw, server_hostname=host) if self.ssl_context else raw
        with conn:
            conn.sendall(b"".join(str(len(line)).encode() + b" " + line for line in lines))

    def flush(self, force=False):
        now = time.time()
        if not force and now - self.last_flush < FLUSH_INTERVAL:
            return 0
        if not self.flushing.acquire(blocking=False):
            return 0
        sent = 0
        try:
            self.last_flush = now
            while True:
                with self.lock:
                    batch = [self.queue.popleft() for _ in range(min(BATCH, len(self.queue)))]
                if not batch:
                    break
                try:
                    if self.url:
                        self._post(batch)
                    if self.syslog:
                        self._syslog(batch)
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    with self.lock:
                        self.queue.extendleft(reversed(batch[:self.queue.maxlen - len(self.queue)]))
                        self.stats.update(errors=self.stats["errors"] + 1, last_error=f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"[:200])
                    break
                sent += len(batch)
                with self.lock:
                    self.stats.update(sent=self.stats["sent"] + len(batch), last_sent=time.time())
        finally:
            self.flushing.release()
        return sent

    def status(self):
        with self.lock:
            return {"configured": True, "webhook": urlsplit(self.url).hostname if self.url else None,
                    "syslog": f"{self.syslog_target[0]}://{self.syslog_target[1]}:{self.syslog_target[2]}" if self.syslog else None,
                    "verdicts": self.verdicts, "categories": sorted(self.categories), "queued": len(self.queue), **self.stats}


class SiemMixin:
    def init_siem(self, exporter=None):
        self.siem = exporter if exporter is not None else SiemExporter.from_env()

    def export_event(self, category, event):
        if self.siem:
            self.siem.put(category, event)

    def flush_siem(self, force=False):
        if not self.siem:
            return 0
        if force:
            return self.siem.flush(force=True)
        threading.Thread(target=self.siem.flush, daemon=True).start()
        return 0

    def siem_status(self):
        return self.siem.status() if self.siem else {"configured": False, "categories": list(CATEGORIES),
                                                      "note": "Set DUVORA_SIEM_URL and/or DUVORA_SIEM_SYSLOG to export events"}

    def siem_test(self, actor):
        if not self.siem:
            raise Problem("No SIEM is configured (DUVORA_SIEM_URL or DUVORA_SIEM_SYSLOG)", 409)
        self.siem.put("audit", {"time": time.time(), "actor": actor, "action": "siem.test", "detail": {"note": "Test event from Duvora"}})
        sent = self.siem.flush(force=True)
        return {**self.siem.status(), "flushed": sent}

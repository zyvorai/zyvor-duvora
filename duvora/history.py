"""Per-device metric samples with windowed, downsampled reads."""
import json
import random
import time

from .common import Problem, canonical

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, ts REAL NOT NULL, metrics TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS samples_device_ts ON samples(device, ts);
"""
WINDOWS = {"1h": (3600, 0), "24h": (86400, 300), "7d": (7 * 86400, 3600)}
SAMPLE_INTERVAL = 10
SAMPLE_RETENTION = 7 * 86400
METRICS = ("throughput_gbps", "drops", "temperature_c", "link_gbps", "pps", "blocked_pps", "tcp_retransmits_pm", "tcp_resets_pm")


class HistoryMixin:
    def init_history(self):
        self.db.executescript(SCHEMA)
        self.last_sample = 0.0

    def record_sample(self, device, metrics, ts=None):
        if metrics:
            self.db.execute("INSERT INTO samples(device, ts, metrics) VALUES(?,?,?)", (device, ts or time.time(), canonical(metrics)))
            self.update_baselines(device, metrics)

    def simulate_metrics(self, now=None):
        """Random-walk the demo counters around their seeded baseline and sample every device."""
        now = now or time.time()
        if not self.demo or now - self.last_sample < SAMPLE_INTERVAL:
            return
        self.last_sample = now
        with self.transaction():
            for d in self.rows("devices"):
                if d["source"] != "simulator":
                    continue
                try:
                    i = int(d["id"].rsplit("-", 1)[1])
                except (IndexError, ValueError):
                    continue
                m = d["metrics"]
                base_tp, base_temp = 62 + i * 18, 76 if i == 3 else 43 + i
                m["throughput_gbps"] = round(min(m.get("link_gbps", 200), max(0, m.get("throughput_gbps", base_tp) + random.uniform(-6, 6) + (base_tp - m.get("throughput_gbps", base_tp)) * 0.2)), 1)
                m["temperature_c"] = round(max(30, m.get("temperature_c", base_temp) + random.uniform(-1.5, 1.5) + (base_temp - m.get("temperature_c", base_temp)) * 0.15), 1)
                if i == 3 and random.random() < 0.3:
                    m["drops"] = m.get("drops", 0) + random.randint(1, 4)
                d["metrics"] = m
                self.put("devices", d["id"], d)
                self.record_sample(d["id"], m, now)

    def history(self, device_id, window="1h"):
        if window not in WINDOWS:
            raise Problem("Window must be 1h, 24h or 7d")
        span, bucket = WINDOWS[window]
        with self.lock:
            self.device(device_id)
            rows = self.db.execute("SELECT ts, metrics FROM samples WHERE device=? AND ts>=? ORDER BY ts",
                                   (device_id, time.time() - span)).fetchall()
        points = [dict(ts=r["ts"], **json.loads(r["metrics"])) for r in rows]
        if bucket:
            grouped = {}
            for p in points:
                grouped.setdefault(int(p["ts"] // bucket) * bucket, []).append(p)
            points = []
            for start, group in sorted(grouped.items()):
                point = {"ts": start}
                for key in METRICS:
                    values = [p[key] for p in group if key in p]
                    if values:
                        point[key] = round(max(values) if key == "drops" else sum(values) / len(values), 2)
                points.append(point)
        return {"device": device_id, "window": window, "bucket_seconds": bucket or SAMPLE_INTERVAL, "points": points}

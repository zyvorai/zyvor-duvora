"""Regressions: partial device capacity and SIEM drop accounting."""
import unittest

from duvora.budget import budget_blockers
from duvora.siem import SiemExporter


class PartialCapacity(unittest.TestCase):
    def test_missing_resource_does_not_raise(self):
        d = {"id": "d1", "capacity": {"arm_cores": 8}, "services": []}
        self.assertEqual(budget_blockers(d, "svc", {"arm_cores": 1}), [])
        out = budget_blockers(d, "svc", {"memory_gb": 1})
        self.assertEqual(len(out), 1)
        self.assertIn("unknown", out[0])


class SiemDrops(unittest.TestCase):
    def test_failed_flush_counts_events_that_no_longer_fit(self):
        ex = SiemExporter(url="http://127.0.0.1:1/x")
        ex.queue = type(ex.queue)(maxlen=3)

        def fail(batch):
            ex.queue.append({"category": "audit", "i": "new"})  # arrives while the send is in flight
            raise OSError("down")
        ex._post = fail
        for i in range(3):
            ex.queue.append({"category": "audit", "i": i})
        ex.flush(force=True)
        self.assertEqual(ex.stats["dropped"], 1)
        self.assertEqual(len(ex.queue), 3)


if __name__ == "__main__":
    unittest.main()

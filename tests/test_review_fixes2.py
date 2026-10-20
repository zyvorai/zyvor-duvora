"""Regressions: agent credential errors, steering payload drain, unknown-agent rows, DPF bridge kubectl failure."""
import io
import subprocess
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from duvora import agent, dpf
from duvora.agent import Credential
from duvora.bpf.steer import PAYLOAD, FLOW_KEY, Steering
from duvora.core import Store
from duvora.identity import UNKNOWN_MAX


def http_error(code):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(b""))


class CredentialErrors(unittest.TestCase):
    def test_remote_http_falls_back_to_bootstrap(self):
        c = Credential("http://10.0.0.5:8787", "boot")
        self.assertEqual(c.current(), "boot")  # check_url raises ValueError for non-loopback HTTP

    def test_malformed_response_falls_back(self):
        c = Credential("https://x", "boot")
        with patch.object(agent, "request", return_value={}):
            self.assertEqual(c.current(), "boot")

    def test_status_code_drives_state(self):
        c = Credential("https://x", "boot")
        with patch.object(agent, "request", side_effect=http_error(404)):
            c.current()
        self.assertFalse(c.supported)
        c = Credential("https://x", "boot")
        c.token, c.rotate_after = "dva_old", 0
        with patch.object(agent, "request", side_effect=http_error(401)):
            self.assertEqual(c.current(), "boot")
        self.assertEqual(c.token, "")

    def test_non_status_error_mentioning_404_is_not_a_missing_endpoint(self):
        c = Credential("https://x", "boot")
        with patch.object(agent, "request", side_effect=OSError("connect to 10.0.4.04:404 refused")):
            c.current()
        self.assertTrue(c.supported)


class FakeBpf:
    def __init__(self, n):
        self.map = {bytes([i]) * FLOW_KEY.size: bytes(PAYLOAD.size) for i in range(n)}

    def items(self, fd, ks, vs):
        return list(self.map.items())

    def delete(self, fd, key):
        self.map.pop(key, None)


class PayloadDrain(unittest.TestCase):
    def test_entries_beyond_limit_are_kept(self):
        st = Steering.__new__(Steering)
        st.bpf, st.fds = FakeBpf(5), {"steer_payloads": 1}
        with patch("duvora.bpf.steer.decode_payload", lambda k, v: k):
            self.assertEqual(len(st.drain_payloads(limit=2)), 2)
            self.assertEqual(len(st.bpf.map), 3)


class UnknownAgentRows(unittest.TestCase):
    def test_pruned_by_age_and_count(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(str(Path(d) / "s.db"), demo=False)
            try:
                store.note_unknown_agent("203.0.113.9")
                now = time.time()
                with store.transaction():
                    store.prune_identity(now)
                self.assertEqual(len(store.db.execute("SELECT 1 FROM agent_identity").fetchall()), 1)
                with store.transaction():
                    store.prune_identity(now + 2 * 86400)
                self.assertEqual(len(store.db.execute("SELECT 1 FROM agent_identity").fetchall()), 0)
                for i in range(UNKNOWN_MAX + 5):
                    store.note_unknown_agent(f"198.51.{i // 250}.{i % 250}")
                with store.transaction():
                    store.prune_identity(time.time())
                self.assertEqual(len(store.db.execute("SELECT 1 FROM agent_identity").fetchall()), UNKNOWN_MAX)
            finally:
                store.close()


class DpfBridge(unittest.TestCase):
    ARGV = ["dpf", "--context", "c", "--host", "h"]

    def test_kubectl_failure_is_a_clean_exit(self):
        err = subprocess.CalledProcessError(1, "kubectl", stderr="Unable to connect")
        with patch("sys.argv", self.ARGV), patch.object(dpf.subprocess, "run", side_effect=err):
            with self.assertRaises(SystemExit) as cm:
                dpf.main()
        self.assertIn("Unable to connect", str(cm.exception))

    def test_missing_token_is_checked_before_the_cluster_call(self):
        with patch("sys.argv", self.ARGV + ["--submit"]), patch.dict("os.environ", {}, clear=True), \
                patch.object(dpf.subprocess, "run", side_effect=AssertionError("kubectl called")), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                dpf.main()


if __name__ == "__main__":
    unittest.main()

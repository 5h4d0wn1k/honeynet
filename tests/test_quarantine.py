import tempfile
import unittest
from pathlib import Path

from honeynet.quarantine import Quarantine, is_lab_source


def _record(src, event="request"):
    return {"ts": "2026-09-09T00:00:00+00:00", "src": src, "proto": "http",
            "event": event, "port": 1, "data": {}}


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.quar = Quarantine(path=f"{self.tmp}/quarantine.json", dry_run=True)

    def test_mark_kill_rfc5737(self):
        res = self.quar.mark_kill("203.0.113.7", "demo detection")
        self.assertTrue(res["marked"])
        self.assertTrue(res["first"])

    def test_refuses_non_lab_source(self):
        with self.assertRaises(ValueError):
            self.quar.mark_kill("8.8.8.8")

    def test_is_killed(self):
        self.assertFalse(self.quar.is_killed("203.0.113.7"))
        self.quar.mark_kill("203.0.113.7")
        self.assertTrue(self.quar.is_killed("203.0.113.7"))

    def test_filter_interactions_drops_killed_src(self):
        records = [_record("203.0.113.7"), _record("198.51.100.9")]
        self.quar.mark_kill("203.0.113.7")
        kept = self.quar.filter_interactions(records)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["src"], "198.51.100.9")

    def test_interceptions_lists_suppressed(self):
        records = [_record("203.0.113.7"), _record("203.0.113.7"), _record("192.0.2.1")]
        self.quar.mark_kill("203.0.113.7")
        self.assertEqual(len(self.quar.interceptions(records)), 2)

    def test_persist_and_reload(self):
        quar = Quarantine(path=f"{self.tmp}/q.json", dry_run=False)
        quar.mark_kill("203.0.113.7", "persisted")
        self.assertTrue(Path(quar.path).exists())
        reloaded = Quarantine(path=f"{self.tmp}/q.json", dry_run=True)
        self.assertTrue(reloaded.is_killed("203.0.113.7"))

    def test_lab_source_helper(self):
        self.assertTrue(is_lab_source("127.0.0.1"))
        self.assertTrue(is_lab_source("203.0.113.7"))
        self.assertFalse(is_lab_source("10.0.0.1"))
        self.assertFalse(is_lab_source("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
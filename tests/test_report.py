import json
import tempfile
import unittest
from pathlib import Path

from honeynet.report import (
    build_report,
    recommender,
    replay_timeline,
    to_markdown,
    write_reports,
)


def _records():
    base = "2026-09-09T00:00:00+00:00"
    return [
        {"ts": base, "src": "203.0.113.7", "port": 1, "proto": "ssh",
         "event": "connect", "data": {}, "direction": "in"},
        {"ts": "2026-09-09T00:00:10+00:00", "src": "203.0.113.7", "port": 2, "proto": "http",
         "event": "request", "data": {"path": "/admin", "user_agent": "sqlmap/1.6"}, "direction": "in"},
        {"ts": "2026-09-09T00:00:05+00:00", "src": "198.51.100.5", "port": 3, "proto": "mqtt",
         "event": "subscribe", "data": {"topic": "t"}, "direction": "in"},
    ]


class TestReport(unittest.TestCase):
    def test_build_report_keys(self):
        rep = build_report(records=_records())
        for key in ("engagements", "stats", "iocs", "replay", "recommendation", "generated", "tool"):
            self.assertIn(key, rep)
        self.assertEqual(rep["tool"], "honeynet")

    def test_replay_sorted_chronologically(self):
        timeline = replay_timeline(_records())
        self.assertEqual(len(timeline), 3)
        self.assertIn("ssh connect", timeline[0])
        self.assertIn("mqtt subscribe", timeline[1])
        self.assertIn("http request", timeline[-1])

    def test_markdown_sections(self):
        md = to_markdown(build_report(records=_records()))
        for heading in ("Dwell & Risk", "Engagements", "Detected IOCs",
                        "Interaction Replay", "Recommendation"):
            self.assertIn(f"## {heading}", md)

    def test_markdown_table_rows(self):
        rep = build_report(records=_records(), engagements=[
            {"src": "203.0.113.7", "protocols": ["ssh", "http"], "actions": 2,
             "dwell_seconds": 10.0, "flags": ["tool-ua:sqlmap"],
             "risk": {"score": 66, "level": "high"}}])
        md = to_markdown(rep)
        self.assertIn("| 203.0.113.7 | ssh, http |", md)

    def test_write_reports_writes_both_files(self):
        tmp = tempfile.mkdtemp()
        rep = build_report(records=_records())
        json_path, md_path = write_reports(rep, tmp, name="honeynet-test")
        self.assertTrue(Path(json_path).exists())
        self.assertTrue(Path(md_path).exists())
        data = json.loads(Path(json_path).read_text())
        self.assertEqual(data["tool"], "honeynet")

    def test_recommender_high_risk(self):
        scored = [{"src": "203.0.113.7", "actions": 30, "risk": {"level": "critical", "score": 90}}]
        text = recommender(scored)
        self.assertIn("Investigate", text)
        self.assertIn("203.0.113.7", text)


if __name__ == "__main__":
    unittest.main()
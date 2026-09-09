import unittest

from honeynet.engage import Engagement, EngagementTracker, fingerprint_engagement


def rec(event, proto="http", src="203.0.113.7", ts="2026-09-09T00:00:00+00:00", data=None):
    return {"ts": ts, "src": src, "port": 1, "proto": proto, "event": event, "data": data or {}}


class TestEngagementTracker(unittest.TestCase):
    def test_groups_by_source(self):
        tracker = EngagementTracker()
        tracker.observe(rec("connect"))
        tracker.observe(rec("connect", src="198.51.100.5"))
        tracker.observe(rec("connect"))
        self.assertEqual(len(tracker.engagements()), 2)

    def test_measures_dwell_from_timestamps(self):
        eng = Engagement("203.0.113.7")
        eng.add(rec("connect", ts="2026-09-09T00:00:00+00:00"))
        eng.add(rec("disconnect", ts="2026-09-09T00:00:05+00:00"))
        self.assertAlmostEqual(eng.dwell_seconds(), 5.0, places=3)

    def test_fingerprints_tool_ua(self):
        tracker = EngagementTracker()
        tracker.observe(rec("request", data={"path": "/", "user_agent": "sqlmap/1.7.2"}))
        [eng] = tracker.engagements(fingerprints=True)
        self.assertIn("tool-ua:sqlmap", eng.flags)

    def test_fingerprints_credential_reuse(self):
        tracker = EngagementTracker()
        tracker.observe(rec("auth-attempt", proto="ssh", data={"username": "root", "password": "same!"}))
        tracker.observe(rec("params", data={"path": "/admin/login.php",
                                            "params": {"user": "root", "pass": "same!"}}))
        [eng] = tracker.engagements(fingerprints=True)
        self.assertTrue(any(f.startswith("credential-reuse") for f in eng.flags))

    def test_fingerprints_path_probe(self):
        tracker = EngagementTracker()
        tracker.observe(rec("request", data={"path": "/phpmyadmin/index.php", "user_agent": ""}))
        [eng] = tracker.engagements(fingerprints=True)
        self.assertTrue(any(f.startswith("path-probe") for f in eng.flags))

    def test_fingerprints_tripwire(self):
        tracker = EngagementTracker()
        tracker.observe(rec("tripwire", data={"path": "/config/secrets.env", "token": "HNYTKN-1"}))
        [eng] = tracker.engagements(fingerprints=True)
        self.assertIn("honeytoken-tripwire", eng.flags)

    def test_action_count_excludes_metadata(self):
        eng = Engagement("203.0.113.7")
        eng.add(rec("connect"))
        eng.add(rec("request", data={"path": "/", "user_agent": ""}))
        eng.add(rec("disconnect"))
        eng.add(rec("subscribe", proto="mqtt", data={"topic": "t"}))
        self.assertEqual(eng.action_count(), 2)

    def test_user_agents_dict_counts(self):
        eng = Engagement("203.0.113.7")
        eng.add(rec("request", data={"path": "/", "user_agent": "ua"}))
        eng.add(rec("request", data={"path": "/x", "user_agent": "ua"}))
        self.assertEqual(eng.user_agents["ua"], 2)


if __name__ == "__main__":
    unittest.main()
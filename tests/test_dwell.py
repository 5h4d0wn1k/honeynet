import unittest

from honeynet.dwell import (
    build_iocs,
    compute_score,
    dwell_stats,
    risk_level,
    score_engagement,
)
from honeynet.engage import Engagement, fingerprint_engagement


def rec(event, data=None, ts="2026-09-09T00:00:00+00:00"):
    return {"ts": ts, "src": "203.0.113.7", "port": 1, "proto": "http", "event": event, "data": data or {}}


def base_engagement(ts_start="2026-09-09T00:00:00+00:00", ts_end="2026-09-09T00:00:02+00:00"):
    eng = Engagement("203.0.113.7")
    eng.add(rec("connect", ts=ts_start))
    eng.add(rec("request", {"path": "/", "user_agent": ""}, ts=ts_end))
    eng.add(rec("disconnect", ts=ts_end))
    return eng


class TestDwellScoring(unittest.TestCase):
    def test_score_is_bounded_int(self):
        score = compute_score(base_engagement())
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_score_increases_with_actions(self):
        light = base_engagement()
        heavy = base_engagement()
        for i in range(6):
            heavy.add(rec("request", {"path": f"/p{i}", "user_agent": ""},
                          ts=f"2026-09-09T00:00:0{i + 1}+00:00"))
        heavy.add(rec("tripwire", {"path": "/config/secrets.env", "token": "HNYTKN-1"}))
        self.assertGreater(compute_score(heavy), compute_score(light))

    def test_dwell_component_scales(self):
        short = base_engagement()
        long = base_engagement(ts_end="2026-09-09T00:00:30+00:00")
        c1 = score_engagement(short)["risk"]["components"]["dwell_pts"]
        c2 = score_engagement(long)["risk"]["components"]["dwell_pts"]
        self.assertGreater(c2, c1)

    def test_risk_level_buckets(self):
        self.assertEqual(risk_level(0), "low")
        self.assertEqual(risk_level(30), "medium")
        self.assertEqual(risk_level(60), "high")
        self.assertEqual(risk_level(90), "critical")

    def test_ioc_extraction(self):
        eng = base_engagement()
        eng.add(rec("request", {"path": "/phpmyadmin", "user_agent": "sqlmap/1.6"}))
        eng.add(rec("request", {"path": "/admin", "user_agent": "sqlmap/1.6"}))
        eng.add(rec("auth-attempt", {"username": "root", "password": "pw"}))
        eng.add(rec("tripwire", {"path": "/config/secrets.env", "token": "HNYTKN-1"}))
        iocs = build_iocs(eng)
        kinds = {i["type"] for i in iocs}
        self.assertIn("source-ip", kinds)
        self.assertIn("user-agent", kinds)
        self.assertIn("path", kinds)
        self.assertIn("credential-attempt", kinds)
        self.assertIn("honeytoken", kinds)

    def test_dwell_stats_aggregates(self):
        stats = dwell_stats([score_engagement(base_engagement()), score_engagement(base_engagement())])
        self.assertEqual(stats["engagements"], 2)
        self.assertEqual(stats["total_actions"], 2)  # one request event per engagement


if __name__ == "__main__":
    unittest.main()
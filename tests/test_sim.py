import unittest

from honeynet.sim import Attacker, run_standard_attack, standard_plan
from tests.helpers import ATTRIB, start_farm


class TestAttackerScriptedPlays(unittest.TestCase):
    def test_standard_plan_has_all_ops(self):
        ops = [s["op"] for s in standard_plan() if s["op"] != "sleep"]
        for expected in ("ssh", "http_get", "http_post", "mqtt_subscribe",
                         "mcp_call", "telnet", "smtp", "vnc"):
            self.assertIn(expected, ops)

    def test_attacker_runs_against_live_farm(self):
        farm, _, ports = start_farm(["ssh", "http", "mqtt", "mcp", "telnet", "smtp", "vnc"])
        try:
            attacker = Attacker(src="203.0.113.7")
            result = attacker.run_plan(ports, standard_plan())
            self.assertEqual(result["actions_attempted"], 9)
            self.assertEqual(result["actions_ok"], 9)
        finally:
            farm.stop()

    def test_ssh_login_rejected_ok(self):
        farm, _, ports = start_farm(["ssh"])
        try:
            attacker = Attacker()
            ok, note = attacker.ssh_login("127.0.0.1", ports["ssh"], "root", "pw")
            self.assertTrue(ok)
            self.assertIn("rejected", note)
        finally:
            farm.stop()

    def test_http_post_200(self):
        farm, _, ports = start_farm(["http"])
        try:
            attacker = Attacker()
            ok, note = attacker.http_request("127.0.0.1", ports["http"], "POST",
                                             "/admin/login.php", {"user": "root", "pass": "x"})
            self.assertTrue(ok)
        finally:
            farm.stop()

    def test_mqtt_subscribe_ok(self):
        farm, _, ports = start_farm(["mqtt"])
        try:
            attacker = Attacker()
            ok, note = attacker.mqtt_subscribe("127.0.0.1", ports["mqtt"], "telemetry/edge/#")
            self.assertTrue(ok)
            self.assertIn("->", note)
        finally:
            farm.stop()

    def test_mcp_tool_call_no_error(self):
        farm, _, ports = start_farm(["mcp"])
        try:
            attacker = Attacker()
            ok, note = attacker.mcp_call("127.0.0.1", ports["mcp"], "tools/call",
                                         {"name": "read_secrets", "arguments": {}})
            self.assertTrue(ok)
        finally:
            farm.stop()


class TestSimDetectionProof(unittest.TestCase):
    def test_standard_attack_logs_actions_and_iocs(self):
        farm, logger, ports = start_farm(["ssh", "http", "telnet", "smtp", "vnc", "mqtt", "mcp"], attribution=ATTRIB)
        try:
            result = run_standard_attack(ports, logger, cfg={"attacker_src": "203.0.113.7"})
            self.assertGreater(result["actions_logged"], 0)
            self.assertGreaterEqual(result["dwell_seconds"], 0.0)
            self.assertIsNotNone(result["risk"])
            self.assertTrue(result["iocs"])
            ioc_kinds = {i["type"] for i in result["iocs"]}
            self.assertIn("source-ip", ioc_kinds)
            self.assertIn("mqtt-subscribe", ioc_kinds)
            self.assertIn("mcp-tool-call", ioc_kinds)
            self.assertTrue(result["replay"])
        finally:
            farm.stop()

    def test_credential_reuse_detected(self):
        farm, logger, ports = start_farm(["ssh", "http"], attribution=ATTRIB)
        try:
            attacker = Attacker(src="203.0.113.7")
            attacker.ssh_login("127.0.0.1", ports["ssh"], "root", "labcred")
            attacker.http_request("127.0.0.1", ports["http"], "POST", "/admin/login.php",
                                  {"user": "root", "pass": "labcred"})
            from honeynet.engage import tracker_from_records
            tracker = tracker_from_records(logger.read())
            [eng] = tracker.engagements(fingerprints=True)
            self.assertTrue(any(f.startswith("credential-reuse") for f in eng.flags))
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()
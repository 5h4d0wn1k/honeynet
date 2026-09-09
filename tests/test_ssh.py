import unittest

from tests.helpers import ssh_exchange, start_farm


class TestSshHoneypot(unittest.TestCase):
    def test_logs_rejected_auth(self):
        farm, logger, ports = start_farm(["ssh"])
        try:
            banner, _, _, denial = ssh_exchange(ports["ssh"], "root", "Hunter2-Lab!")
            self.assertIn(b"SSH-2.0-OpenSSH", banner)
            self.assertIn(b"Permission denied", denial)
            auth = [r for r in logger.read() if r["event"] == "auth-attempt"]
            self.assertEqual(len(auth), 1)
            self.assertEqual(auth[0]["data"]["username"], "root")
            self.assertEqual(auth[0]["data"]["password"], "Hunter2-Lab!")
            self.assertTrue(auth[0]["data"]["rejected"])
            self.assertEqual(auth[0]["src"], "203.0.113.7")
        finally:
            farm.stop()

    def test_two_attempts_logs_two(self):
        farm, logger, ports = start_farm(["ssh"])
        try:
            ssh_exchange(ports["ssh"], "user1", "pw1")
            ssh_exchange(ports["ssh"], "user2", "pw2")
            auths = [r for r in logger.read() if r["event"] == "auth-attempt"]
            self.assertEqual(len(auths), 2)
            self.assertEqual({a["data"]["username"] for a in auths}, {"user1", "user2"})
        finally:
            farm.stop()

    def test_ephemeral_port_bound(self):
        farm, _, ports = start_farm(["ssh"])
        try:
            self.assertGreater(ports["ssh"], 0)
            self.assertLess(ports["ssh"], 65536)
        finally:
            farm.stop()

    def test_emits_rejected_event(self):
        farm, logger, ports = start_farm(["ssh"])
        try:
            ssh_exchange(ports["ssh"], "admin", "pw")
            import time
            time.sleep(0.3)
            self.assertTrue(any(r["event"] == "auth-rejected" for r in logger.read()))
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()
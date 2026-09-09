import unittest

from honeynet.engine import Farm
from honeynet.services.base import SafetyError
from tests.helpers import start_farm


class TestFarmEngine(unittest.TestCase):
    def test_all_protos_start_on_ephemeral_ports(self):
        farm, _, ports = start_farm(["ssh", "http", "telnet", "smtp", "vnc", "mqtt", "mcp"])
        try:
            for proto in ("ssh", "http", "telnet", "smtp", "vnc", "mqtt", "mcp"):
                self.assertGreater(ports[proto], 0, proto)
            self.assertEqual(farm.services_up(), 7)
        finally:
            farm.stop()

    def test_family_count_is_five(self):
        farm, _, _ = start_farm(["ssh", "http", "telnet", "smtp", "vnc", "mqtt", "mcp"])
        try:
            self.assertEqual(farm.family_count(), 5)
            self.assertIn("telnet/smtp/vnc", farm.families())
            self.assertIn("json-rpc/mcp", farm.families())
        finally:
            farm.stop()

    def test_refuses_non_loopback_bind(self):
        from tests.helpers import tmp_logger, make_grid
        from honeynet.services import make_service
        svc = make_service("ssh", tmp_logger(), make_grid(), host="192.0.2.10")
        with self.assertRaises(SafetyError):
            svc.start()

    def test_refuses_privileged_port(self):
        from tests.helpers import make_grid, tmp_logger
        from honeynet.services import make_service
        svc = make_service("ssh", tmp_logger(), make_grid(), port=22)
        with self.assertRaises(SafetyError):
            svc.start()

    def test_attribution_labels_source(self):
        farm, logger, ports = start_farm(["ssh"])
        try:
            from tests.helpers import ssh_exchange
            ssh_exchange(ports["ssh"], "root", "pw")
            records = logger.read()
            self.assertTrue(all(r["src"] == "203.0.113.7" for r in records if r["event"] == "connect"))
            self.assertTrue(all(r.get("peer") == "127.0.0.1" for r in records if r["event"] == "connect"))
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()
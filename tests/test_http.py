import unittest

from tests.helpers import http_request, start_farm


class TestHttpHoneypot(unittest.TestCase):
    def test_parses_post_params(self):
        farm, logger, ports = start_farm(["http"])
        try:
            status, _, body = http_request(ports["http"], "POST", "/admin/login.php",
                                           body="user=root&pass=Lab-demo-2026!")
            self.assertTrue(status.startswith("HTTP/1.1 200"))
            self.assertIn("<form", body)
            params = [r for r in logger.read() if r["event"] == "params"]
            self.assertEqual(len(params), 1)
            p = params[0]["data"]["params"]
            self.assertEqual(p.get("user"), "root")
            self.assertEqual(p.get("pass"), "Lab-demo-2026!")
        finally:
            farm.stop()

    def test_logs_get_request_with_ua(self):
        farm, logger, ports = start_farm(["http"])
        try:
            http_request(ports["http"], "GET", "/")
            req = [r for r in logger.read() if r["event"] == "request"]
            self.assertEqual(len(req), 1)
            self.assertEqual(req[0]["data"]["method"], "GET")
            self.assertEqual(req[0]["data"]["path"], "/")
            self.assertIn("sqlmap", req[0]["data"]["user_agent"].lower())
        finally:
            farm.stop()

    def test_serves_login_page(self):
        farm, _, ports = start_farm(["http"])
        try:
            _, _, body = http_request(ports["http"], "GET", "/index.html")
            self.assertIn("Sign in to honeynet.lab", body)
        finally:
            farm.stop()

    def test_tripwire_serves_honeytoken(self):
        farm, logger, ports = start_farm(["http"])
        try:
            status, _, body = http_request(ports["http"], "GET", "/config/secrets.env")
            self.assertTrue(status.startswith("HTTP/1.1 200"))
            self.assertIn("HNYTKN-", body)
            trip = [r for r in logger.read() if r["event"] == "tripwire"]
            self.assertEqual(len(trip), 1)
            self.assertEqual(trip[0]["data"]["path"], "/config/secrets.env")
            self.assertIn(trip[0]["data"]["token"], body)
        finally:
            farm.stop()

    def test_not_found_path(self):
        farm, logger, ports = start_farm(["http"])
        try:
            status, _, _ = http_request(ports["http"], "GET", "/nothing/here")
            self.assertTrue(status.startswith("HTTP/1.1 404"))
            self.assertTrue(any(r["event"] == "not-found" for r in logger.read()))
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()
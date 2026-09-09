import unittest

from tests.helpers import mcp_call, start_farm


class TestMcpHoneypot(unittest.TestCase):
    def test_tools_list(self):
        farm, logger, ports = start_farm(["mcp"])
        try:
            [(rid, resp)] = mcp_call(ports["mcp"], [(1, "tools/list", None)])
            self.assertEqual(resp["id"], 1)
            self.assertIn("tools", resp["result"])
            names = [t["name"] for t in resp["result"]["tools"]]
            self.assertIn("read_secrets", names)
        finally:
            farm.stop()

    def test_tool_call_logged_full(self):
        farm, logger, ports = start_farm(["mcp"])
        try:
            mcp_call(ports["mcp"], [(42, "tools/call", {"name": "run_command", "arguments": {"command": "whoami"}})])
            calls = [r for r in logger.read() if r["event"] == "tool-call"]
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["data"]["tool"], "run_command")
            self.assertEqual(calls[0]["data"]["arguments"], {"command": "whoami"})
            self.assertIn("tools/call", calls[0]["data"]["full_request"])
        finally:
            farm.stop()

    def test_initialize_returns_protocol_version(self):
        farm, _, ports = start_farm(["mcp"])
        try:
            [(rid, resp)] = mcp_call(ports["mcp"], [(5, "initialize", {"protocolVersion": "2025-03-26"})])
            self.assertEqual(resp["result"]["protocolVersion"], "2025-03-26")
        finally:
            farm.stop()

    def test_unknown_method_returns_error(self):
        farm, logger, ports = start_farm(["mcp"])
        try:
            mcp_call(ports["mcp"], [(9, "bogus/method", None)])
            self.assertTrue(any(r["event"] == "jsonrpc-method" for r in logger.read()))
        finally:
            farm.stop()


if __name__ == "__main__":
    unittest.main()
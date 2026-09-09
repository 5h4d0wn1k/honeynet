import socket
import tempfile
import unittest
from pathlib import Path

from honeynet.logger import InteractionLogger, describe


class TestInteractionLogger(unittest.TestCase):
    def setUp(self):
        self.logger = InteractionLogger(tempfile.mkdtemp(prefix="hntest-log-"))

    def test_write_and_read_roundtrip(self):
        self.logger.log("ssh", "203.0.113.7", 2222, "auth-attempt", {"username": "root", "password": "x"})
        records = self.logger.read()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event"], "auth-attempt")
        self.assertEqual(records[0]["data"]["username"], "root")
        self.assertEqual(records[0]["src"], "203.0.113.7")
        self.assertEqual(records[0]["port"], 2222)
        self.assertEqual(records[0]["proto"], "ssh")

    def test_logger_filter_by_source(self):
        self.logger.log("ssh", "203.0.113.7", 1, "connect", {})
        self.logger.log("http", "198.51.100.9", 2, "connect", {})
        self.assertEqual(len(self.logger.for_source("203.0.113.7")), 1)
        self.assertEqual(self.logger.count(src="198.51.100.9"), 1)

    def test_logger_count_and_clear(self):
        self.logger.log("mqtt", "203.0.113.7", 3, "subscribe", {"topic": "t"})
        self.logger.log("mqtt", "203.0.113.7", 3, "subscribe", {"topic": "t2"})
        self.assertEqual(self.logger.count("mqtt"), 2)
        self.assertEqual(self.logger.count("http"), 0)
        self.logger.clear()
        empty = Path(self.logger.path)
        self.assertTrue(list(self.logger.read()) == [])

    def test_timestamp_is_utc_iso(self):
        record = self.logger.log("mcp", "192.0.2.5", 4, "tool-call", {"tool": "read_secrets"})
        self.assertIn(":", record["ts"])
        self.assertIn("+", record["ts"])

    def test_describe_human_readable(self):
        record = self.logger.log("ssh", "203.0.113.7", 5, "auth-attempt", {"username": "root", "password": "pw"})
        line = describe(record)
        self.assertIn("auth-attempt", line)
        self.assertIn("root:pw", line)


if __name__ == "__main__":
    unittest.main()
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import honeynet.cli as cli
from honeynet.logger import InteractionLogger
from honeynet.sim import Attacker
from tests.helpers import start_farm


class TestCliDemo(unittest.TestCase):
    def test_demo_exits_zero_with_proof(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["--demo"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("5 service families up", out)
        self.assertIn("sim attacker logged with", out)
        self.assertIn("dwell T =", out)
        self.assertIn("score:", out)
        self.assertIn("replay timeline", out)
        self.assertIn("IOCs:", out)


class TestCliParser(unittest.TestCase):
    def test_no_args_exits_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main([])
        self.assertEqual(rc, 0)

    def test_all_subcommands_present(self):
        parser = cli.build_parser()
        names = set(parser._subparsers._group_actions[0].choices)
        for expected in ["pot", "engage", "deceive", "sim", "dwell", "report", "quarantine"]:
            self.assertIn(expected, names)

    def test_version_flag(self):
        parser = cli.build_parser()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["--version"])
            self.assertEqual(ctx.exception.code, 0)
        self.assertIn("1.0.0", buf.getvalue())


class TestCliSubcommands(unittest.TestCase):
    def _attack_log(self):
        farm, logger, ports = start_farm(["ssh", "http", "mqtt", "mcp", "telnet", "smtp", "vnc"])
        try:
            attacker = Attacker(src="203.0.113.7")
            attacker.run_plan(ports, [
                {"op": "ssh", "proto": "ssh", "username": "root", "password": "pw"},
                {"op": "http_get", "proto": "http", "path": "/config/secrets.env"},
                {"op": "mqtt_subscribe", "proto": "mqtt", "topic": "telemetry/edge/#"},
                {"op": "mcp_call", "proto": "mcp", "method": "tools/call",
                 "params": {"name": "read_secrets", "arguments": {}}},
            ])
            return logger.path
        finally:
            farm.stop()

    def test_pot_sim_offline(self):
        buf = io.StringIO()
        tmp = tempfile.mkdtemp()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["pot", "--services", "ssh,http,mqtt", "--duration", "0",
                           "--sim", "--report-dir", tmp])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("services up:", out)
        self.assertIn("sim-attacker: actions=", out)

    def test_engage_reports_sources(self):
        log = str(self._attack_log())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["engage", "--log", log])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertGreaterEqual(data["sources"], 1)
        self.assertGreaterEqual(data["records"], 1)

    def test_dwell_iocs(self):
        log = str(self._attack_log())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["dwell", "--log", log, "--iocs"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertGreater(len(data["engagements"]), 0)
        self.assertTrue(data["iocs"])

    def test_report_writes_files(self):
        log = str(self._attack_log())
        tmp = tempfile.mkdtemp()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["report", "--log", log, "--report-dir", tmp])
        self.assertEqual(rc, 0)
        files = sorted(Path(tmp).glob("honeynet-engagements-*"))
        self.assertEqual(len(files), 2)
        self.assertTrue(files[0].suffix in (".json", ".md"))
        self.assertTrue(files[1].suffix in (".json", ".md"))

    def test_quarantine_scan_dry_run(self):
        log = str(self._attack_log())
        tmp = tempfile.mkdtemp()
        qfile = f"{tmp}/quarantine.json"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["quarantine", "kill", "--src", "203.0.113.7", "--file", qfile, "--confirm"])
        self.assertEqual(rc, 0)
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc = cli.main(["quarantine", "scan", "--log", log, "--file", qfile])
        self.assertEqual(rc, 0)
        data = json.loads(buf2.getvalue())
        self.assertGreater(data["interceptions_suppressed"], 0)

    def test_deceive_show_and_tripwire(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["deceive", "show"])
        self.assertEqual(rc, 0)
        grid = json.loads(buf.getvalue())
        self.assertIn("assets", grid)
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc = cli.main(["deceive", "tripwire", "--path", "/config/secrets.env"])
        self.assertEqual(rc, 0)
        data = json.loads(buf2.getvalue())
        self.assertTrue(data["is_tripwire"])
        self.assertTrue(str(data["token"]).startswith("HNYTKN-"))


if __name__ == "__main__":
    unittest.main()
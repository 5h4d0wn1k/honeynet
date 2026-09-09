import json
import tempfile
import unittest
from pathlib import Path

from honeynet.deceive import (
    KEY_PREFIX,
    TOKEN_PREFIX,
    DeceptionGrid,
    grid_from_dict,
    load_deception_grid,
    digest,
)


class TestDeceptionGrid(unittest.TestCase):
    def test_deterministic_honeytoken(self):
        grid = DeceptionGrid(seed="lab-demo-seed")
        self.assertEqual(grid.honeytoken_for("/a"), grid.honeytoken_for("/a"))
        self.assertEqual(grid.honeytoken_for("/a"), TOKEN_PREFIX + digest("lab-demo-seed", "/a"))

    def test_token_is_runtime_constructed_placeholder(self):
        grid = DeceptionGrid(seed="fixture-seed")
        token = grid.honeytoken_for("/config/secrets.env")
        self.assertTrue(token.startswith("HNYTKN-"))
        self.assertTrue(all(c in "0123456789ABCDEF" for c in token[len(TOKEN_PREFIX):]))

    def test_tripwire_paths(self):
        grid = DeceptionGrid()
        self.assertTrue(grid.is_tripwire("/config/secrets.env"))
        self.assertFalse(grid.is_tripwire("/"))

    def test_asset_lookup(self):
        grid = DeceptionGrid()
        asset = grid.asset_for("/admin/login.php")
        self.assertEqual(asset["kind"], "admin_page")
        self.assertIsNone(grid.asset_for("/nope"))

    def test_default_fake_keys_prefix(self):
        grid = DeceptionGrid(seed="x")
        for key in grid.fake_keys:
            self.assertTrue(key.startswith("hn_lab_"))

    def test_fake_creds_are_plain_placeholders(self):
        grid = DeceptionGrid()
        rows = grid.fake_creds
        self.assertGreaterEqual(len(rows), 1)
        self.assertIn(rows[0]["username"], {"admin", "root"})

    def test_leak_topic_match(self):
        grid = DeceptionGrid()
        self.assertTrue(grid.is_leak_topic("telemetry/edge/sensor-1"))
        self.assertTrue(grid.is_leak_topic("controllers/gw-2/config"))
        self.assertFalse(grid.is_leak_topic("firmware/a/b"))

    def test_fake_telemetry_mentions_topic(self):
        grid = DeceptionGrid()
        tl = json.loads(grid.fake_telemetry("telemetry/edge/sensor-9"))
        self.assertIn("edge/sensor-9", tl["sensor"])
        self.assertIn("gateway", tl)

    def test_mcp_tool_catalogue(self):
        grid = DeceptionGrid()
        names = [t["name"] for t in grid.tool_catalogue()]
        self.assertIn("read_secrets", names)
        self.assertIn("run_command", names)

    def test_json_roundtrip(self):
        grid = DeceptionGrid(seed="s")
        d = grid.to_dict()
        grid2 = grid_from_dict(d)
        self.assertEqual(grid2.honeytoken_for("/x"), grid.honeytoken_for("/x"))
        self.assertEqual(grid2.fake_keys, grid.fake_keys)

    def test_save_and_load_json(self):
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "grid.json"
        grid = DeceptionGrid(seed="zz")
        grid.save(str(path))
        loaded = load_deception_grid(str(path), {})
        self.assertEqual(loaded.honeytoken_for("/config/secrets.env"),
                         grid.honeytoken_for("/config/secrets.env"))

    def test_save_and_load_yaml(self):
        import yaml
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "grid.yaml"
        grid = DeceptionGrid(seed="zy")
        grid.save(str(path))
        loaded = load_deception_grid(str(path), {})
        self.assertEqual(loaded.seed, "zy")

    def test_load_from_config_defaults(self):
        grid = load_deception_grid(None, {})
        self.assertTrue(grid.is_tripwire("/secret/api-tokens.txt"))


if __name__ == "__main__":
    unittest.main()
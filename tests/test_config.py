import json
import tempfile
import unittest
from pathlib import Path

from honeynet.config import default_config, load_config


class TestConfig(unittest.TestCase):
    def test_defaults_are_lab_safe(self):
        cfg = default_config()
        self.assertEqual(cfg["bind"], "127.0.0.1")
        self.assertIn("ssh", cfg["services"])
        self.assertIn("rfc5737_nets", cfg)
        self.assertEqual(cfg["sim"]["attacker_src"], "203.0.113.7")

    def test_json_config_merge(self):
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "cfg.json"
        path.write_text(json.dumps({"services": ["mqtt"], "deception": {"seed": "custom"}}))
        cfg = load_config(str(path))
        self.assertEqual(cfg["services"], ["mqtt"])
        self.assertEqual(cfg["deception"]["seed"], "custom")
        self.assertEqual(cfg["bind"], "127.0.0.1")  # default preserved

    def test_yaml_config_merge(self):
        import yaml
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "cfg.yaml"
        path.write_text(yaml.safe_dump({"bind": "127.0.0.1", "sim": {"attacker_src": "192.0.2.9"}}))
        cfg = load_config(str(path))
        self.assertEqual(cfg["sim"]["attacker_src"], "192.0.2.9")

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/config.json")

    def test_non_mapping_raises(self):
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "cfg.json"
        path.write_text("[1,2,3]")
        with self.assertRaises(ValueError):
            load_config(str(path))


if __name__ == "__main__":
    unittest.main()
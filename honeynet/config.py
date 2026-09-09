"""config.py — YAML/JSON configuration loading for honeynet.

Loads a config file (YAML or JSON) describing which honeypot services to run,
deception-grid seeds, dwell scoring weights, source attribution for lab runs,
and quarantine settings. Falls back to hardened defaults when absent. The
defaults never bind outside loopback and never reference production IP space.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import DEFAULT_BIND, RFC5737_NETS

DEFAULT_SERVICES = ["ssh", "http", "mqtt", "mcp", "telnet"]


def default_config() -> dict[str, Any]:
    return {
        "bind": DEFAULT_BIND,
        "services": DEFAULT_SERVICES,
        "ports": {},                       # proto -> fixed port (must be >=1024, loopback only)
        "attribution": {},                 # {physical_loopback_peer: lab_label} e.g. 127.0.0.1 -> 203.0.113.7
        "rfc5737_nets": list(RFC5737_NETS),
        "deception": {
            "seed": "lab-demo-seed",
            "root": "honeynet.lab",
            "assets": [],
            "fake_creds": [],
            "fake_keys": [],
            "mqtt_leak_topics": ["telemetry/edge/#", "controllers/+/config", "secret/secrets"],
        },
        "dwell": {
            "dwell_max_pts": 30,
            "actions_max_pts": 25,
            "protocol_bonus": 3,
            "flag_bonus": 5,
            "tripwire_bonus": 10,
        },
        "logger": {
            "dir": "reports/honeypot",
        },
        "quarantine": {
            "file": "reports/quarantine.json",
        },
        "report": {
            "dir": "reports",
        },
        "sim": {
            "attacker_src": "203.0.113.7",
            "attacker_ua": "sqlmap/1.7.2#stable (http://sqlmap.org)",
            "sleep": 0.1,
        },
    }


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load config from a YAML or JSON file, or return defaults."""
    defaults = default_config()

    if not path:
        return defaults

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    text = p.read_text()
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            raise RuntimeError("PyYAML is required to load .yaml configs")
    elif suffix in (".json", ""):
        data = json.loads(text)
    else:
        raise ValueError(f"Unsupported config extension: {suffix}")

    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping")

    return _deep_merge(defaults, data)


def _deep_merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base
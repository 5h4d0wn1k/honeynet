"""deceive.py — deception grid configurator.

Defines fake assets (URL paths, fake creds, fake API keys — all constructed at
runtime from a fixture seed, never committed), honeyplanted honeytokens backed
by tripwires, MQTT leak topics, and the MCP tool catalogue. Everything the
honeypots serve lives here and is built from non-secret placeholder seeds.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

TOKEN_PREFIX = "HNYTKN-"
KEY_PREFIX = "hn_lab_"

DEFAULT_ASSETS = [
    {"path": "/admin/login.php", "kind": "admin_page"},
    {"path": "/phpmyadmin/index.php", "kind": "phpmyadmin"},
    {"path": "/config/secrets.env", "kind": "honeytoken_file", "tripwire": True},
    {"path": "/secret/api-tokens.txt", "kind": "api_keys", "tripwire": True},
]

DEFAULT_CREDS = [
    {"username": "admin", "password": "Ch4ng3me-HYBRID-2026", "asset": "/admin/login.php"},
    {"username": "root", "password": "toor-lab-edge-42", "asset": "/phpmyadmin/index.php"},
]

DEFAULT_LEAK_TOPICS = ["telemetry/edge/#", "controllers/+/config", "secret/secrets"]


def _mqtt_topic_match(topic: str, pattern: str) -> bool:
    """Match an MQTT topic against a topic filter.

    ``#`` matches zero or more levels (including trailing ``/``),
    ``+`` matches exactly one level.
    """
    topic_levels = topic.split("/")
    pat_levels = pattern.split("/")
    ti = 0
    for pi, pp in enumerate(pat_levels):
        if pp == "#":
            return True
        if ti >= len(topic_levels):
            return False
        if pp == "+":
            ti += 1
            continue
        if pp != topic_levels[ti]:
            return False
        ti += 1
    return ti == len(topic_levels)


def digest(*parts: str, length: int = 16) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return h[:length].upper()


class DeceptionGrid:
    def __init__(
        self,
        assets: list[dict[str, Any]] | None = None,
        fake_creds: list[dict[str, Any]] | None = None,
        fake_keys: list[str] | None = None,
        leak_topics: list[str] | None = None,
        seed: str = "lab-demo-seed",
        root: str = "honeynet.lab",
    ) -> None:
        self.seed = seed
        self.root = root
        self.assets = assets or [dict(a) for a in DEFAULT_ASSETS]
        self.fake_creds = fake_creds or [dict(c) for c in DEFAULT_CREDS]
        self.leak_topics = list(leak_topics or DEFAULT_LEAK_TOPICS)
        self._key_prefix = KEY_PREFIX + digest(seed, "keys")[:6].lower() + "_"
        self.fake_keys = list(fake_keys or [
            self._key_prefix + digest(self.seed, "key", str(i))[:20]
            for i in range(3)
        ])

    # ── honeytokens (runtime-built from the fixture seed) ───────────────────
    def honeytoken_for(self, path: str) -> str:
        return TOKEN_PREFIX + digest(self.seed, path)

    def is_tripwire(self, path: str) -> bool:
        for asset in self.assets:
            if asset.get("path") == path and asset.get("tripwire"):
                return True
        return False

    def asset_for(self, path: str) -> dict[str, Any] | None:
        for asset in self.assets:
            if asset.get("path") == path:
                return asset
        return None

    def credential_for(self, asset: str) -> dict[str, str] | None:
        for cred in self.fake_creds:
            if cred.get("asset") == asset:
                return cred
        return None

    # ── fake pages ──────────────────────────────────────────────────────────
    def page_html(self, kind: str) -> str:
        if kind == "admin_page":
            cred = self.credential_for("/admin/login.php") or {}
            return (
                "<!DOCTYPE html><html><head><title>Honeynet Admin</title></head>"
                "<body><h1>Honeynet Operations Portal</h1>"
                "<form action='/admin/login.php' method='POST'>"
                f"<input name='user' placeholder='username' autocomplete='off'/>"
                f"<input name='pass' type='password' placeholder='password'/>"
                "<button type='submit'>Sign in</button></form>"
                f"<p style='font-size:10px;color:#666'>fixture cred: {cred.get('username', '?')}:******** (simulated)</p>"
                "</body></html>"
            )
        if kind == "phpmyadmin":
            return (
                "<!DOCTYPE html><html><head><title>phpMyAdmin - Error</title></head>"
                "<body><h1>Welcome to phpMyAdmin</h1><p>5.2.1 (simulated)</p>"
                "<form action='/phpmyadmin/index.php' method='POST'>"
                "<input name='pma_username' placeholder='Username'/>"
                "<input name='pma_password' type='password' placeholder='Password'/>"
                "<input type='hidden' name='server' value='1'/>"
                "<button type='submit'>Log in</button></form></body></html>"
            )
        if kind == "honeytoken_file":
            token = self.honeytoken_for("/config/secrets.env")
            return (
                "HONEYNET_EDGE_TOKEN=" + token + "\n"
                "EDGE_ENDPOINT=https://edge." + self.root + "/v1/ingest\n"
            )
        if kind == "api_keys":
            return "\n".join(f"API_KEY_{i}={k}" for i, k in enumerate(self.fake_keys)) + "\n"
        # login (default)
        return (
            "<!DOCTYPE html><html><head><title>Sign in</title></head>"
            "<body><h1>Sign in to honeynet.lab</h1>"
            "<form action='/admin/login.php' method='POST'>"
            "<input name='user' placeholder='Username'/>"
            "<input name='pass' type='password' placeholder='Password'/>"
            "<button type='submit'>Log in</button></form></body></html>"
        )

    # ── MQTT leak game ──────────────────────────────────────────────────────
    def is_leak_topic(self, topic: str) -> bool:
        return any(_mqtt_topic_match(topic, pat) for pat in self.leak_topics)

    def fake_telemetry(self, topic: str) -> str:
        sensor = topic.replace("#", "edge/sensor-01").replace("+", "gw-2")
        return json.dumps({
            "sensor": sensor,
            "gateway": "lab-gw-02",
            "vlan": 202,
            "firmware": "v4.3.1",
            "temp_c": 41.2,
            "latency_ms": 12,
            "uplink": "edge://" + self.root,
            "last_seen": "2026-09-09T00:00:00Z",
        })

    # ── MCP (json-rpc) tool catalogue ───────────────────────────────────────
    def tool_catalogue(self) -> list[dict[str, Any]]:
        return [
            {"name": "read_secrets", "description": "Read a secrets path (simulated)", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "list_credentials", "description": "List stored credentials (simulated)", "inputSchema": {"type": "object"}},
            {"name": "run_command", "description": "Execute a command on the edge host (simulated)", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
            {"name": "query_database", "description": "Run a SQL query (simulated)", "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}}},
            {"name": "get_flags", "description": "Retrieve deployment flags (simulated)", "inputSchema": {"type": "object"}},
        ]

    def fake_tool_result(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "read_secrets":
            return {"secrets": [self.honeytoken_for("/config/secrets.env"), self.fake_keys[0]], "source": "simulated"}
        if tool == "list_credentials":
            return {"credentials": [{"user": c["username"], "asset": c["asset"]} for c in self.fake_creds]}
        if tool == "run_command":
            cmd = args.get("command", "id")
            return {"exit": 0, "stdout": f"uid=0(root) gid=0(root) ({cmd!r} simulated)"}
        if tool == "query_database":
            return {"rows": [{"table": "users", "rows": 1337, "note": "simulated"}]}
        if tool == "get_flags":
            return {"flags": ["flag{" + digest(self.seed, "flag")[:12] + "}"], "note": "simulated"}
        return {"result": "ok", "tool": tool, "note": "simulated"}

    # ── serialisation ───────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "root": self.root,
            "assets": self.assets,
            "fake_creds": self.fake_creds,
            "fake_keys": self.fake_keys,
            "leak_topics": self.leak_topics,
        }

    def save(self, path: str) -> str:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml
            except ImportError:
                raise RuntimeError("PyYAML is required to write YAML grids")
            p.write_text(yaml.safe_dump(self.to_dict(), sort_keys=False))
        else:
            p.write_text(json.dumps(self.to_dict(), indent=2))
        return str(p)


def grid_from_dict(data: dict[str, Any]) -> DeceptionGrid:
    return DeceptionGrid(
        assets=data.get("assets"),
        fake_creds=data.get("fake_creds"),
        fake_keys=data.get("fake_keys"),
        leak_topics=data.get("leak_topics"),
        seed=data.get("seed", "lab-demo-seed"),
        root=data.get("root", "honeynet.lab"),
    )


def load_deception_grid(path: str | None, cfg: dict[str, Any] | None = None) -> DeceptionGrid:
    """Load a grid from a YAML/JSON file if given, else build from config defaults."""
    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Deception grid not found: {path}")
        if p.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(p.read_text())
            except ImportError:
                raise RuntimeError("PyYAML is required to load .yaml grids")
        else:
            data = json.loads(p.read_text())
        if not isinstance(data, dict):
            raise ValueError("Deception grid must be a mapping")
        return grid_from_dict(data)

    deception = (cfg or {}).get("deception", {})
    grid = DeceptionGrid(
        assets=deception.get("assets") or None,
        fake_creds=deception.get("fake_creds") or None,
        fake_keys=deception.get("fake_keys") or None,
        leak_topics=deception.get("mqtt_leak_topics") or None,
        seed=deception.get("seed", "lab-demo-seed"),
        root=deception.get("root", "honeynet.lab"),
    )
    return grid
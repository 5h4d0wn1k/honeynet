"""quarantine.py — mark a source as 'kill' and filter it out of the feed.

Sources can only ever be RFC 5737 test-net or loopback placeholders — the tool
refuses to quarantine anything on a real address range. Once marked, `kill`
logs are persisted (reports/quarantine.json) and future interactions from that
source are filtered out of engagement/report views. Filtering is dry by
default: it tells you the interceptions it *would* make unless --confirm.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import LAB_HOSTS, RFC5737_NETS
from .logger import utc_now_iso


def is_lab_source(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if obj.is_loopback:
        return True
    for net in RFC5737_NETS:
        if obj in ipaddress.ip_network(net):
            return True
    return False


class Quarantine:
    def __init__(self, path: str | None = None, dry_run: bool = True) -> None:
        self.path = Path(path) if path else Path("reports") / "quarantine.json"
        self.dry_run = dry_run
        self._entries: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            if isinstance(data.get("quarantined"), dict):
                self._entries = data["quarantined"]
        except (json.JSONDecodeError, OSError):
            self._entries = {}

    def _persist(self) -> None:
        if self.dry_run:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"quarantined": self._entries, "policy": "RFC5737-test-net/loopback only"}
        self.path.write_text(json.dumps(payload, indent=2))

    def mark_kill(self, src: str, reason: str | None = None, by: str = "5h4d0wn1k") -> dict[str, Any]:
        if not is_lab_source(src):
            raise ValueError(f"Refusing to quarantine non-lab source {src!r} (RFC5737/loopback required)")
        with self._lock:
            was = src in self._entries
            self._entries[src] = {
                "status": "kill",
                "since": utc_now_iso(),
                "reason": reason or "simulated lab threat",
                "by": by,
                "dry_run": self.dry_run,
            }
            first = not was
            if not self.dry_run:
                self._persist()
        return {"src": src, "marked": True, "dry_run": self.dry_run, "first": first}

    def unmark(self, src: str) -> dict[str, Any]:
        with self._lock:
            removed = self._entries.pop(src, None) is not None
            if not self.dry_run:
                self._persist()
        return {"src": src, "removed": removed, "dry_run": self.dry_run}

    def is_killed(self, src: str) -> bool:
        with self._lock:
            entry = self._entries.get(src)
            return bool(entry) and entry.get("status") == "kill"

    def status(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{"src": src, **entry} for src, entry in sorted(self._entries.items())]

    def killed_sources(self) -> list[str]:
        return [e["src"] for e in self.status()]

    def filter_interactions(
        self, records: Iterable[dict[str, Any]], fail_open: bool = False
    ) -> list[dict[str, Any]]:
        """Return only interactions NOT originating from a quarantined source."""
        out = []
        for r in records:
            src = str(r.get("src", ""))
            killed = self.is_killed(src)
            if killed and not fail_open:
                continue
            out.append(r)
        return out

    def interceptions(self, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """List (affirmatively) the interactions a kill would suppress."""
        return [
            r for r in records
            if self.is_killed(str(r.get("src", "")))
        ]
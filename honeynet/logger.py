"""logger.py — shared JSONL interaction logger.

Every attacker interaction across all honeypot protocols lands in a single
append-only JSONL stream under reports/honeypot/. Records are thread-safe,
UTC-timestamped, and readable back for engagement tracking, dwell/risk
scoring, replay timelines, quarantine filtering and report generation.

Record schema (one JSON object per line):
    {
      "ts":      ISO-8601 UTC timestamp,
      "src":     effective source (lab attribution label or loopback peer),
      "peer":    physical peer as seen by the socket,
      "port":    honeypot listener port,
      "proto":   service protocol (ssh, http, telnet, smtp, vnc, mqtt, mcp),
      "event":   event name,
      "data":    event-specific payload,
      "direction": "in" (from attacker) | "out" (from honeypot)
    }
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

IN = "in"
OUT = "out"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InteractionLogger:
    def __init__(self, log_dir: str | None = None, name: str = "interactions") -> None:
        self.base = Path(log_dir) if log_dir else Path("reports") / "honeypot"
        self.base.mkdir(parents=True, exist_ok=True)
        self.path = self.base / f"{name}.jsonl"
        self._lock = threading.Lock()

    def log(
        self,
        proto: str,
        src: str,
        port: int,
        event: str,
        data: dict[str, Any] | None = None,
        peer: str | None = None,
        direction: str = IN,
    ) -> dict[str, Any]:
        """Append one interaction record and return it."""
        record = {
            "ts": utc_now_iso(),
            "src": src,
            "peer": peer or src,
            "port": int(port),
            "proto": proto,
            "event": event,
            "data": data or {},
            "direction": direction,
        }
        line = json.dumps(record, default=str, sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return record

    def read(self) -> list[dict[str, Any]]:
        """Read every interaction record in append order."""
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self._lock:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def for_source(self, src: str) -> list[dict[str, Any]]:
        return [r for r in self.read() if r.get("src") == src]

    def count(self, proto: str | None = None, src: str | None = None) -> int:
        n = 0
        for r in self.read():
            if proto and r.get("proto") != proto:
                continue
            if src and r.get("src") != src:
                continue
            n += 1
        return n

    def clear(self) -> None:
        with self._lock:
            if self.path.exists():
                self.path.unlink()


def describe(record: dict[str, Any]) -> str:
    """Human-readable one-line summary of a record (used in replay/reports)."""
    data = record.get("data") or {}
    payload = ""
    if record.get("event") == "auth-attempt":
        payload = f" {data.get('username', '?')}:{data.get('password', '?')}"
    elif record.get("event") == "subscribe":
        payload = f" topic={data.get('topic', '?')}"
    elif record.get("event") == "tool-call":
        payload = f" tool={data.get('tool', '?')}"
    elif record.get("event") == "request":
        payload = f" {data.get('method', '?')} {data.get('path', '?')}"
    elif record.get("event") in ("publish", "tripwire", "auth-rejected", "honeytoken-served"):
        for key in ("topic", "path", "message"):
            if data.get(key) is not None:
                payload = f" {key}={data[key]}"
                break
    return f"{record.get('ts', '')} [{record.get('direction', 'in')}] {record.get('proto', '?')} {record.get('event', '?')}{payload} (src={record.get('src', '?')})"
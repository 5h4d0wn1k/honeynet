"""engage.py — engagement tracker + attack fingerprinting.

Groups interaction records by effective source into session objects, measures
dwell time (first/last seen), and fingerprints the attack: credential reuse,
tool-signature user agents, and probing path patterns. Feeds the dwell/risk
scorer and the report generator.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

TOOL_UAS = [
    "sqlmap", "nmap", "masscan", "zgrab", "nikto", "ffuf", "dirb",
    "gobuster", "nuclei", "wpscan", "hydra", "medusa", "metasploit",
    "nessus", "awvs", "acunetix", "httpx", "python-requests", "curl/",
    "wget/", "httpie",
]

PATH_PATTERNS = [
    ("admin", r"/admin"),
    ("phpmyadmin", r"phpmyadmin"),
    ("traversal", r"\.\./"),
    ("dotenv", r"\.env"),
    ("wp-scan", r"wp-"),
    ("config-probe", r"config\.|/config/"),
    ("backup-probe", r"backup|\.bak|\.sql"),
    ("secret-probe", r"/secret|secrets|api-keys"),
    ("passwd-probe", r"passwd|shadow"),
]

METADATA_EVENTS = {"connect", "disconnect", "banner-sent", "peer-rejected", "handler-error"}
ATTACKER_ACTIONS = frozenset({
    "auth-attempt", "auth-rejected", "session-input", "client-banner",
    "request", "params", "tripwire", "asset-served", "login-page", "not-found",
    "honeytoken-served", "connect-attempt", "subscribe", "publish", "verb",
    "verb-reply", "jsonrpc-request", "tool-call", "jsonrpc-method", "malformed",
})


def parse_ts(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        import time as _time
        dt = dt.replace(tzinfo=_time.timezone.utc)
    return dt


class Engagement:
    def __init__(self, src: str) -> None:
        self.src = src
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.events: list[dict[str, Any]] = []
        self.protocols: set[str] = set()
        self.credentials: set[tuple[str, str]] = set()
        self.credential_counts: dict[tuple[str, str], int] = {}
        self.user_agents: dict[str, int] = {}
        self.paths: dict[str, int] = {}
        self.topics: set[str] = set()
        self.tools: set[str] = set()
        self.tripwires: list[dict[str, Any]] = []
        self.flags: set[str] = set()

    def add(self, record: dict[str, Any]) -> None:
        ts = parse_ts(record["ts"])
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts
        self.events.append(record)
        proto = record.get("proto", "?")
        self.protocols.add(proto)
        event = record.get("event", "")
        data = record.get("data") or {}

        if event == "auth-attempt":
            cred = (str(data.get("username", "")), str(data.get("password", "")))
            self._note_credential(cred)
        elif event == "request":
            ua = str(data.get("user_agent", "")).strip()
            if ua:
                self.user_agents[ua] = self.user_agents.get(ua, 0) + 1
            path = str(data.get("path", ""))
            if path:
                self.paths[path] = self.paths.get(path, 0) + 1
        elif event == "params":
            path = str(data.get("path", ""))
            if path:
                self.paths[path] = self.paths.get(path, 0) + 1
            params = data.get("params") or {}
            if isinstance(params, dict):
                for uname_key, pwd_key in (("user", "pass"), ("username", "password"), ("user", "password")):
                    if uname_key in params and pwd_key in params:
                        self._note_credential((str(params[uname_key]), str(params[pwd_key])))
                        break
        elif event == "subscribe":
            topic = str(data.get("topic", ""))
            if topic:
                self.topics.add(topic)
        elif event == "tool-call":
            tool = str(data.get("tool", ""))
            if tool:
                self.tools.add(tool)
        elif event == "tripwire":
            path = str(data.get("path", ""))
            self.tripwires.append({"path": path, "token": str(data.get("token", ""))})

    def _note_credential(self, cred: tuple[str, str]) -> None:
        if cred not in self.credential_counts:
            self.credentials.add(cred)
            self.credential_counts[cred] = 0
        self.credential_counts[cred] += 1

    def dwell_seconds(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    def action_count(self) -> int:
        return sum(1 for e in self.events if e.get("event") not in METADATA_EVENTS)

    def summary(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "dwell_seconds": round(self.dwell_seconds(), 3),
            "actions": self.action_count(),
            "protocols": sorted(self.protocols),
            "user_agents": list(self.user_agents),
            "paths": [{"path": p, "count": c} for p, c in sorted(self.paths.items())],
            "topics": sorted(self.topics),
            "tools": sorted(self.tools),
            "tripwires": self.tripwires,
            "flags": sorted(self.flags),
        }


def flag_uas(eng: Engagement) -> None:
    for ua in eng.user_agents:
        low = ua.lower()
        for sig in TOOL_UAS:
            if sig in low:
                eng.flags.add(f"tool-ua:{sig.rstrip('/')}")
                break


def flag_paths(eng: Engagement) -> None:
    for path in eng.paths:
        low = path.lower()
        for label, pattern in PATH_PATTERNS:
            import re
            if re.search(pattern, low):
                eng.flags.add(f"path-probe:{label}")


def flag_creds(eng: Engagement) -> None:
    reused = [f"{u}:{p}" for (u, p), c in eng.credential_counts.items() if c >= 2]
    distinct_attempts = len(eng.credentials)
    if reused:
        eng.flags.add(f"credential-reuse:{','.join(sorted(reused)[:2])}")
    elif distinct_attempts >= 3:
        eng.flags.add(f"credential-stuffing:{distinct_attempts}")


def flag_tripwires(eng: Engagement) -> None:
    if eng.tripwires:
        eng.flags.add("honeytoken-tripwire")


def fingerprint_engagement(eng: Engagement) -> Engagement:
    eng.flags.clear()
    flag_uas(eng)
    flag_paths(eng)
    flag_creds(eng)
    flag_tripwires(eng)
    return eng


class EngagementTracker:
    def __init__(self, auto_fingerprint: bool = True) -> None:
        self._engagements: dict[str, Engagement] = {}
        self.auto_fingerprint = auto_fingerprint

    def observe(self, record: dict[str, Any]) -> Engagement:
        src = str(record.get("src", "unknown"))
        eng = self._engagements.setdefault(src, Engagement(src))
        eng.add(record)
        if self.auto_fingerprint:
            fingerprint_engagement(eng)
        return eng

    def observe_many(self, records: Iterable[dict[str, Any]]) -> None:
        for r in records:
            self.observe(r)

    def engagements(self, fingerprints: bool = False) -> list[Engagement]:
        if fingerprints:
            for eng in self._engagements.values():
                fingerprint_engagement(eng)
        return list(self._engagements.values())

    def results(self, fingerprints: bool = True) -> list[dict[str, Any]]:
        return [fingerprint_engagement(e).summary() for e in self.engagements(fingerprints)]


def tracker_from_records(records: Iterable[dict[str, Any]]) -> EngagementTracker:
    tracker = EngagementTracker()
    tracker.observe_many(records)
    return tracker
"""sim.py — attacker SIMULATOR.

A scripted, offline attacker that connects to the real honeypot farm with real
loopback sockets and performs plausible attack steps: SSH banner + credential
attempt, HTTP GET and credential POST, tripwire fetch, MQTT subscribe to a leak
topic, MCP tools/call, telnet commands, SMTP verbs and a VNC handshake. Used by
tests and `--demo` to prove detection end-to-end.
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any
from urllib.parse import urlencode

from .deceive import DeceptionGrid
from .engage import EngagementTracker, tracker_from_records
from .logger import InteractionLogger
from .protocol import (
    http_bytes,
    jsonrpc_request,
    mqtt_packet,
    mqtt_utf8,
    recv_exact,
    recv_line,
    recv_until,
)

DEFAULT_UA = "sqlmap/1.7.2#stable (http://sqlmap.org)"
DEFAULT_SRC = "203.0.113.7"


def read_mqtt_packet(sock: socket.socket, timeout: float = 3.0) -> tuple[int, bytes] | None:
    sock.settimeout(timeout)
    try:
        head = recv_exact(sock, 1, timeout=timeout)
    except (socket.timeout, OSError):
        return None
    if not head:
        return None
    length_field = bytearray()
    while True:
        lb = sock.recv(1)
        if not lb:
            return None
        length_field.append(lb[0])
        if not lb[0] & 0x80:
            break
    from .protocol import decode_remaining_length
    (rem_len, _) = decode_remaining_length(bytes(length_field), 0)
    body = b""
    if rem_len:
        body = recv_exact(sock, rem_len, timeout=timeout)
    return head[0], body


def _recv_http(sock: socket.socket, timeout: float = 5.0) -> tuple[str, dict[str, str], bytes]:
    from .protocol import recv_until
    sock.settimeout(timeout)
    head = recv_until(sock, b"\r\n\r\n")
    pieces = head.split(b"\r\n\r\n", 1)
    status_line = pieces[0].split(b"\r\n", 1)[0].decode("latin-1", "replace")
    headers: dict[str, str] = {}
    body = pieces[1] if len(pieces) > 1 else b""
    for ln in pieces[0].split(b"\r\n")[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().decode("latin-1", "replace").lower()] = v.strip().decode("latin-1", "replace")
    cl = int(headers.get("content-length", "0") or 0)
    if cl and len(body) < cl:
        body += recv_exact(sock, cl - len(body))
    return status_line, headers, body


class Attacker:
    def __init__(self, name: str = "lab-attacker", src: str = DEFAULT_SRC, user_agent: str = DEFAULT_UA) -> None:
        self.name = name
        self.src = src
        self.user_agent = user_agent

    # ── concrete attack primitives ─────────────────────────────────────────
    def ssh_login(self, host: str, port: int, username: str, password: str) -> tuple[bool, str]:
        sock = socket.create_connection((host, port), timeout=5)
        try:
            banner = recv_line(sock, timeout=5)
            sock.sendall(b"SSH-2.0-OpenSSH_9.1p1 Debian-2\r\n")
            prompt1 = recv_until(sock, b"login: ", timeout=5)
            sock.sendall((username + "\r\n").encode("utf-8"))
            prompt2 = recv_until(sock, b"Password: ", timeout=5)
            sock.sendall((password + "\r\n").encode("utf-8"))
            denial = recv_line(sock, timeout=5)
            ok = b"Permission denied" in denial
            return ok, f"{username}@{host}:{port} rejected (banner={banner.strip().decode(errors='replace')!r})"
        finally:
            sock.close()

    def http_request(self, host: str, port: int, method: str, path: str,
                     params: dict[str, str] | None = None, ua: str | None = None) -> tuple[bool, str]:
        body = urlencode(params) if params else ""
        headers = {"User-Agent": ua or self.user_agent, "Content-Type": "application/x-www-form-urlencoded"}
        sock = socket.create_connection((host, port), timeout=5)
        try:
            sock.sendall(http_bytes(method, path, headers, body))
            status, hdrs, resp = _recv_http(sock)
            return status.startswith("HTTP/1.1 200"), f"{status} body={len(resp)}B"
        finally:
            sock.close()

    def mqtt_subscribe(self, host: str, port: int, topic: str, client_id: str = "lab-attacker") -> tuple[bool, str]:
        conn_vh = mqtt_utf8("MQTT") + bytes([4, 0x02]) + (60).to_bytes(2, "big") + mqtt_utf8(client_id)
        sock = socket.create_connection((host, port), timeout=5)
        try:
            sock.sendall(mqtt_packet(0x10, conn_vh))
            connack = recv_exact(sock, 4, timeout=5)
            if connack[:2] != b"\x20\x02":
                return False, "no CONNACK"
            sub_body = (1).to_bytes(2, "big") + mqtt_utf8(topic) + b"\x00"
            sock.sendall(mqtt_packet(0x82, sub_body))
            got = None
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                pkt = read_mqtt_packet(sock, timeout=1.0)
                if pkt is None:
                    break
                if pkt[0] == 0x90:
                    got = ("SUBACK", pkt[1])
                    break
                got = ("PUBLISH", pkt[1])
                break
            if got is None:
                return False, f"no response for subscribe {topic}"
            return True, f"subscribe {topic} -> {got[0]}"
        finally:
            sock.close()

    def mcp_call(self, host: str, port: int, method: str, params: dict[str, Any] | None,
                 req_id: Any = 42) -> tuple[bool, str]:
        sock = socket.create_connection((host, port), timeout=5)
        try:
            sock.sendall(jsonrpc_request(req_id, method, params))
            resp = recv_line(sock, timeout=5)
            obj = json.loads(resp.decode("utf-8", "replace"))
            ok = "error" not in obj
            return ok, f"mcp {method} -> {'error' if 'error' in obj else 'result'}"
        finally:
            sock.close()

    def telnet_session(self, host: str, port: int, lines: list[str]) -> tuple[bool, str]:
        sock = socket.create_connection((host, port), timeout=5)
        try:
            banner = recv_until(sock, b"login: ", timeout=5)
            sent = 0
            for i, line in enumerate(lines):
                sock.sendall((line + "\r\n").encode("utf-8"))
                reply = recv_until(sock, b"Password: " if i == 0 else b"$ ", timeout=5)
                sent += 1
            return True, f"telnet sent {sent} verb(s)"
        finally:
            sock.close()

    def smtp_session(self, host: str, port: int, verbs: list[str]) -> tuple[bool, str]:
        sock = socket.create_connection((host, port), timeout=5)
        try:
            greeting = recv_line(sock, timeout=5)
            if not greeting.startswith(b"220 "):
                return False, f"no SMTP greeting: {greeting!r}"
            seen = 0
            for verb in verbs:
                sock.sendall((verb + "\r\n").encode("utf-8"))
                reply = recv_line(sock, timeout=5)
                seen += 1
                verb_upper = verb.split(" ", 1)[0].upper()
                if verb_upper == "EHLO":
                    parts = reply.splitlines()
                    while parts and parts[-1][:4] == b"250-":
                        more = recv_line(sock, timeout=3)
                        if not more:
                            break
                        reply += more
                        parts = reply.splitlines()
            return True, f"smtp sent {len(verbs)} verb(s)"
        finally:
            sock.close()

    def vnc_handshake(self, host: str, port: int) -> tuple[bool, str]:
        sock = socket.create_connection((host, port), timeout=5)
        try:
            version = recv_line(sock, timeout=5)
            if version.strip() != b"RFB 003.008":
                return False, f"unexpected RFB version {version!r}"
            sock.sendall(version)
            security = recv_exact(sock, 4, timeout=5)
            sock.sendall(b"\x00")  # choose "None" security
            result = recv_exact(sock, 4, timeout=5)
            return True, f"vnc handshake completed (security bytes={security.hex()})"
        finally:
            sock.close()

    # ── plan runner ─────────────────────────────────────────────────────────
    def run_plan(self, targets: dict[str, int], plan: list[dict[str, Any]]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for op in plan:
            if op.get("op") == "sleep":
                time.sleep(float(op.get("seconds", 0.1)))
                continue
            proto = op["proto"]
            port = targets.get(proto)
            if port is None:
                results.append({"op": op["op"], "ok": False, "note": f"no target for {proto}"})
                continue
            ok, note = self._dispatch(op, port)
            results.append({"op": op["op"], "proto": proto, "ok": bool(ok), "note": note})
        actions = sum(1 for r in results if r.get("ok"))
        return {
            "attacker": self.name,
            "src": self.src,
            "user_agent": self.user_agent,
            "steps": results,
            "actions_ok": actions,
            "actions_attempted": len(results),
        }

    def _dispatch(self, op: dict[str, Any], port: int) -> tuple[bool, str]:
        kind = op["op"]
        host = op.get("host", "127.0.0.1")
        if kind == "ssh":
            return self.ssh_login(host, port, op["username"], op["password"])
        if kind == "http_get":
            return self.http_request(host, port, "GET", op["path"], ua=op.get("ua"))
        if kind == "http_post":
            return self.http_request(host, port, "POST", op["path"], params=op.get("params"), ua=op.get("ua"))
        if kind == "mqtt_subscribe":
            return self.mqtt_subscribe(host, port, op["topic"])
        if kind == "mcp_call":
            return self.mcp_call(host, port, op["method"], op.get("params"))
        if kind == "telnet":
            return self.telnet_session(host, port, op.get("lines", []))
        if kind == "smtp":
            return self.smtp_session(host, port, op.get("verbs", []))
        if kind == "vnc":
            return self.vnc_handshake(host, port)
        return False, f"unknown op {kind}"


def standard_plan() -> list[dict[str, Any]]:
    return [
        {"op": "ssh", "proto": "ssh", "username": "root", "password": "Lab-demo-2026!"},
        {"op": "sleep", "seconds": 0.1},
        {"op": "http_get", "proto": "http", "path": "/"},
        {"op": "http_post", "proto": "http", "path": "/admin/login.php",
         "params": {"user": "root", "pass": "Lab-demo-2026!"}},
        {"op": "http_get", "proto": "http", "path": "/config/secrets.env"},
        {"op": "sleep", "seconds": 0.1},
        {"op": "mqtt_subscribe", "proto": "mqtt", "topic": "telemetry/edge/#"},
        {"op": "mcp_call", "proto": "mcp", "method": "tools/call",
         "params": {"name": "read_secrets", "arguments": {"path": "/etc/hosts"}}},
        {"op": "sleep", "seconds": 0.1},
        {"op": "telnet", "proto": "telnet", "lines": ["admin", "whoami"]},
        {"op": "smtp", "proto": "smtp",
         "verbs": ["EHLO attacker.example", "MAIL FROM:<root@attacker.local>",
                   "RCPT TO:<root@honeynet.lab>", "QUIT"]},
        {"op": "vnc", "proto": "vnc"},
    ]


def run_standard_attack(
    targets: dict[str, int],
    logger: InteractionLogger,
    deceive: DeceptionGrid | None = None,
    cfg: dict[str, Any] | None = None,
    plan: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the scripted attacker against a live farm and score what we caught.

    cfg: the "sim" section of config (attacker_src, attacker_ua).
    """
    cfg = cfg or {}
    attacker = Attacker(src=cfg.get("attacker_src", DEFAULT_SRC), user_agent=cfg.get("attacker_ua", DEFAULT_UA))
    result = attacker.run_plan(targets, plan or standard_plan())

    records = logger.read()
    tracker = tracker_from_records(records)
    engagements = tracker.engagements(fingerprints=True)

    from .dwell import build_iocs, dwell_stats, score_engagement, score_all
    from .logger import describe as describe_record

    engage_records = [e for e in engagements if e.src == attacker.src]
    primary = engage_records[0] if engage_records else (engagements[0] if engagements else None)
    scored = score_all(engagements)

    if primary is not None:
        scored_primary = score_engagement(primary)
        iocs = build_iocs(primary)
        dwell_s = primary.dwell_seconds()
        actions = primary.action_count()
    else:
        scored_primary = None
        iocs = []
        dwell_s = 0.0
        actions = 0

    replay = [describe_record(r) for r in sorted(records, key=lambda r: r["ts"])]

    return {
        "attacker": result,
        "dwell_seconds": round(dwell_s, 3),
        "actions_logged": actions,
        "engagements": len(engagements),
        "scored": scored,
        "risk": scored_primary["risk"] if scored_primary else None,
        "iocs": iocs,
        "replay": replay,
        "stats": dwell_stats(scored),
    }
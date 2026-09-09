"""protocol.py — wire-level helpers shared by services, sim and tests.

Keeps the raw framing (MQTT remaining-length encoding, HTTP request line
parsing, line/TLV socket reads) in one place so the honeypot services and the
attacker simulator/tests stay byte-for-byte compatible. 100% stdlib.
"""

from __future__ import annotations

import socket
from typing import Any

MAX_RECV = 1 << 20


def recv_until(
    sock: socket.socket,
    marker: bytes = b"\n",
    maxlen: int = MAX_RECV,
    timeout: float = 8.0,
) -> bytes:
    """Read from sock until marker appears (or timeout/maxlen)."""
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > maxlen:
            break
    return buf


def recv_line(sock: socket.socket, timeout: float = 8.0) -> bytes:
    return recv_until(sock, marker=b"\n", timeout=timeout)


def recv_exact(sock: socket.socket, n: int, timeout: float = 8.0) -> bytes:
    """Read exactly n bytes (may return early on EOF)."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def send_all(sock: socket.socket, data: bytes) -> int:
    return sock.sendall(data)


# ── MQTT 3.1.1 framing ───────────────────────────────────────────────────────
def mqtt_remaining_length(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def decode_remaining_length(data: bytes, pos: int = 0) -> tuple[int, int]:
    """Decode a MQTT remaining-length field from data at pos.

    Returns (value, next_pos). Raises ValueError on malformed input.
    """
    value = 0
    multiplier = 1
    consumed = 0
    while True:
        if pos + consumed >= len(data):
            raise ValueError("Malformed MQTT remaining length")
        byte = data[pos + consumed]
        consumed += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128
        if multiplier > 128 ** 4:
            raise ValueError("MQTT remaining length too long")
    return value, pos + consumed


def mqtt_packet(header: int, variable_payload: bytes) -> bytes:
    return bytes([header]) + mqtt_remaining_length(len(variable_payload)) + variable_payload


def mqtt_utf8(s: str) -> bytes:
    b = s.encode("utf-8")
    if len(b) > 0xFFFF:
        raise ValueError("MQTT UTF-8 string too long")
    return len(b).to_bytes(2, "big") + b


def parse_mqtt_subscribe(body: bytes) -> list[dict[str, Any]]:
    """Parse SUBSCRIBE variable header + payload into topic filter entries."""
    topics: list[dict[str, Any]] = []
    if len(body) < 2:
        return topics
    packet_id = int.from_bytes(body[:2], "big")
    pos = 2
    while pos < len(body):
        (tlen,) = (int.from_bytes(body[pos:pos + 2], "big"),)
        pos += 2
        topic = body[pos:pos + tlen].decode("utf-8", "replace")
        pos += tlen
        qos = body[pos] & 0x03 if pos < len(body) else 0
        pos += 1
        topics.append({"packet_id": packet_id, "topic": topic, "qos": qos})
    return topics


def parse_mqtt_connect(body: bytes) -> dict[str, Any]:
    """Parse CONNECT variable header + payload (best effort)."""
    info: dict[str, Any] = {"client_id": ""}
    if len(body) < 10:
        return info
    (plen,) = (int.from_bytes(body[:2], "big"),)
    if plen != 4 or body[2:6] != b"MQTT":
        return info
    info["level"] = body[6]
    flags = body[7]
    info["clean_session"] = bool(flags & 0x02)
    info["keepalive"] = int.from_bytes(body[8:10], "big")
    pos = 10
    if pos + 2 <= len(body):
        (clen,) = (int.from_bytes(body[pos:pos + 2], "big"),)
        pos += 2
        info["client_id"] = body[pos:pos + clen].decode("utf-8", "replace")
    return info


def parse_mqtt_publish(body: bytes) -> dict[str, Any]:
    """Parse a PUBLISH payload: topic name + application message."""
    if len(body) < 2:
        return {}
    (tlen,) = (int.from_bytes(body[:2], "big"),)
    topic = body[2:2 + tlen].decode("utf-8", "replace")
    payload = body[2 + tlen:].decode("utf-8", "replace")
    return {"topic": topic, "payload": payload}


# ── HTTP helpers ─────────────────────────────────────────────────────────────
def parse_http_request(head: bytes) -> tuple[str, str, str, dict[str, str], bytes]:
    """Parse an HTTP request head block.

    Returns (method, target, version, headers, body). Headers are lowercased.
    """
    parts = head.split(b"\r\n\r\n", 1)
    head_part = parts[0]
    body = parts[1] if len(parts) > 1 else b""
    lines = head_part.split(b"\r\n")
    if not lines:
        return "GET", "/", "HTTP/1.1", {}, body
    pieces = lines[0].decode("latin-1", "replace").split(" ", 2)
    method = pieces[0] if len(pieces) > 0 else "GET"
    target = pieces[1] if len(pieces) > 1 else "/"
    version = pieces[2] if len(pieces) > 2 else "HTTP/1.1"
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().decode("latin-1", "replace").lower()] = (
                v.strip().decode("latin-1", "replace")
            )
    return method, target, version, headers, body


def http_bytes(method: str, target: str, headers: dict[str, str], body: str = "") -> bytes:
    """Build a client HTTP request (used by sim/tests)."""
    lines = [f"{method} {target} HTTP/1.1"]
    merged: dict[str, str] = {"Host": "honeynet.lab", **headers}
    for k, v in merged.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    data = "\r\n".join(lines) + "\r\n\r\n"
    return data.encode("utf-8") + body.encode("utf-8")


# ── JSON-RPC framing (newline-delimited JSON over TCP) ───────────────────────
def jsonrpc_request(req_id: dict[str, Any] | int | str | None, method: str, params: Any = None) -> bytes:
    obj = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        obj["params"] = params
    return (json_dumps(obj) + "\n").encode("utf-8")


def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, separators=(",", ":"))
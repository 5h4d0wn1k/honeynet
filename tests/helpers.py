"""Shared helpers: real-loopback-socket clients for honeypot tests."""

import socket
import tempfile
from pathlib import Path

from honeynet.deceive import DeceptionGrid
from honeynet.engine import Farm
from honeynet.logger import InteractionLogger
from honeynet.protocol import (
    http_bytes,
    jsonrpc_request,
    mqtt_packet,
    mqtt_utf8,
    recv_exact,
    recv_line,
    recv_until,
)

ATTRIB = {"127.0.0.1": "203.0.113.7"}


def tmp_logger() -> InteractionLogger:
    return InteractionLogger(tempfile.mkdtemp(prefix="hntest-log-"))


def make_grid() -> DeceptionGrid:
    return DeceptionGrid(seed="lab-demo-seed")


def start_farm(protos, attribution=ATTRIB, deceive=None, logger=None):
    logger = logger or tmp_logger()
    farm = Farm(protos, logger=logger, deceive=deceive or make_grid(), attribution=attribution)
    farm.start()
    return farm, logger, farm.port_map()


# ── raw socket clients ───────────────────────────────────────────────────────
def ssh_exchange(port, username, password):
    """Perform a full banner + keyboard-interactive auth attempt."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        banner = recv_line(sock, timeout=5)
        sock.sendall(b"SSH-2.0-OpenSSH_9.1p1 Debian-2\r\n")
        prompt1 = recv_until(sock, b"login: ", timeout=5)
        sock.sendall((username + "\r\n").encode("utf-8"))
        prompt2 = recv_until(sock, b"Password: ", timeout=5)
        sock.sendall((password + "\r\n").encode("utf-8"))
        denial = recv_line(sock, timeout=5)
        return banner, prompt1, prompt2, denial
    finally:
        sock.close()


def http_request(port, method, path, body="", headers=None):
    """Send an HTTP request, return (status_line, response_headers, body)."""
    merged = {"User-Agent": "sqlmap/1.7.2#stable (http://sqlmap.org)"}
    if headers:
        merged.update(headers)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(http_bytes(method, path, merged, body))
        raw = recv_until(sock, b"\r\n\r\n", timeout=5)
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = lines[0].decode("latin-1", "replace")
        resp_headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                resp_headers[k.strip().decode("latin-1", "replace").lower()] = v.strip().decode("latin-1", "replace")
        body_bytes = rest
        cl = int(resp_headers.get("content-length", "0") or 0)
        if cl and len(body_bytes) < cl:
            body_bytes += recv_exact(sock, cl - len(body_bytes))
        return status, resp_headers, body_bytes.decode("utf-8", "replace")
    finally:
        sock.close()


class MqttClient:
    """Tiny MQTT 3.1.1 client for tests."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self._open = True

    def connect(self, client_id="lab-attacker"):
        vh = mqtt_utf8("MQTT") + bytes([4, 0x02]) + (60).to_bytes(2, "big") + mqtt_utf8(client_id)
        self.sock.sendall(mqtt_packet(0x10, vh))
        return recv_exact(self.sock, 4, timeout=5)

    def subscribe(self, topic, packet_id=1):
        body = packet_id.to_bytes(2, "big") + mqtt_utf8(topic) + b"\x00"
        self.sock.sendall(mqtt_packet(0x82, body))
        out = []
        while True:
            head = self.sock.recv(1)
            if not head:
                break
            rem = bytearray()
            while True:
                lb = self.sock.recv(1)
                if not lb:
                    break
                rem.append(lb[0])
                if not lb[0] & 0x80:
                    break
            from honeynet.protocol import decode_remaining_length
            (n, _) = decode_remaining_length(bytes(rem), 0)
            payload = recv_exact(self.sock, n, timeout=5) if n else b""
            out.append((head[0], payload))
            if head[0] == 0x90:
                break
        return out

    def ping(self):
        self.sock.sendall(b"\xc0\x00")
        return recv_exact(self.sock, 2, timeout=5)

    def disconnect(self):
        try:
            self.sock.sendall(b"\xe0\x00")
        except OSError:
            pass

    def close(self):
        if self._open:
            self._open = False
            try:
                self.sock.close()
            except OSError:
                pass


def mcp_call(port, reqs):
    """Send newline-delimited JSON-RPC requests; return parsed responses."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        out = []
        for rid, method, params in reqs:
            sock.sendall(jsonrpc_request(rid, method, params))
            line = recv_line(sock, timeout=5)
            import json as _json
            out.append((rid, _json.loads(line.decode("utf-8", "replace"))))
        return out
    finally:
        sock.close()
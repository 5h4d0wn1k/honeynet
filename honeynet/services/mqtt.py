"""mqtt.py — MQTT 3.1.1 topic-request honeypot.

Speaks just enough MQTT 3.1.1 framing to accept CONNECT, log SUBSCRIBE/PUBLISH
topics, and answer the deception "leak game": when an attacker subscribes to a
planted leak topic, the honeypot immediately serves a PUBLISH carrying fake
telemetry on that same (attacker-requested) topic. No real device is ever
contacted.
"""

from __future__ import annotations

import fnmatch
import socket
from typing import Any

from ..logger import OUT
from ..protocol import decode_remaining_length, parse_mqtt_connect, parse_mqtt_publish, parse_mqtt_subscribe, recv_exact
from .base import HoneypotService

CONNACK = b"\x20\x02\x00\x00"
SUBACK_HEADER = b"\x90"
PINGRESP = b"\xd0\x00"


def _mqtt_payload(packet: bytes) -> bytes:
    pos = 1
    _, pos = decode_remaining_length(packet, pos)
    return packet[pos:]


class MqttHoneypot(HoneypotService):
    proto = "mqtt"

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        while True:
            head = recv_exact(conn, 1, timeout=8.0)
            if not head:
                return

            first = head[0]

            # Read the remaining-length field (1-4 bytes, big-endian base-128).
            length_field = bytearray()
            while True:
                lb = recv_exact(conn, 1, timeout=8.0)
                if not lb:
                    return
                length_field.append(lb[0])
                if not lb[0] & 0x80:
                    break
                if len(length_field) > 4:
                    self.logger.log(self.proto, src, self.port, "malformed", {"reason": "remaining length too long"})
                    return
            try:
                (rem_len, _) = decode_remaining_length(bytes(length_field), 0)
            except ValueError:
                self.logger.log(self.proto, src, self.port, "malformed", {"reason": "bad remaining length"})
                return
            payload = b""
            if rem_len:
                payload = recv_exact(conn, rem_len, timeout=8.0)

            kind = first & 0xF0
            if kind == 0x10:  # CONNECT
                info = parse_mqtt_connect(payload)
                self.logger.log(self.proto, src, self.port, "connect-attempt", info)
                conn.sendall(CONNACK)
                self.logger.log(self.proto, src, self.port, "connack-sent", {}, direction=OUT)
            elif kind == 0x80:  # SUBSCRIBE (fixed header 0x82)
                topics = parse_mqtt_subscribe(payload)
                for entry in topics:
                    topic = entry["topic"]
                    is_leak = self.deceive.is_leak_topic(topic)
                    self.logger.log(self.proto, src, self.port, "subscribe", {
                        "topic": topic,
                        "qos": entry["qos"],
                        "leak": is_leak,
                    })
                    if is_leak:
                        self._leak(conn, src, topic)
                packet_id = topics[0]["packet_id"] if topics else _packet_id_from_body(payload)
                conn.sendall(SUBACK_HEADER + mqtt_suback(packet_id, len(topics)))
                self.logger.log(self.proto, src, self.port, "suback-sent", {"topics": len(topics)}, direction=OUT)
            elif kind == 0x30:  # PUBLISH (from attacker)
                info = parse_mqtt_publish(payload)
                self.logger.log(self.proto, src, self.port, "publish", {"incoming": True, **info})
            elif kind == 0xC0:  # PINGREQ
                conn.sendall(PINGRESP)
                self.logger.log(self.proto, src, self.port, "pingresp-sent", {}, direction=OUT)
            elif kind == 0xE0:  # DISCONNECT
                self.logger.log(self.proto, src, self.port, "disconnect-request", {})
                return
            else:
                self.logger.log(self.proto, src, self.port, "unsupported", {"packet_type": hex(kind)})
                return

    def _leak(self, conn: socket.socket, src: str, topic: str) -> None:
        """Attacker subscribed to a planted leak topic: serve fake telemetry."""
        telemetry = self.deceive.fake_telemetry(topic)
        payload = encode_publish(topic, telemetry)
        conn.sendall(payload)
        self.logger.log(self.proto, src, self.port, "publish", {
            "outgoing": True,
            "fake": True,
            "topic": topic,
            "payload": telemetry,
        }, direction=OUT)


def mqtt_suback(packet_id: int, count: int) -> bytes:
    from ..protocol import mqtt_remaining_length
    body = packet_id.to_bytes(2, "big") + bytes([0x00]) * count
    return mqtt_remaining_length(len(body)) + body


def encode_publish(topic: str, payload: str) -> bytes:
    """Server-side PUBLISH (QoS 0) used for the fake telemetry leak."""
    from ..protocol import mqtt_packet, mqtt_utf8
    body = mqtt_utf8(topic) + payload.encode("utf-8")
    return mqtt_packet(0x30, body)


def _packet_id_from_body(payload: bytes) -> int:
    if len(payload) >= 2:
        return int.from_bytes(payload[:2], "big")
    return 1
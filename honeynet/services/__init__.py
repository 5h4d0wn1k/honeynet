"""honeynet.services — pluggable honeypot protocol handlers.

Registry maps a protocol name to a HoneypotService subclass. All services bind
loopback ephemeral ports, share one InteractionLogger and optionally a
DeceptionGrid. Attackers are simulated locally (tests/demo); nothing here ever
talks to a real host.
"""

from __future__ import annotations

from ..deceive import DeceptionGrid
from ..logger import InteractionLogger
from .base import HoneypotService
from .http import HttpHoneypot
from .mcp import JsonRpcMcpHoneypot
from .mqtt import MqttHoneypot
from .ssh import SshHoneypot
from .textbanner import SmtpHoneypot, TelnetHoneypot, VncMockHoneypot

PROTOCOLS = {
    "ssh": SshHoneypot,
    "http": HttpHoneypot,
    "telnet": TelnetHoneypot,
    "smtp": SmtpHoneypot,
    "vnc": VncMockHoneypot,
    "mqtt": MqttHoneypot,
    "mcp": JsonRpcMcpHoneypot,
    "jsonrpc": JsonRpcMcpHoneypot,
}

# Protocol -> logical deception family, used for demo/dashboard grouping.
FAMILIES = {
    "ssh": "ssh",
    "http": "http",
    "telnet": "telnet/smtp/vnc",
    "smtp": "telnet/smtp/vnc",
    "vnc": "telnet/smtp/vnc",
    "mqtt": "mqtt",
    "mcp": "json-rpc/mcp",
    "jsonrpc": "json-rpc/mcp",
}


def get_service_class(proto: str) -> type[HoneypotService]:
    if proto not in PROTOCOLS:
        raise ValueError(f"Unknown honeypot service: {proto!r}")
    return PROTOCOLS[proto]


def make_service(
    proto: str,
    logger: InteractionLogger,
    deceive: DeceptionGrid | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    attribution: dict[str, str] | None = None,
) -> HoneypotService:
    cls = get_service_class(proto)
    return cls(logger=logger, deceive=deceive, host=host, port=port, attribution=attribution)


__all__ = [
    "PROTOCOLS", "FAMILIES", "get_service_class", "make_service",
    "HoneypotService", "SshHoneypot", "HttpHoneypot", "TelnetHoneypot",
    "SmtpHoneypot", "VncMockHoneypot", "MqttHoneypot", "JsonRpcMcpHoneypot",
]
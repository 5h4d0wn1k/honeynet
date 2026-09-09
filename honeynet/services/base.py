"""base.py — HoneypotService base class and safety gates.

A service owns a real TCP listener on loopback (127.0.0.1) binding an
ephemeral port, an accept loop in a daemon thread, per-connection handler
threads, and a shared InteractionLogger. A safety gate refuses any
non-loopback bind and any peer that is not a loopback address; the only
"external" identity this tool understands is a configured RFC 5737 lab label
attributed to the loopback peer (see Farm.attribution).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Any

from .. import LAB_HOSTS
from ..deceive import DeceptionGrid
from ..logger import InteractionLogger


class SafetyError(Exception):
    """Raised when a config/operation would leave the sanctioned lab surface."""


def require_loopback(host: str) -> str:
    try:
        obj = ipaddress.ip_address(host)
    except ValueError:
        raise SafetyError(f"Bind address must be an IP literal, got {host!r}")
    if obj.is_loopback:
        return str(obj)
    raise SafetyError(f"Refusing to bind honeypot outside loopback: {host!r}")


def require_lab_peer(peer: str) -> None:
    try:
        obj = ipaddress.ip_address(peer)
    except ValueError:
        raise SafetyError(f"Peer is not an IP literal: {peer!r}")
    if obj.is_loopback:
        return
    raise SafetyError(f"Refusing to serve non-loopback peer: {peer!r}")


class HoneypotService:
    """Base class: one listener + accept loop + per-connection handler."""

    proto = "base"

    def __init__(
        self,
        logger: InteractionLogger,
        deceive: DeceptionGrid | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        attribution: dict[str, str] | None = None,
    ) -> None:
        self.host = host
        if port < 0 or port > 65535:
            raise SafetyError(f"Port out of range: {port}")
        self._requested_port = port
        self.logger = logger
        self.deceive = deceive or DeceptionGrid()
        self.attribution = attribution or {}
        self.socket: socket.socket | None = None
        self._stop = threading.Event()
        self._looper: threading.Thread | None = None
        self._handlers: list[threading.Thread] = []
        self._local = threading.local()
        self.port = port

    def _log(self, src: str, event: str, data: dict[str, Any] | None = None,
             direction: str = "in") -> dict[str, Any]:
        """Log with the connection-local physical peer attached."""
        return self.logger.log(
            self.proto, src, self.port, event, data,
            peer=getattr(self._local, "peer", None) or src,
            direction=direction,
        )

    def start(self) -> int:
        """Bind, listen and start the accept loop. Returns the bound port."""
        if self.socket is not None:
            return self.port
        require_loopback(self.host)
        port = self._requested_port
        if port and port < 1024:
            raise SafetyError(f"Refusing privileged/well-known port: {port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, port))
        sock.listen(64)
        sock.settimeout(0.25)
        self.socket = sock
        self.port = sock.getsockname()[1]
        self._looper = threading.Thread(target=self._accept_loop, name=f"hn-{self.proto}-accept", daemon=True)
        self._looper.start()
        return self.port

    def _effective_src(self, peer: str) -> str:
        return self.attribution.get(peer, peer)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self.socket.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            handler = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
            handler.start()
            self._handlers.append(handler)

    def _handle(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        peer = addr[0]
        src = self._effective_src(peer)
        try:
            require_lab_peer(peer)
        except SafetyError as exc:
            self._local.peer = peer
            self._log(src, "peer-rejected", {"peer": peer, "reason": str(exc)})
            try:
                conn.close()
            except OSError:
                pass
            return
        conn.settimeout(10.0)
        self._local.peer = peer
        self._log(src, "connect", {"peer": peer})
        try:
            self.handle_client(conn, src, peer)
        except Exception as exc:  # noqa: BLE001 — never crash the farm on a hostile client
            self._log(src, "handler-error", {"error": str(exc)})
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._log(src, "disconnect", {})

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
        if self._looper is not None:
            self._looper.join(timeout=2.0)
        for t in self._handlers:
            t.join(timeout=2.0)
        self._handlers.clear()

    @property
    def running(self) -> bool:
        return self.socket is not None and not self._stop.is_set()

    def __enter__(self) -> "HoneypotService":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
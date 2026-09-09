"""ssh.py — SSH-banner + auth-sim honeypot.

Presents a plausible OpenSSH banner, runs a keyboard-interactive-style exchange
(username/password prompts), logs every credential attempt, rejects all logins,
and keeps the (command-free) session open briefly to log any trailing input
that a would-be attacker sends — never executing anything.
"""

from __future__ import annotations

import socket
from typing import Any

from ..logger import OUT
from ..protocol import recv_line
from .base import HoneypotService

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
DENIAL = b"Permission denied, please try again.\r\n"


class SshHoneypot(HoneypotService):
    proto = "ssh"

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        conn.sendall(SSH_BANNER)
        self.logger.log(self.proto, src, self.port, "banner-sent", {"banner": SSH_BANNER.decode().strip()}, direction=OUT)

        client_banner = recv_line(conn).strip()
        if not client_banner:
            return
        self.logger.log(self.proto, src, self.port, "client-banner", {"banner": client_banner.decode("utf-8", "replace")})

        conn.sendall(b"login: ")
        username = recv_line(conn).strip().decode("utf-8", "replace")
        if not username:
            return

        conn.sendall(b"Password: ")
        password = recv_line(conn).strip().decode("utf-8", "replace")

        self.logger.log(self.proto, src, self.port, "auth-attempt", {
            "username": username,
            "password": password,
            "rejected": True,
        })
        conn.sendall(DENIAL)
        self.logger.log(self.proto, src, self.port, "auth-rejected", {
            "username": username,
            "message": DENIAL.decode().strip(),
        })

        trailing = recv_line(conn, timeout=1.0).strip()
        if trailing:
            self.logger.log(self.proto, src, self.port, "session-input", {
                "username": username,
                "command": trailing.decode("utf-8", "replace"),
                "executed": False,
            })
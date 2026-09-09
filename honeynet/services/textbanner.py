"""textbanner.py — banner + verb-logging honeypots (telnet, smtp, vnc-mock).

These services announce a plausible service, then log every line/verb the
attacker sends (telnet commands, SMTP verbs, a mock RFB handshake) without
ever executing anything. They are intentionally naive: the point is detection
and luring, not protocol fidelity.
"""

from __future__ import annotations

import socket
from typing import Any, Callable

from ..logger import OUT
from ..protocol import recv_exact, recv_line
from .base import HoneypotService

TELNET_BANNER = (
    b"Trying 127.0.0.1...\r\n"
    b"Connected to honeynet.lab.\r\n"
    b"Escape character is '^]'.\r\n\r\n"
    b"Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
    b"honeynet login: "
)

SMTP_BANNER = b"220 honeynet.lab ESMTP Postfix (Ubuntu)\r\n"


class TextBannerHoneypot(HoneypotService):
    """Configurable banner/verb logger shared by telnet and smtp."""

    proto = "text"
    banner: bytes = b""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.reply: Callable[[str, int], bytes] | None = None

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        conn.sendall(self.banner)
        self.logger.log(self.proto, src, self.port, "banner-sent", {"banner": self.banner.decode("utf-8", "replace").strip()}, direction=OUT)
        stage = 0
        while True:
            line = recv_line(conn, timeout=4.0).strip()
            if not line:
                return
            text = line.decode("utf-8", "replace")
            self.logger.log(self.proto, src, self.port, "verb", {"verb": text, "stage": stage})
            reply = self.reply(text, stage) if self.reply else None
            if reply:
                conn.sendall(reply)
                self.logger.log(self.proto, src, self.port, "verb-reply", {"reply": reply.decode("utf-8", "replace").strip()}, direction=OUT)
            stage += 1


class TelnetHoneypot(TextBannerHoneypot):
    proto = "telnet"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.banner = TELNET_BANNER

        def reply(line: str, stage: int) -> bytes:
            if stage == 0:
                return b"Password: "
            return b"\r\n$ "

        self.reply = reply


class SmtpHoneypot(TextBannerHoneypot):
    proto = "smtp"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.banner = SMTP_BANNER

        def reply(line: str, stage: int) -> bytes:
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                return b"250-honeynet.lab\r\n250-PIPELINING\r\n250 8BITMIME\r\n"
            if verb == "MAIL":
                return b"250 2.1.0 Ok\r\n"
            if verb == "RCPT":
                return b"250 2.1.5 Ok\r\n"
            if verb == "DATA":
                return b"354 End data with <CR><LF>.<CR><LF>\r\n"
            if verb == "QUIT":
                return b"221 2.0.0 Bye\r\n"
            return b"250 Ok\r\n"

        self.reply = reply


class VncMockHoneypot(HoneypotService):
    proto = "vnc"

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        conn.sendall(b"RFB 003.008\n")
        self.logger.log(self.proto, src, self.port, "banner-sent", {"banner": "RFB 003.008"}, direction=OUT)
        line = recv_line(conn).strip()
        self.logger.log(self.proto, src, self.port, "verb", {"verb": line.decode("utf-8", "replace") or "(none)", "stage": 0})
        if line != b"RFB 003.008":
            return
        conn.sendall(b"\x00\x00\x00\x02\x00\x01")  # 2 security types: None, VNC Auth
        choice = recv_exact(conn, 1, timeout=2.0)
        self.logger.log(self.proto, src, self.port, "verb", {
            "verb": f"security-choice=0x{choice.hex() or 'nil'}",
            "stage": 1,
        })
        if choice == b"\x00":
            conn.sendall(b"\x00\x00\x00\x00")  # None security: OK
        elif choice == b"\x02":
            conn.sendall(b"\x00\x00\x00\x00")  # pretend auth succeeds, then drop
        else:
            return
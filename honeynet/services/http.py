"""http.py — fake HTTP honeypot.

Serves plausible login/admin/phpMyAdmin-style pages, logs every request
method/path/headers plus parsed GET and POST parameters, and — when an
attacker pokes a deception-grid tripwire path — serves the planted honeytoken
and logs the tripwire. The honeytoken GET/POST leak game is fully offline.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..protocol import parse_http_request, recv_exact, recv_until
from .base import HoneypotService

NOT_FOUND = (
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
    "<body><h1>404 Not Found</h1><p>nginx honeynet.lab</p></body></html>"
)


def _qs(params: dict[str, list[str]]) -> dict[str, str]:
    return {k: (v[0] if v else "") for k, v in params.items()}


class HttpHoneypot(HoneypotService):
    proto = "http"

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        head = recv_until(conn, b"\r\n\r\n")
        if not head:
            return
        method, target, version, headers, partial = parse_http_request(head)
        ua = headers.get("user-agent", "")
        self.logger.log(self.proto, src, self.port, "request", {
            "method": method,
            "path": target,
            "version": version,
            "user_agent": ua,
            "host": headers.get("host", ""),
        })

        body = partial
        content_length = headers.get("content-length")
        if content_length:
            try:
                n = int(content_length)
            except ValueError:
                n = 0
            if n > 0 and len(partial) < n:
                body = partial + recv_exact(conn, n - len(partial))

        parsed = urlparse(target)
        path = parsed.path or "/"
        params: dict[str, str] = {}
        if parsed.query:
            params.update(_qs(parse_qs(parsed.query)))
        if body:
            params.update(_qs(parse_qs(body.decode("latin-1", "replace"))))
        if params:
            self.logger.log(self.proto, src, self.port, "params", {
                "method": method,
                "path": path,
                "params": params,
            })

        asset = self.deceive.asset_for(path)
        if self.deceive.is_tripwire(path):
            token = self.deceive.honeytoken_for(path)
            self.logger.log(self.proto, src, self.port, "tripwire", {
                "path": path,
                "token": token,
                "method": method,
            })
            self._respond(conn, body=token, content_type="text/plain")
            self.logger.log(self.proto, src, self.port, "honeytoken-served", {
                "path": path,
                "token": token,
            })
            return

        if asset is not None:
            kind = asset.get("kind", "admin_page")
            page = self.deceive.page_html(kind)
            self.logger.log(self.proto, src, self.port, "asset-served", {"path": path, "kind": kind})
            self._respond(conn, body=page, content_type="text/html")
            return

        if path in ("/", "/index.html", "/login", "/login.html"):
            page = self.deceive.page_html("login")
            self.logger.log(self.proto, src, self.port, "login-page", {"path": path})
            self._respond(conn, body=page, content_type="text/html")
            return

        self.logger.log(self.proto, src, self.port, "not-found", {"path": path, "method": method})
        self._respond(conn, body=NOT_FOUND, content_type="text/html", code=404)

    def _respond(self, conn: socket.socket, body: str, content_type: str = "text/html", code: int = 200) -> None:
        payload = body.encode("utf-8")
        reason = "OK" if code == 200 else "Not Found"
        head = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Server: nginx/1.18.0 (Ubuntu)\r\n"
            f"Content-Type: {content_type}; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        try:
            conn.sendall(head + payload)
        except OSError:
            return
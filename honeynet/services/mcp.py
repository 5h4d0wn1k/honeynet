"""mcp.py — MCP-like (JSON-RPC 2.0) honeypot.

Speaks newline-delimited JSON-RPC 2.0 over TCP and pretends to be a Model
Context Protocol server. It announces a plausible fake tool catalogue
(initialize / tools/list) and — the interesting part — logs the FULL request
of every `tools/call` attempt, returning runtime-built fake placeholders.
"""

from __future__ import annotations

import json
import socket
from typing import Any

from ..protocol import recv_line
from .base import HoneypotService

PROTOCOL_VERSION = "2025-03-26"
SERVER_NAME = "honeynet-mcp"


class JsonRpcMcpHoneypot(HoneypotService):
    proto = "mcp"

    def handle_client(self, conn: socket.socket, src: str, peer: str) -> None:
        while True:
            line = recv_line(conn, timeout=8.0)
            if not line.strip():
                return
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self.logger.log(self.proto, src, self.port, "malformed", {"request": line.decode("utf-8", "replace")})
                self._send(conn, json_rpc_error(None, -32700, "Parse error"))
                continue

            self.logger.log(self.proto, src, self.port, "jsonrpc-request", {
                "full_request": line.decode("utf-8", "replace"),
            })
            method = req.get("method", "")
            req_id = req.get("id")

            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
                }
                self._send(conn, json_rpc_result(req_id, result))
            elif method == "tools/list":
                self._send(conn, json_rpc_result(req_id, {"tools": self.deceive.tool_catalogue()}))
            elif method == "tools/call":
                params = req.get("params") or {}
                tool = params.get("name", "?")
                args = params.get("arguments") or {}
                self.logger.log(self.proto, src, self.port, "tool-call", {
                    "tool": tool,
                    "arguments": args,
                    "full_request": line.decode("utf-8", "replace"),
                })
                fake = self.deceive.fake_tool_result(tool, args)
                self._send(conn, json_rpc_result(req_id, fake))
            else:
                self.logger.log(self.proto, src, self.port, "jsonrpc-method", {
                    "method": method,
                    "full_request": line.decode("utf-8", "replace"),
                })
                self._send(conn, json_rpc_error(req_id, -32601, "Method not found"))

    def _send(self, conn: socket.socket, obj: dict[str, Any]) -> None:
        conn.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))


def json_rpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def json_rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
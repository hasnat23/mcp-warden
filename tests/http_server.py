"""A small Streamable HTTP MCP server for tests (JSON and SSE responses)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SESSION = "sess-123"
VERSION = "2025-06-18"


class FakeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, tools: list[dict[str, Any]], require_auth: str | None = None):
        super().__init__(("127.0.0.1", 0), Handler)
        self.tools = tools
        self.require_auth = require_auth
        self.received: list[dict[str, Any]] = []
        self.deleted = False
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/mcp"


class Handler(BaseHTTPRequestHandler):
    server: FakeHTTPServer

    def log_message(self, *args: Any) -> None:
        pass

    def _reply(
        self,
        status: int,
        body: bytes = b"",
        ctype: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, msg: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        self._reply(200, json.dumps(msg).encode(), headers=headers)

    def _sse(self, messages: list[dict[str, Any]]) -> None:
        body = "".join(
            f": keep-alive\r\nid: {i}\r\nevent: message\r\ndata: {json.dumps(m)}\r\n\r\n"
            for i, m in enumerate(messages)
        ).encode()
        self._reply(200, body, ctype="text/event-stream")

    def do_DELETE(self) -> None:
        self.server.deleted = self.headers.get("Mcp-Session-Id") == SESSION
        self._reply(200)

    def do_POST(self) -> None:
        if (
            self.server.require_auth
            and self.headers.get("Authorization") != self.server.require_auth
        ):
            self._reply(401, b'{"error":"unauthorized"}')
            return
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with self.server.lock:
            self.server.received.append(msg)
        method, msg_id = msg.get("method"), msg.get("id")
        if method == "initialize":
            result = {
                "protocolVersion": VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-http", "version": "2.0.0"},
            }
            self._json(
                {"jsonrpc": "2.0", "id": msg_id, "result": result},
                headers={"Mcp-Session-Id": SESSION},
            )
            return
        if (
            self.headers.get("Mcp-Session-Id") != SESSION
            or self.headers.get("MCP-Protocol-Version") != VERSION
        ):
            self._reply(400, b'{"error":"missing session or protocol version"}')
            return
        if method is None or msg_id is None:
            self._reply(202)
            return
        if method == "tools/list":
            self._sse(
                [
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {"level": "info", "data": "listing"},
                    },
                    {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": self.server.tools}},
                ]
            )
        elif method == "tools/call":
            name = msg["params"]["name"]
            text = "token ghp_" + "a" * 36 if name == "get_env" else f"ran {name}"
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": text}]},
                }
            )
        else:
            self._json(
                {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "not found"}}
            )


def serve(tools: list[dict[str, Any]], require_auth: str | None = None) -> FakeHTTPServer:
    server = FakeHTTPServer(tools, require_auth)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

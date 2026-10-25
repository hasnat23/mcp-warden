"""Serve the multi-server gateway over MCP Streamable HTTP.

This turns mcp-warden into a shared gateway: a team points every client at one
URL, and one place holds the policies, pins, audit log and upstream credentials.

Each POST carries one JSON-RPC message (or a batch, for older clients). Requests
get a JSON response; notifications and responses get 202. ``initialize`` hands
out an ``Mcp-Session-Id`` that every later request must echo, and DELETE ends
the session. There is no server-initiated stream, so GET answers 405 as the
spec allows. Browsers are kept out with an Origin check (DNS rebinding), and
callers can be required to present a bearer token: one shared token, or one per
named client, each optionally limited to some servers. Sessions are bound to the
client that opened them.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import secrets
import threading
from collections import OrderedDict
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from mcp_warden.gateway import Gateway, Message
from mcp_warden.servers import ClientSpec, ServerSpec, token_digest
from mcp_warden.warden import AUDIT_CONTEXT, Sink

log = logging.getLogger("mcp_warden")

SESSION_HEADER = "Mcp-Session-Id"
MAX_BODY = 8 * 1024 * 1024
MAX_SESSIONS = 10_000
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def origin_allowed(origin: str | None, allowed: Sequence[str]) -> bool:
    """Requests without Origin come from non-browser clients and are fine."""
    if not origin:
        return True
    if "*" in allowed or origin in allowed:
        return True
    return urlsplit(origin).hostname in LOCAL_HOSTS


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    owner: GatewayServer


class GatewayServer:
    def __init__(
        self,
        specs: Sequence[ServerSpec],
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        path: str = "/mcp",
        sinks: Sequence[Sink] = (),
        token: str | None = None,
        clients: Sequence[ClientSpec] = (),
        allowed_origins: Sequence[str] = (),
        request_timeout: float = 300.0,
    ):
        self.gateway = Gateway(specs, sinks=sinks)
        self.gateway.notifies = False
        self.host, self.port, self.path = host, port, path
        if token is not None and clients:
            raise ValueError("use a shared token or per-client tokens, not both")
        self.clients = list(clients)
        if token is not None:
            self.clients.append(ClientSpec("", token_digest(token)))
        self.auth_required = bool(self.clients)
        self.allowed_origins = list(allowed_origins)
        self.request_timeout = request_timeout
        # session id -> the client that opened it
        self.sessions: OrderedDict[str, ClientSpec | None] = OrderedDict()
        self._sessions_lock = threading.Lock()
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(
            target=self._loop.run_forever, name="mcp-warden-gateway", daemon=True
        )
        self._httpd: _HTTPServer | None = None

    @property
    def url(self) -> str:
        assert self._httpd is not None
        host, port = str(self._httpd.server_address[0]), self._httpd.server_address[1]
        host = f"[{host}]" if ":" in host else host
        return f"http://{host}:{port}{self.path}"

    def start(self) -> None:
        """Start the upstreams, list their tools once, then bind the listener."""
        self._loop_thread.start()
        self._run(self._prime(), timeout=None)
        self._httpd = _HTTPServer((self.host, self.port), _Handler)
        self._httpd.owner = self

    async def _prime(self) -> None:
        await self.gateway.start()
        # Listing up front means poisoned or drifted tools are hidden before any
        # client could call them without listing first.
        await self.gateway.list_tools()

    def serve_forever(self) -> None:
        assert self._httpd is not None
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        """Stop serving; safe to call from a signal handler or another thread."""
        if self._httpd is not None:
            threading.Thread(target=self._httpd.shutdown, daemon=True).start()

    def close(self) -> None:
        if self._httpd is not None:
            self._httpd.server_close()
        with contextlib.suppress(Exception):
            self._run(self.gateway.close(), timeout=30)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._loop_thread.join(timeout=5)

    def _run(self, coro: Any, timeout: float | None) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    # ------------------------------------------------------------------ sessions

    def new_session(self, client: ClientSpec | None) -> str:
        sid = secrets.token_urlsafe(24)
        with self._sessions_lock:
            self.sessions[sid] = client
            while len(self.sessions) > MAX_SESSIONS:
                self.sessions.popitem(last=False)
        return sid

    def has_session(self, sid: str, client: ClientSpec | None) -> bool:
        """A session only exists for the client that opened it."""
        with self._sessions_lock:
            if sid in self.sessions and self.sessions[sid] == client:
                self.sessions.move_to_end(sid)
                return True
            return False

    def end_session(self, sid: str, client: ClientSpec | None) -> bool:
        with self._sessions_lock:
            if sid in self.sessions and self.sessions[sid] == client:
                del self.sessions[sid]
                return True
            return False

    def authenticate(self, header: str | None) -> tuple[bool, ClientSpec | None]:
        """(ok, client) for an Authorization header; client is None when auth is off."""
        if not self.auth_required:
            return True, None
        scheme, _, value = (header or "").partition(" ")
        if scheme.lower() != "bearer" or not value.strip():
            return False, None
        digest = token_digest(value.strip()).encode()
        found = None
        for client in self.clients:  # compare against every client, in constant time
            if hmac.compare_digest(digest, client.token_sha256.encode()):
                found = client
        return found is not None, found

    def handle(
        self, msg: Any, session: str, remote: str, client: ClientSpec | None = None
    ) -> Message | None:
        context: dict[str, Any] = {"session": session[:8], "remote": remote}
        if client is not None and client.name:
            context["user"] = client.name
        allowed = client.servers if client is not None else None

        async def run() -> Message | None:
            token = AUDIT_CONTEXT.set(context)
            try:
                return await self.gateway.handle(msg, scope=session, allowed=allowed)
            finally:
                AUDIT_CONTEXT.reset(token)

        return self._run(run(), timeout=self.request_timeout)  # type: ignore[no-any-return]


def _is_request(msg: Any) -> bool:
    return isinstance(msg, dict) and "method" in msg and "id" in msg


def _rpc_error(code: int, message: str, msg_id: Any = None) -> Message:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


class _Handler(BaseHTTPRequestHandler):
    server: _HTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        log.debug("%s %s", self.address_string(), format % args)

    @property
    def owner(self) -> GatewayServer:
        return self.server.owner

    def _send(self, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        data = b"" if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    client: ClientSpec | None = None

    def _guard(self) -> bool:
        """Path, Origin and auth checks shared by every MCP method."""
        if urlsplit(self.path).path != self.owner.path:
            self._send(404, _rpc_error(-32600, "not found"))
            return False
        if not origin_allowed(self.headers.get("Origin"), self.owner.allowed_origins):
            self._send(403, _rpc_error(-32600, "origin not allowed"))
            return False
        ok, self.client = self.owner.authenticate(self.headers.get("Authorization"))
        if not ok:
            self._send(401, _rpc_error(-32600, "unauthorized"), {"WWW-Authenticate": "Bearer"})
            return False
        return True

    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/healthz":
            self._send(200, {"status": "ok"})
        elif self._guard():
            self._send(
                405, _rpc_error(-32600, "no server-initiated stream"), {"Allow": "POST, DELETE"}
            )

    def do_DELETE(self) -> None:
        if not self._guard():
            return
        sid = self.headers.get(SESSION_HEADER, "")
        self._send(200 if sid and self.owner.end_session(sid, self.client) else 404)

    def do_POST(self) -> None:
        if not self._guard():
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, _rpc_error(-32600, "request too large"), {"Connection": "close"})
            self.close_connection = True
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, _rpc_error(-32700, "parse error"))
            return
        batch = isinstance(payload, list)
        messages = payload if batch else [payload]
        if not messages or not all(isinstance(m, dict) for m in messages):
            self._send(400, _rpc_error(-32600, "invalid request"))
            return

        headers: dict[str, str] = {}
        if any(m.get("method") == "initialize" for m in messages):
            if len(messages) > 1:
                self._send(400, _rpc_error(-32600, "initialize must not be batched"))
                return
            sid = self.owner.new_session(self.client)
            headers[SESSION_HEADER] = sid
        else:
            sid = self.headers.get(SESSION_HEADER, "")
            if not sid:
                self._send(400, _rpc_error(-32600, f"missing {SESSION_HEADER} header"))
                return
            if not self.owner.has_session(sid, self.client):
                self._send(404, _rpc_error(-32001, "session not found"))
                return

        replies = []
        for msg in messages:
            try:
                reply = self.owner.handle(msg, sid, self.client_address[0], self.client)
            except Exception as exc:
                log.exception("request failed")
                reply = (
                    _rpc_error(-32603, f"mcp-warden internal error: {exc}", msg["id"])
                    if _is_request(msg)
                    else None
                )
            if reply is not None:
                replies.append(reply)
        if not replies:
            self._send(202, headers=headers)
        else:
            self._send(200, replies if batch else replies[0], headers)


def run_server(server: GatewayServer) -> int:
    import signal

    server.start()
    if not server.auth_required and server.host not in LOCAL_HOSTS:
        log.warning(
            "listening on %s without a token: anyone who can reach it can call tools", server.host
        )
    print(f"mcp-warden: serving {len(server.gateway.specs)} server(s) at {server.url}", flush=True)
    with contextlib.suppress(ValueError):  # not the main thread
        signal.signal(signal.SIGTERM, lambda *_: server.shutdown())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return 0

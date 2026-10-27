"""Multi-server gateway: one stdio MCP endpoint in front of several servers.

The client sees a single server whose tools are named ``<server>__<tool>``.
Each upstream server gets its own ``Warden`` (and so its own policy, lockfile
and rate limits), and every audit record carries the server it came from.
Upstreams are either child processes speaking stdio or Streamable HTTP
endpoints.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import os
import sys
from collections.abc import Callable, Collection, Sequence
from typing import Any, BinaryIO

from mcp_warden import __version__
from mcp_warden.audit import AuditLog
from mcp_warden.client import PROTOCOL_VERSION
from mcp_warden.http_transport import StreamableHTTP, TransportError
from mcp_warden.jsonrpc import decode, encode
from mcp_warden.proxy import STREAM_LIMIT, _start_reader
from mcp_warden.servers import SEP, ServerSpec
from mcp_warden.warden import Sink, Warden

log = logging.getLogger("mcp_warden")

Message = dict[str, Any]
Notify = Callable[[str, Message], None]

CLIENT_INFO = {"name": "mcp-warden", "version": __version__}
# Where an upstream notification goes: (message, client scope or None for every
# client, upstream server name).
Deliver = Callable[[Message, "str | None", str], None]


class UpstreamError(RuntimeError):
    pass


def _error(msg_id: Any, code: int, message: str) -> Message:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


class Upstream:
    """One MCP server the gateway talks to as a client."""

    def __init__(self, name: str, on_notify: Notify):
        self.name = name
        self._on_notify = on_notify
        self._ids = itertools.count(1)

    def next_id(self) -> int:
        return next(self._ids)

    async def start(self) -> None:
        raise NotImplementedError

    async def request(self, msg: Message) -> Message:
        raise NotImplementedError

    async def notify(self, msg: Message) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    async def call(self, method: str, params: Message | None = None) -> Message:
        msg: Message = {"jsonrpc": "2.0", "id": self.next_id(), "method": method}
        if params is not None:
            msg["params"] = params
        return await self.request(msg)

    async def initialize(self) -> None:
        reply = await self.call(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        if "error" in reply:
            raise UpstreamError(f"{self.name}: initialize failed: {reply['error']}")
        await self.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _incoming(self, msg: Any) -> Message | None:
        """Handle a non-response message; returns a reply to send back, if any."""
        if not isinstance(msg, dict) or "method" not in msg:
            return None
        if "id" in msg:
            # The gateway advertises no client capabilities (sampling, roots, ...).
            return _error(msg["id"], -32601, f"{msg['method']} is not supported by mcp-warden")
        self._on_notify(self.name, msg)
        return None


class StdioUpstream(Upstream):
    def __init__(self, name: str, command: Sequence[str], on_notify: Notify):
        super().__init__(name, on_notify)
        self.command = list(command)
        self._proc: asyncio.subprocess.Process | None = None
        self._waiting: dict[Any, asyncio.Future[Message]] = {}
        self._reader: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
            limit=STREAM_LIMIT,
            env=os.environ.copy(),
        )
        self._reader = asyncio.create_task(self._read())
        await self.initialize()

    async def _read(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while line := await self._proc.stdout.readline():
            msg = decode(line)
            if isinstance(msg, dict) and "id" in msg and "method" not in msg:
                future = self._waiting.pop(msg["id"], None)
                if future is not None and not future.done():
                    future.set_result(msg)
                continue
            reply = self._incoming(msg)
            if reply is not None:
                await self._write(reply)
        for future in self._waiting.values():
            if not future.done():
                future.set_exception(UpstreamError(f"{self.name}: server exited"))
        self._waiting.clear()

    async def _write(self, msg: Message) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write(encode(msg))
        await self._proc.stdin.drain()

    async def request(self, msg: Message) -> Message:
        if self._reader is None or self._reader.done():
            raise UpstreamError(f"{self.name}: server is not running")
        future: asyncio.Future[Message] = asyncio.get_running_loop().create_future()
        self._waiting[msg["id"]] = future
        try:
            await self._write(msg)
        except ConnectionError as exc:
            self._waiting.pop(msg["id"], None)
            raise UpstreamError(f"{self.name}: {exc}") from exc
        return await future

    async def notify(self, msg: Message) -> None:
        with contextlib.suppress(ConnectionError):
            await self._write(msg)

    async def close(self) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.stdin is not None:
            with contextlib.suppress(ConnectionError):
                proc.stdin.close()
        if proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.terminate()
                await proc.wait()
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader


class HttpUpstream(Upstream):
    def __init__(self, name: str, transport: StreamableHTTP, on_notify: Notify):
        super().__init__(name, on_notify)
        self.transport = transport

    async def start(self) -> None:
        await self.initialize()

    def _post(self, msg: Message) -> Message | None:
        # Runs on a worker thread; the response may arrive after notifications on an SSE stream.
        response = None
        for reply in self.transport.post(msg):
            if (
                isinstance(reply, dict)
                and reply.get("id") == msg.get("id")
                and "method" not in reply
            ):
                response = reply
                continue
            answer = self._incoming(reply)
            if answer is not None:
                for _ in self.transport.post(answer):
                    pass
        return response

    async def request(self, msg: Message) -> Message:
        try:
            response = await asyncio.to_thread(self._post, msg)
        except TransportError as exc:
            raise UpstreamError(f"{self.name}: {exc}") from exc
        if response is None:
            raise UpstreamError(f"{self.name}: no response to {msg.get('method')}")
        return response

    async def notify(self, msg: Message) -> None:
        try:
            await asyncio.to_thread(self._post, msg)
        except TransportError as exc:
            log.warning("%s: %s", self.name, exc)

    async def close(self) -> None:
        await asyncio.to_thread(self.transport.close)


class Gateway:
    def __init__(
        self,
        specs: Sequence[ServerSpec],
        *,
        sinks: Sequence[Sink] = (),
        write: Callable[[Message], None] | None = None,
    ):
        self.specs = list(specs)
        self.sinks = list(sinks)
        self._write = write or (lambda m: None)
        # Overridable routing of notifications to clients; stdio has a single client.
        self.deliver: Deliver = lambda msg, scope, server: self._write(msg)
        self._loop: asyncio.AbstractEventLoop | None = None
        # Progress tokens are rewritten per call, because clients sharing an upstream
        # may pick the same ones: gateway token -> (client scope, client's token).
        self._progress: dict[str, tuple[str, Any]] = {}
        self._progress_ids = itertools.count(1)
        self._audits: dict[str | None, AuditLog] = {}
        self.wardens: dict[str, Warden] = {}
        self.upstreams: dict[str, Upstream] = {}
        # (client scope, client request id) -> (server, upstream request id), for cancellation
        self._calls: dict[tuple[str, str], tuple[str, int]] = {}
        # Whether clients can be told the tool list changed (stdio, or serve's GET stream).
        self.notifies = True
        self._started = False
        for spec in self.specs:
            path = spec.policy.audit_path
            if path not in self._audits:
                self._audits[path] = AuditLog(path)
            self.wardens[spec.name] = Warden(
                spec.policy, audit=self._audits[path], sinks=self.sinks, label=spec.name
            )
            if spec.url:
                self.upstreams[spec.name] = HttpUpstream(
                    spec.name, StreamableHTTP(spec.url, spec.headers), self._upstream_notification
                )
            else:
                self.upstreams[spec.name] = StdioUpstream(
                    spec.name, spec.command, self._upstream_notification
                )

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._loop = asyncio.get_running_loop()
        results = await asyncio.gather(
            *(u.start() for u in self.upstreams.values()), return_exceptions=True
        )
        for name, result in zip(self.upstreams, results, strict=True):
            if isinstance(result, BaseException):
                log.error("server %s failed to start: %s", name, result)

    async def close(self) -> None:
        await asyncio.gather(*(u.close() for u in self.upstreams.values()), return_exceptions=True)
        for audit in self._audits.values():
            audit.close()
        for sink in self.sinks:
            closer = getattr(sink, "close", None)
            if callable(closer):
                closer()

    def _upstream_notification(self, server: str, msg: Message) -> None:
        # HTTP upstreams report from worker threads; deliver on the loop, in order.
        loop = self._loop
        if loop is not None and not loop.is_closed():
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is not loop:
                loop.call_soon_threadsafe(self._route_notification, server, msg)
                return
        self._route_notification(server, msg)

    def _route_notification(self, server: str, msg: Message) -> None:
        method = msg.get("method")
        if method == "notifications/tools/list_changed":
            self.deliver({"jsonrpc": "2.0", "method": method}, None, server)
            return
        if method not in ("notifications/progress", "notifications/message"):
            return
        warden = self.wardens[server]
        if warden.policy.redact:
            msg = {**msg, "params": warden.redactor.redact(msg.get("params"))[0]}
        if method == "notifications/message":
            self.deliver(msg, None, server)
            return
        params = msg.get("params") or {}
        target = self._progress.get(str(params.get("progressToken")))
        if target is None:
            return  # not a call we made, or it already finished
        scope, token = target
        self.deliver({**msg, "params": {**params, "progressToken": token}}, scope, server)

    # ------------------------------------------------------------------ client requests

    async def handle(
        self, msg: Any, scope: str = "", allowed: Collection[str] | None = None
    ) -> Message | None:
        """Handle one client message and return the response, if it needs one.

        ``scope`` separates clients that share this gateway (one per HTTP session),
        since their request ids can collide. ``allowed`` limits the client to some
        upstream servers; the others are invisible to it.
        """
        if not isinstance(msg, dict) or "method" not in msg:
            return None
        method, params = msg["method"], msg.get("params") or {}
        if method == "notifications/cancelled":
            await self._cancel(params, scope)
            return None
        if "id" not in msg:
            return None
        msg_id = msg["id"]
        if method == "initialize":
            await self.start()
            version = params.get("protocolVersion")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": version if isinstance(version, str) else PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": self.notifies}},
                    "serverInfo": CLIENT_INFO,
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        if method == "tools/list":
            tools = await self.list_tools(allowed)
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}
        if method == "tools/call":
            return await self._call_tool(msg_id, params, scope, allowed)
        empty = {"resources/list": "resources", "resources/templates/list": "resourceTemplates"}
        if method in empty or method == "prompts/list":
            key = empty.get(method, "prompts")
            return {"jsonrpc": "2.0", "id": msg_id, "result": {key: []}}
        return _error(msg_id, -32601, f"method not found: {method}")

    async def list_tools(self, allowed: Collection[str] | None = None) -> list[Message]:
        names = [n for n in self.upstreams if allowed is None or n in allowed]
        lists = await asyncio.gather(*(self._list_server(name) for name in names))
        return [tool for tools in lists for tool in tools]

    async def _list_server(self, name: str) -> list[Message]:
        upstream, warden = self.upstreams[name], self.wardens[name]
        tools: list[Message] = []
        cursor = None
        try:
            while True:
                msg: Message = {"jsonrpc": "2.0", "id": upstream.next_id(), "method": "tools/list"}
                if cursor:
                    msg["params"] = {"cursor": cursor}
                warden.from_client(msg)
                reply = warden.from_server(await upstream.request(msg)).to_client[0]
                result = reply.get("result")
                if not isinstance(result, dict):
                    log.error("%s: tools/list failed: %s", name, reply.get("error"))
                    break
                tools.extend(t for t in result.get("tools") or [] if isinstance(t, dict))
                cursor = result.get("nextCursor")
                if not cursor:
                    break
        except UpstreamError as exc:
            log.error("%s", exc)
        return [{**t, "name": f"{name}{SEP}{t.get('name')}"} for t in tools]

    async def _call_tool(
        self,
        client_id: Any,
        params: Message,
        scope: str = "",
        allowed: Collection[str] | None = None,
    ) -> Message:
        full = str(params.get("name", ""))
        server, sep, tool = full.partition(SEP)
        if not sep or server not in self.upstreams:
            return _error(client_id, -32602, f"unknown tool: {full}")
        if allowed is not None and server not in allowed:
            # Answer exactly as for a server that does not exist, but keep a record.
            self.wardens[server]._audit_call(
                tool, params.get("arguments"), "deny", reason="client may not use this server"
            )
            return _error(client_id, -32602, f"unknown tool: {full}")
        upstream, warden = self.upstreams[server], self.wardens[server]
        upstream_id = upstream.next_id()
        forwarded = {**params, "name": tool}
        meta = params.get("_meta")
        progress = None
        if isinstance(meta, dict) and "progressToken" in meta:
            progress = f"mcp-warden-{next(self._progress_ids)}"
            forwarded["_meta"] = {**meta, "progressToken": progress}
        msg = {"jsonrpc": "2.0", "id": upstream_id, "method": "tools/call", "params": forwarded}
        outcome = warden.from_client(msg)
        if outcome.to_client:  # denied by policy
            return {**outcome.to_client[0], "id": client_id}
        key = (scope, repr(client_id))
        self._calls[key] = (server, upstream_id)
        if progress is not None:
            assert isinstance(meta, dict)
            self._progress[progress] = (scope, meta["progressToken"])
        try:
            reply = await upstream.request(msg)
        except UpstreamError as exc:
            warden.from_client(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": upstream_id, "reason": str(exc)},
                }
            )
            return _error(client_id, -32000, f"mcp-warden upstream error: {exc}")
        finally:
            self._calls.pop(key, None)
            if progress is not None:
                self._progress.pop(progress, None)
        return {**warden.from_server(reply).to_client[0], "id": client_id}

    async def _cancel(self, params: Message, scope: str = "") -> None:
        target = self._calls.get((scope, repr(params.get("requestId"))))
        if target is None:
            return
        server, upstream_id = target
        note = {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {**params, "requestId": upstream_id},
        }
        self.wardens[server].from_client(note)
        await self.upstreams[server].notify(note)


async def run_gateway(
    specs: Sequence[ServerSpec],
    *,
    sinks: Sequence[Sink] = (),
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
) -> int:
    client_in = client_in or sys.stdin.buffer
    client_out = client_out or sys.stdout.buffer
    loop = asyncio.get_running_loop()

    def write(msg: Any) -> None:
        client_out.write(encode(msg))
        client_out.flush()

    gateway = Gateway(specs, sinks=sinks, write=write)
    in_flight: set[asyncio.Task[None]] = set()

    async def serve(msg: Any) -> None:
        try:
            reply = await gateway.handle(msg)
        except Exception as exc:  # never let one request take the gateway down
            log.exception("request failed")
            if isinstance(msg, dict) and "id" in msg and "method" in msg:
                write(_error(msg["id"], -32603, f"mcp-warden internal error: {exc}"))
            return
        if reply is not None:
            write(reply)

    queue = _start_reader(client_in, loop)
    try:
        while line := await queue.get():
            msg = decode(line)
            if msg is None:
                continue
            if isinstance(msg, dict) and msg.get("method") == "initialize":
                await serve(msg)  # upstreams must be up before anything else runs
                continue
            task = asyncio.create_task(serve(msg))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)
        if in_flight:
            await asyncio.wait(set(in_flight), timeout=30)
    finally:
        for task in in_flight:
            task.cancel()
        await gateway.close()
    return 0

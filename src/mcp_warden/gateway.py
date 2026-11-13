"""Multi-server gateway: one stdio MCP endpoint in front of several servers.

The client sees a single server whose tools and prompts are named
``<server>__<name>``. Resources keep their URIs; reads are routed to the server
that listed the URI or whose template matches it. Each upstream server gets its
own ``Warden`` (and so its own policy, lockfile and rate limits), and every audit
record carries the server it came from. Upstreams are either child processes
speaking stdio or Streamable HTTP endpoints.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import os
import re
import sys
from collections.abc import Awaitable, Callable, Collection, Sequence
from typing import Any, BinaryIO

from mcp_warden import __version__
from mcp_warden.audit import AuditLog
from mcp_warden.client import PROTOCOL_VERSION
from mcp_warden.http_transport import StreamableHTTP, TransportError
from mcp_warden.jsonrpc import decode, encode
from mcp_warden.proxy import STREAM_LIMIT, _start_reader
from mcp_warden.servers import SEP, ServerSpec
from mcp_warden.warden import AUDIT_CONTEXT, CLIENT, Sink, Warden

log = logging.getLogger("mcp_warden")

Message = dict[str, Any]
Notify = Callable[[str, Message], None]
# Answers a request an upstream server sends its client: (server, request, id of the
# gateway's request it arrived with, if known) -> response.
OnRequest = Callable[[str, Message, Any], Awaitable[Message]]

CLIENT_INFO = {"name": "mcp-warden", "version": __version__}
# Where an upstream notification or request goes: (message, client scope or None for
# every client, upstream server name). Returns False when it could not be sent.
Deliver = Callable[[Message, "str | None", str], "bool | None"]

# Client features a server can ask for, by the requests that use them.
CLIENT_FEATURES = {
    "sampling/createMessage": "sampling",
    "elicitation/create": "elicitation",
    "roots/list": "roots",
}


UPDATED = "notifications/resources/updated"
LIST_CHANGED = (
    "notifications/tools/list_changed",
    "notifications/resources/list_changed",
    "notifications/prompts/list_changed",
)


class UpstreamError(RuntimeError):
    pass


def template_regex(template: str) -> re.Pattern[str]:
    """A regex for the URIs an RFC 6570 template can expand to (loosely)."""
    out = []
    for part in re.split(r"(\{[^}]*\})", template):
        if part.startswith("{") and part.endswith("}"):
            op = part[1:2]
            out.append(".+" if op in ("+", "#") else ".*" if op in ("?", "&") else "[^/?#]+")
        else:
            out.append(re.escape(part))
    return re.compile("".join(out))


def _error(msg_id: Any, code: int, message: str) -> Message:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


class Upstream:
    """One MCP server the gateway talks to as a client."""

    def __init__(self, name: str, on_notify: Notify, on_request: OnRequest | None = None):
        self.name = name
        self._on_notify = on_notify
        self._on_request = on_request
        self._ids = itertools.count(1)
        self.capabilities: dict[str, Any] = {}
        # What the gateway tells the server it can do as a client.
        self.client_capabilities: dict[str, Any] = {}

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
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": self.client_capabilities,
                "clientInfo": CLIENT_INFO,
            },
        )
        if "error" in reply:
            raise UpstreamError(f"{self.name}: initialize failed: {reply['error']}")
        result = reply.get("result")
        caps = result.get("capabilities") if isinstance(result, dict) else None
        self.capabilities = caps if isinstance(caps, dict) else {}
        await self.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _incoming(self, msg: Any) -> bool:
        """Pass on a notification; True if ``msg`` is a request that needs answering."""
        if not isinstance(msg, dict) or "method" not in msg:
            return False
        if "id" in msg:
            return True
        self._on_notify(self.name, msg)
        return False

    async def _answer(self, msg: Message, related: Any = None) -> Message:
        """The response to a request from the server (sampling, roots, ping, ...)."""
        if msg.get("method") == "ping":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
        if self._on_request is None:
            return _error(msg["id"], -32601, f"{msg['method']} is not supported by mcp-warden")
        try:
            return await self._on_request(self.name, msg, related)
        except Exception as exc:
            log.exception("%s: answering %s failed", self.name, msg.get("method"))
            return _error(msg["id"], -32603, f"mcp-warden internal error: {exc}")


class StdioUpstream(Upstream):
    def __init__(
        self,
        name: str,
        command: Sequence[str],
        on_notify: Notify,
        on_request: OnRequest | None = None,
    ):
        super().__init__(name, on_notify, on_request)
        self.command = list(command)
        self._proc: asyncio.subprocess.Process | None = None
        self._waiting: dict[Any, asyncio.Future[Message]] = {}
        self._reader: asyncio.Task[None] | None = None
        self._answering: set[asyncio.Task[None]] = set()

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
            if self._incoming(msg):
                # Answered on the side: the reply may wait on the client, and this
                # loop must keep reading meanwhile (e.g. the tool result after it).
                task = asyncio.create_task(self._reply_to(msg))
                self._answering.add(task)
                task.add_done_callback(self._answering.discard)
        for future in self._waiting.values():
            if not future.done():
                future.set_exception(UpstreamError(f"{self.name}: server exited"))
        self._waiting.clear()

    async def _reply_to(self, msg: Message) -> None:
        reply = await self._answer(msg)
        with contextlib.suppress(ConnectionError):
            await self._write(reply)

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
    def __init__(
        self,
        name: str,
        transport: StreamableHTTP,
        on_notify: Notify,
        on_request: OnRequest | None = None,
    ):
        super().__init__(name, on_notify, on_request)
        self.transport = transport
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
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
            if self._incoming(reply) and self._loop is not None:
                # The server waits for this answer before it finishes the response.
                pending = asyncio.run_coroutine_threadsafe(
                    self._answer(reply, msg.get("id")), self._loop
                )
                for _ in self.transport.post(pending.result()):
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
        # What each server last listed, for routing resources/read by URI.
        self._resource_uris: dict[str, set[str]] = {}
        self._templates: dict[str, list[re.Pattern[str]]] = {}
        # Resource subscriptions: (server, uri) -> client scopes. Each URI is subscribed
        # upstream once, however many clients want it, and dropped with the last one.
        self._subscriptions: dict[tuple[str, str], set[str]] = {}
        self._audits: dict[str | None, AuditLog] = {}
        self.wardens: dict[str, Warden] = {}
        self.upstreams: dict[str, Upstream] = {}
        # (client scope, client request id) -> (server, upstream request id), for cancellation
        self._calls: dict[tuple[str, str], tuple[str, int]] = {}
        # Whether clients can be told the tool list changed (stdio, or serve's GET stream).
        self.notifies = True
        # The client a server's request goes to when no call ties it to one: the only
        # client, on stdio; None where several share the gateway.
        self.default_scope: str | None = ""
        self.client_timeout = 300.0
        self._client_caps: dict[str, Message] = {}
        # (client scope, id the gateway gave a request it forwarded) -> its response
        self._forwarded: dict[tuple[str, str], asyncio.Future[Message]] = {}
        self._forward_ids = itertools.count(1)
        # Each client's audit context and identity, for the requests servers send it.
        self._contexts: dict[str, tuple[Any, str | None]] = {}
        self._started = False
        # The client features offered to upstreams, fixed when they first start.
        self._offered: Message = {}
        for spec in self.specs:
            self._add(spec)

    def _add(self, spec: ServerSpec) -> Upstream:
        path = spec.policy.audit_path
        if path not in self._audits:
            self._audits[path] = AuditLog(path)
        self.wardens[spec.name] = Warden(
            spec.policy, audit=self._audits[path], sinks=self.sinks, label=spec.name
        )
        upstream: Upstream
        if spec.url:
            upstream = HttpUpstream(
                spec.name,
                StreamableHTTP(spec.url, spec.headers),
                self._upstream_notification,
                self._server_request,
            )
        else:
            upstream = StdioUpstream(
                spec.name, spec.command, self._upstream_notification, self._server_request
            )
        upstream.client_capabilities = self._offered
        self.upstreams[spec.name] = upstream
        return upstream

    async def _remove(self, name: str) -> None:
        """Stop a server and forget everything routed to it; its calls in flight fail."""
        upstream = self.upstreams.pop(name)
        warden = self.wardens.pop(name)
        self._resource_uris.pop(name, None)
        self._templates.pop(name, None)
        for key in [k for k in self._subscriptions if k[0] == name]:
            del self._subscriptions[key]
        try:
            await upstream.close()
        except Exception as exc:
            log.warning("%s: stopping failed: %s", name, exc)
        path = warden.policy.audit_path
        if not any(w.audit is warden.audit for w in self.wardens.values()):
            self._audits.pop(path, None)
            warden.audit.close()

    # ------------------------------------------------------------------ lifecycle

    async def start(self, client_capabilities: Message | None = None) -> None:
        """Start the upstreams, offering them the client features the client has.

        With ``client_capabilities`` unknown (several clients to come), every feature
        is offered and a request for one a client lacks is refused when it comes.
        """
        if self._started:
            return
        self._started = True
        self._loop = asyncio.get_running_loop()
        features = set(CLIENT_FEATURES.values())
        if client_capabilities is not None:
            features &= set(client_capabilities)
        offered: Message = {f: {} for f in sorted(features)}
        if "roots" in offered and self.default_scope is not None:
            offered["roots"] = {"listChanged": True}  # passed on from the one client
        self._offered = offered
        for upstream in self.upstreams.values():
            upstream.client_capabilities = offered
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

    async def reload(self, specs: Sequence[ServerSpec]) -> list[str]:
        """Switch to new server specs and policies; returns what needs a restart.

        Unchanged servers keep running under their new policy. Added servers are
        started, removed ones stopped, and a server whose command, URL or headers
        changed is restarted. Only audit and telemetry settings take a restart.
        """
        notes: list[str] = []
        new = {spec.name: spec for spec in specs}
        current = {spec.name: spec for spec in self.specs}
        removed = [name for name in current if name not in new]
        for name in removed:
            log.info("reload: stopping server %s", name)
            await self._remove(name)
        starting = []
        for name, spec in new.items():
            old = current.get(name)
            if old is not None and (old.command, old.url, old.headers) == (
                spec.command,
                spec.url,
                spec.headers,
            ):
                notes.extend(f"{name}: {s} changed" for s in self.wardens[name].reload(spec.policy))
                continue
            if old is not None:
                log.info("reload: restarting server %s", name)
                await self._remove(name)
            else:
                log.info("reload: starting server %s", name)
            starting.append((name, self._add(spec)))
        self.specs = list(specs)
        if self._started:
            results = await asyncio.gather(
                *(u.start() for _, u in starting), return_exceptions=True
            )
            for (name, _), result in zip(starting, results, strict=True):
                if isinstance(result, BaseException):
                    log.error("server %s failed to start: %s", name, result)
                    notes.append(f"server {name!r} failed to start")
        # List again so the new policies and lockfiles judge every tool before the next
        # call, then tell clients their lists may have changed.
        await self.list_tools()
        for name in [*self.upstreams, *removed]:
            caps = self.upstreams[name].capabilities if name in self.upstreams else {}
            for method in LIST_CHANGED:
                feature = method.split("/")[1]
                if feature == "tools" or feature in caps or name in removed:
                    self.deliver({"jsonrpc": "2.0", "method": method}, None, name)
        return notes

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
        if method in LIST_CHANGED:
            self.deliver({"jsonrpc": "2.0", "method": method}, None, server)
            return
        if method not in ("notifications/progress", "notifications/message", UPDATED):
            return
        warden = self.wardens[server]
        if warden.policy.redact:
            msg = {**msg, "params": warden.redactor.redact(msg.get("params"))[0]}
        if method == "notifications/message":
            self.deliver(msg, None, server)
            return
        if method == UPDATED:
            uri = str((msg.get("params") or {}).get("uri", ""))
            for scope in sorted(self._subscriptions.get((server, uri), ())):
                self.deliver(msg, scope, server)
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
        if isinstance(msg, dict) and "id" in msg and "method" not in msg:
            # The client answering a request a server sent it through us.
            future = self._forwarded.pop((scope, repr(msg["id"])), None)
            if future is not None and not future.done():
                future.set_result(msg)
            return None
        if not isinstance(msg, dict) or "method" not in msg:
            return None
        if scope:
            self._contexts[scope] = (AUDIT_CONTEXT.get(), CLIENT.get())
        method, params = msg["method"], msg.get("params") or {}
        if method == "notifications/cancelled":
            await self._cancel(params, scope)
            return None
        if method == "notifications/roots/list_changed" and self.default_scope is not None:
            for upstream in self.upstreams.values():
                if "roots" in upstream.client_capabilities:
                    await upstream.notify({"jsonrpc": "2.0", "method": method})
            return None
        if "id" not in msg:
            return None
        msg_id = msg["id"]
        if method == "initialize":
            caps = params.get("capabilities")
            self._client_caps[scope] = caps if isinstance(caps, dict) else {}
            await self.start(self._client_caps[scope] if self.default_scope is not None else None)
            version = params.get("protocolVersion")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": version if isinstance(version, str) else PROTOCOL_VERSION,
                    "capabilities": self._capabilities(),
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
        if method == "resources/list":
            resources = await self.list_resources(allowed)
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": resources}}
        if method == "resources/templates/list":
            templates = await self.list_resource_templates(allowed)
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resourceTemplates": templates}}
        if method == "resources/read":
            return await self._read_resource(msg_id, params, allowed)
        if method == "resources/subscribe":
            return await self._subscribe(msg_id, params, scope, allowed)
        if method == "resources/unsubscribe":
            await self._unsubscribe(str(params.get("uri", "")), scope)
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        if method == "prompts/list":
            prompts = await self.list_prompts(allowed)
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": prompts}}
        if method == "prompts/get":
            return await self._get_prompt(msg_id, params, allowed)
        return _error(msg_id, -32601, f"method not found: {method}")

    def _capabilities(self) -> Message:
        caps: Message = {"tools": {"listChanged": self.notifies}}
        for feature in ("resources", "prompts"):
            if any(feature in u.capabilities for u in self.upstreams.values()):
                caps[feature] = {"listChanged": self.notifies}
        if self._subscribable(None):
            caps["resources"]["subscribe"] = True
        return caps

    def _subscribable(self, allowed: Collection[str] | None) -> list[str]:
        """Servers the client may use whose resources can be subscribed to."""
        return [
            name
            for name in self._serving(allowed, "resources")
            if isinstance(caps := self.upstreams[name].capabilities.get("resources"), dict)
            and caps.get("subscribe")
        ]

    def _serving(self, allowed: Collection[str] | None, feature: str) -> list[str]:
        """Servers, in config order, that the client may use and that offer ``feature``."""
        return [
            name
            for name, upstream in self.upstreams.items()
            if (allowed is None or name in allowed) and feature in upstream.capabilities
        ]

    async def _paginate(self, name: str, method: str, key: str) -> list[Message]:
        upstream, cursor = self.upstreams[name], None
        items: list[Message] = []
        try:
            while True:
                reply = await upstream.call(method, {"cursor": cursor} if cursor else None)
                result = reply.get("result")
                if not isinstance(result, dict):
                    log.error("%s: %s failed: %s", name, method, reply.get("error"))
                    break
                items.extend(i for i in result.get(key) or [] if isinstance(i, dict))
                cursor = result.get("nextCursor")
                if not cursor:
                    break
        except UpstreamError as exc:
            log.error("%s", exc)
        return items

    async def list_resources(self, allowed: Collection[str] | None = None) -> list[Message]:
        names = self._serving(allowed, "resources")
        lists = await asyncio.gather(
            *(self._paginate(n, "resources/list", "resources") for n in names)
        )
        resources, seen = [], set()
        for name, items in zip(names, lists, strict=True):
            uris = {str(r["uri"]) for r in items if isinstance(r.get("uri"), str)}
            self._resource_uris[name] = uris
            for r in self.wardens[name].visible_resources(items):
                uri = r.get("uri")
                if uri in seen:
                    log.warning("%s: resource %s is also listed by an earlier server", name, uri)
                    continue
                seen.add(uri)
                resources.append(r)
        return resources

    async def list_resource_templates(
        self, allowed: Collection[str] | None = None
    ) -> list[Message]:
        names = self._serving(allowed, "resources")
        method, key = "resources/templates/list", "resourceTemplates"
        lists = await asyncio.gather(*(self._paginate(n, method, key) for n in names))
        templates = []
        for name, items in zip(names, lists, strict=True):
            self._templates[name] = [
                template_regex(str(t["uriTemplate"]))
                for t in items
                if isinstance(t.get("uriTemplate"), str)
            ]
            templates.extend(items)
        return templates

    def _known_owners(self, uri: str, candidates: list[str]) -> list[str]:
        """Servers that listed the URI, or else whose URI templates match it."""
        return [n for n in candidates if uri in self._resource_uris.get(n, ())] or [
            n for n in candidates if any(t.fullmatch(uri) for t in self._templates.get(n, ()))
        ]

    def _owners(self, uri: str, candidates: list[str]) -> list[str]:
        """The servers to try for a URI; for one nobody listed yet, each in turn."""
        return self._known_owners(uri, candidates) or candidates

    async def _read_resource(
        self, client_id: Any, params: Message, allowed: Collection[str] | None
    ) -> Message:
        uri = params.get("uri")
        if not isinstance(uri, str):
            return _error(client_id, -32602, "resources/read needs a uri")
        owners = self._owners(uri, self._serving(allowed, "resources"))
        reply: Message = _error(client_id, -32002, f"resource not found: {uri}")
        for name in owners:
            blocked = self.wardens[name].admit_resource(uri)
            if blocked is not None:
                return {"jsonrpc": "2.0", "id": client_id, "result": blocked}
            try:
                answer = await self.upstreams[name].call("resources/read", {"uri": uri})
            except UpstreamError as exc:
                reply = _error(client_id, -32000, f"mcp-warden upstream error: {exc}")
                continue
            if "result" in answer:
                result = self.wardens[name].filter_resource(uri, answer["result"])
                return {"jsonrpc": "2.0", "id": client_id, "result": result}
            reply = {**answer, "id": client_id}
        return reply

    async def _subscribe(
        self, client_id: Any, params: Message, scope: str, allowed: Collection[str] | None
    ) -> Message:
        uri = params.get("uri")
        if not isinstance(uri, str):
            return _error(client_id, -32602, "resources/subscribe needs a uri")
        # Servers tend to accept a subscription to any URI, so trying each in turn
        # would pick the first rather than the owner: find who serves it first, among
        # all servers, so a URI of a server this client may not use goes nowhere.
        every = self._subscribable(None)
        known = self._known_owners(uri, every)
        if not known:
            await asyncio.gather(self.list_resources(), self.list_resource_templates())
            known = self._known_owners(uri, every)
        candidates = self._subscribable(allowed)
        owners = [n for n in known if n in candidates] if known else candidates
        reply: Message = _error(client_id, -32002, f"resource not found: {uri}")
        for name in owners:
            if self.wardens[name].admit_resource(uri, event="resource_subscribe") is not None:
                return _error(client_id, -32002, f"resource not found: {uri}")
            scopes = self._subscriptions.get((name, uri))
            if scopes:  # already subscribed upstream for another client
                scopes.add(scope)
                return {"jsonrpc": "2.0", "id": client_id, "result": {}}
            try:
                answer = await self.upstreams[name].call("resources/subscribe", {"uri": uri})
            except UpstreamError as exc:
                reply = _error(client_id, -32000, f"mcp-warden upstream error: {exc}")
                continue
            if "result" in answer:
                self._subscriptions.setdefault((name, uri), set()).add(scope)
                return {"jsonrpc": "2.0", "id": client_id, "result": {}}
            reply = {**answer, "id": client_id}
        return reply

    async def _unsubscribe(self, uri: str | None, scope: str) -> None:
        """Drop a client's subscription to ``uri``, or to everything when ``uri`` is None."""
        for key in [k for k in self._subscriptions if uri is None or k[1] == uri]:
            scopes = self._subscriptions[key]
            scopes.discard(scope)
            if scopes:
                continue
            del self._subscriptions[key]
            name, sub_uri = key
            try:
                await self.upstreams[name].call("resources/unsubscribe", {"uri": sub_uri})
            except UpstreamError as exc:
                log.warning("%s: unsubscribe from %s failed: %s", name, sub_uri, exc)

    async def forget(self, scope: str) -> None:
        """Release what a client held when its session ends."""
        self._client_caps.pop(scope, None)
        self._contexts.pop(scope, None)
        for key in [k for k in self._forwarded if k[0] == scope]:
            self._forwarded.pop(key).cancel()
        await self._unsubscribe(None, scope)

    # ------------------------------------------------------------------ server requests

    def _requester(self, server: str, related: Any) -> str | None:
        """The client a server's request belongs to: the one whose call it came with."""
        if related is not None:
            for (scope, _), call in self._calls.items():
                if call == (server, related):
                    return scope
        scopes = {scope for (scope, _), (name, _) in self._calls.items() if name == server}
        if len(scopes) == 1:
            return scopes.pop()
        if not scopes:
            return self.default_scope
        return None  # several clients have calls in flight there: ambiguous

    async def _server_request(self, server: str, msg: Message, related: Any) -> Message:
        """Forward a server's request (sampling, elicitation, roots) to its client."""
        method, server_id = str(msg.get("method")), msg["id"]
        scope = self._requester(server, related)
        # Screen as the client it goes to: its limits, and its session in the audit.
        context, who = self._contexts.get(scope or "", (None, None))
        tokens = (AUDIT_CONTEXT.set(context), CLIENT.set(who))
        try:
            forward, refusal = self.wardens[server].screen_server_request(msg)
        finally:
            CLIENT.reset(tokens[1])
            AUDIT_CONTEXT.reset(tokens[0])
        if refusal is not None:
            return refusal
        if scope is None:
            return _error(server_id, -32603, f"mcp-warden: no single client to send {method} to")
        feature = CLIENT_FEATURES.get(method)
        if feature is None or feature not in self._client_caps.get(scope, {}):
            return _error(server_id, -32601, f"{method} is not supported by the client")
        client_id = f"mcp-warden-{next(self._forward_ids)}"
        key = (scope, repr(client_id))
        future: asyncio.Future[Message] = asyncio.get_running_loop().create_future()
        self._forwarded[key] = future
        try:
            if self.deliver({**forward, "id": client_id}, scope, server) is False:
                return _error(server_id, -32603, f"mcp-warden: the client cannot take {method} now")
            answer = await asyncio.wait_for(future, self.client_timeout)
        except asyncio.TimeoutError:
            cancel = {"requestId": client_id, "reason": "timed out"}
            self.deliver(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": cancel},
                scope,
                server,
            )
            return _error(server_id, -32603, f"mcp-warden: the client did not answer {method}")
        except asyncio.CancelledError:
            if not future.cancelled():
                raise  # the gateway is shutting down, not the client leaving
            return _error(server_id, -32603, "mcp-warden: the client went away")
        finally:
            self._forwarded.pop(key, None)
        return {**answer, "id": server_id}

    async def list_prompts(self, allowed: Collection[str] | None = None) -> list[Message]:
        names = self._serving(allowed, "prompts")
        lists = await asyncio.gather(*(self._paginate(n, "prompts/list", "prompts") for n in names))
        return [
            {**p, "name": f"{name}{SEP}{p.get('name')}"}
            for name, items in zip(names, lists, strict=True)
            for p in self.wardens[name].visible_prompts(items)
        ]

    async def _get_prompt(
        self, client_id: Any, params: Message, allowed: Collection[str] | None
    ) -> Message:
        full = str(params.get("name", ""))
        server, sep, prompt = full.partition(SEP)
        if not sep or server not in self._serving(allowed, "prompts"):
            return _error(client_id, -32602, f"unknown prompt: {full}")
        blocked = self.wardens[server].admit_prompt(prompt)
        if blocked is not None:
            return {"jsonrpc": "2.0", "id": client_id, "result": blocked}
        try:
            answer = await self.upstreams[server].call("prompts/get", {**params, "name": prompt})
        except UpstreamError as exc:
            return _error(client_id, -32000, f"mcp-warden upstream error: {exc}")
        if "result" not in answer:
            return {**answer, "id": client_id}
        result = self.wardens[server].filter_prompt(prompt, answer["result"])
        return {"jsonrpc": "2.0", "id": client_id, "result": result}

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

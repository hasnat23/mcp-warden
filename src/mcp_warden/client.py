"""Minimal MCP clients (stdio and Streamable HTTP) used by `scan` and `pin`."""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import os
from collections.abc import Sequence
from typing import Any

from mcp_warden import __version__
from mcp_warden.jsonrpc import decode, encode
from mcp_warden.proxy import STREAM_LIMIT

PROTOCOL_VERSION = "2025-06-18"


class MCPError(RuntimeError):
    pass


class StdioClient:
    def __init__(self, command: Sequence[str], timeout: float = 30.0):
        self.command = list(command)
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._proc: asyncio.subprocess.Process | None = None
        self.server_info: dict[str, Any] = {}

    async def __aenter__(self) -> StdioClient:
        self._proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=STREAM_LIMIT,
            env=os.environ.copy(),
        )
        init = await self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-warden", "version": __version__},
            },
        )
        self.server_info = init.get("serverInfo", {})
        await self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    async def __aexit__(self, *exc: object) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        assert proc.stdin is not None
        with contextlib.suppress(ConnectionError):
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    async def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write(encode(message))
        await self._proc.stdin.drain()

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        req_id = next(self._ids)
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        await self._send(msg)
        return await asyncio.wait_for(self._await_response(req_id), timeout=self.timeout)

    async def _await_response(self, req_id: int) -> dict[str, Any]:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                raise MCPError(f"server exited before answering request {req_id}")
            msg = decode(line)
            if not isinstance(msg, dict):
                continue
            if "method" in msg and "id" in msg:
                # A server->client request (roots/list, sampling...): we offer none.
                await self._send(
                    {
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "error": {"code": -32601, "message": "method not supported"},
                    }
                )
                continue
            if msg.get("id") != req_id:
                continue
            if "error" in msg:
                raise MCPError(f"server error: {msg['error']}")
            result = msg.get("result")
            return result if isinstance(result, dict) else {}

    async def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            result = await self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in result.get("tools", []) if isinstance(t, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools


async def fetch_tools(
    command: Sequence[str], timeout: float = 30.0
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    async with StdioClient(command, timeout=timeout) as client:
        return client.server_info, await client.list_tools()


def fetch_tools_http(
    url: str, headers: dict[str, str] | None = None, timeout: float = 30.0
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch a remote Streamable HTTP server's tools (blocking)."""
    from mcp_warden.http_transport import StreamableHTTP

    transport = StreamableHTTP(url, headers, timeout=timeout)
    ids = itertools.count(1)

    def request(method: str, params: dict[str, Any]) -> dict[str, Any]:
        req_id = next(ids)
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        result: dict[str, Any] | None = None
        for reply in transport.post(msg):
            if not isinstance(reply, dict):
                continue
            if "method" in reply and "id" in reply:
                refusal = {
                    "jsonrpc": "2.0",
                    "id": reply["id"],
                    "error": {"code": -32601, "message": "method not supported"},
                }
                list(transport.post(refusal))
            elif reply.get("id") == req_id:
                if "error" in reply:
                    raise MCPError(f"server error: {reply['error']}")
                result = reply.get("result") if isinstance(reply.get("result"), dict) else {}
        if result is None:
            raise MCPError(f"no response to {method}")
        return result

    try:
        init = request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-warden", "version": __version__},
            },
        )
        list(transport.post({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page = request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in page.get("tools", []) if isinstance(t, dict))
            cursor = page.get("nextCursor")
            if not cursor:
                return init.get("serverInfo", {}), tools
    finally:
        transport.close()

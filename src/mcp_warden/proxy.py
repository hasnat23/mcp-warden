"""stdio transport: run an MCP server as a child process behind a Warden."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import threading
from collections.abc import Sequence
from typing import BinaryIO

from mcp_warden.http_transport import StreamableHTTP, TransportError
from mcp_warden.jsonrpc import decode, encode
from mcp_warden.warden import Outcome, Warden

log = logging.getLogger("mcp_warden")

STREAM_LIMIT = 32 * 1024 * 1024  # MCP results (file contents, images) can be large.


def _start_reader(stream: BinaryIO, loop: asyncio.AbstractEventLoop) -> asyncio.Queue[bytes]:
    """Read a blocking stream on a daemon thread so it never blocks interpreter exit."""
    queue: asyncio.Queue[bytes] = asyncio.Queue()

    def pump() -> None:
        try:
            for line in iter(stream.readline, b""):
                loop.call_soon_threadsafe(queue.put_nowait, line)
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, b"")

    threading.Thread(target=pump, name="mcp-warden-stdin", daemon=True).start()
    return queue


async def run_stdio_proxy(
    command: Sequence[str],
    warden: Warden,
    *,
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
) -> int:
    client_in = client_in or sys.stdin.buffer
    client_out = client_out or sys.stdout.buffer
    loop = asyncio.get_running_loop()

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # server logs go straight to our stderr, i.e. the client's log
        limit=STREAM_LIMIT,
        env=os.environ.copy(),
    )
    assert proc.stdin is not None and proc.stdout is not None
    server_in, server_out = proc.stdin, proc.stdout

    def write_client(messages: list[object]) -> None:
        for m in messages:
            client_out.write(encode(m))
        if messages:
            client_out.flush()

    async def dispatch(outcome: Outcome) -> None:
        write_client(outcome.to_client)
        for m in outcome.to_server:
            server_in.write(encode(m))
        if outcome.to_server:
            await server_in.drain()

    async def client_to_server() -> None:
        queue = _start_reader(client_in, loop)
        while line := await queue.get():
            msg = decode(line)
            if msg is not None:
                await dispatch(warden.from_client(msg))
        with contextlib.suppress(ConnectionError):
            server_in.close()

    async def server_to_client() -> None:
        while line := await server_out.readline():
            msg = decode(line)
            if msg is not None:
                await dispatch(warden.from_server(msg))

    upstream = asyncio.create_task(client_to_server())
    downstream = asyncio.create_task(server_to_client())
    try:
        # The session ends when the server closes stdout (it exited or the client hung up).
        await downstream
    finally:
        upstream.cancel()
        with contextlib.suppress(asyncio.CancelledError, ConnectionError):
            await upstream
        if proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.terminate()
                await proc.wait()
        warden.audit.close()
    log.info("server exited with code %s", proc.returncode)
    return proc.returncode or 0


def _upstream_error(msg: object, exc: Exception) -> dict[str, object] | None:
    """A JSON-RPC error for a request whose HTTP round trip failed."""
    if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
        return None
    return {
        "jsonrpc": "2.0",
        "id": msg["id"],
        "error": {"code": -32000, "message": f"mcp-warden upstream error: {exc}"},
    }


async def run_http_bridge(
    transport: StreamableHTTP,
    warden: Warden,
    *,
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
) -> int:
    """Expose a remote Streamable HTTP server to a stdio client, through the Warden.

    Many MCP clients only speak stdio; this lets them use remote servers with the
    same policy, scanning and redaction as local ones.
    """
    client_in = client_in or sys.stdin.buffer
    client_out = client_out or sys.stdout.buffer
    loop = asyncio.get_running_loop()
    inbound: asyncio.Queue[object] = asyncio.Queue()
    failures = 0

    def post(msg: object) -> None:
        # Runs on a worker thread: one HTTP round trip, which may stream many messages.
        nonlocal failures
        try:
            for reply in transport.post(msg):
                loop.call_soon_threadsafe(inbound.put_nowait, reply)
        except TransportError as exc:
            failures += 1
            log.error("%s", exc)
            error = _upstream_error(msg, exc)
            if error is not None:
                loop.call_soon_threadsafe(inbound.put_nowait, error)

    def write_client(messages: list[object]) -> None:
        for m in messages:
            client_out.write(encode(m))
        if messages:
            client_out.flush()

    in_flight: set[asyncio.Task[None]] = set()

    def send_upstream(messages: list[object]) -> None:
        for m in messages:
            task = asyncio.ensure_future(asyncio.to_thread(post, m))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)

    async def server_to_client() -> None:
        while True:
            msg = await inbound.get()
            outcome = warden.from_server(msg)
            write_client(outcome.to_client)
            send_upstream(outcome.to_server)

    downstream = asyncio.create_task(server_to_client())
    queue = _start_reader(client_in, loop)
    try:
        while line := await queue.get():
            msg = decode(line)
            if msg is None:
                continue
            outcome = warden.from_client(msg)
            write_client(outcome.to_client)
            if isinstance(msg, dict) and msg.get("method") == "initialize":
                # Later requests need the session id this response hands out.
                for m in outcome.to_server:
                    await asyncio.to_thread(post, m)
            else:
                send_upstream(outcome.to_server)
        if in_flight:
            await asyncio.wait(set(in_flight), timeout=30)
        while not inbound.empty():  # let server_to_client flush what is queued
            await asyncio.sleep(0)
        await asyncio.sleep(0)
    finally:
        downstream.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await downstream
        await asyncio.to_thread(transport.close)
        warden.audit.close()
    return 1 if failures else 0

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

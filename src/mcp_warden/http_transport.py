"""MCP Streamable HTTP transport (client side), stdlib only.

Each JSON-RPC message is POSTed to the server's MCP endpoint. The server answers
with 202 (for notifications and responses), a single JSON body, or an SSE stream
that may carry notifications and server-to-client requests before the final
response. The session id handed out on ``initialize`` is echoed on every later
request, and the session is ended with DELETE on shutdown.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import IO, Any

log = logging.getLogger("mcp_warden")

SESSION_HEADER = "Mcp-Session-Id"
VERSION_HEADER = "MCP-Protocol-Version"


class TransportError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def parse_header(value: str) -> tuple[str, str]:
    """Parse a ``"Name: value"`` CLI header."""
    name, sep, val = value.partition(":")
    if not sep or not name.strip():
        raise ValueError(f"header must look like 'Name: value', got {value!r}")
    return name.strip(), val.strip()


def iter_sse(stream: IO[bytes]) -> Iterator[str]:
    """Yield the data payload of each event in a text/event-stream."""
    data: list[str] = []
    for raw in stream:
        line = raw.decode("utf-8").rstrip("\r\n")
        if not line:
            if data:
                yield "\n".join(data)
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        # id:, event:, retry: and comments carry nothing we need.
    if data:
        yield "\n".join(data)


def _messages(payload: Any) -> Iterable[Any]:
    return payload if isinstance(payload, list) else [payload]


class StreamableHTTP:
    def __init__(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        timeout: float = 300.0,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ):
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._open = opener

    def _request_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id
        if self.protocol_version:
            headers[VERSION_HEADER] = self.protocol_version
        return headers

    def post(self, message: Any) -> Iterator[Any]:
        """Send one message and yield every message the server sends back for it."""
        body = json.dumps(message, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=body, method="POST", headers=self._request_headers()
        )
        try:
            resp = self._open(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read(500).decode("utf-8", "replace").strip()
            if exc.code == 404 and self.session_id:
                detail = f"session {self.session_id} expired or unknown. {detail}".strip()
            raise TransportError(f"HTTP {exc.code} {exc.reason}: {detail}", exc.code) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise TransportError(f"cannot reach {self.url}: {exc}") from exc

        with resp:
            session = resp.headers.get(SESSION_HEADER)
            if session:
                self.session_id = session
            if resp.status == 202:
                return
            ctype = resp.headers.get_content_type()
            if ctype == "text/event-stream":
                for data in iter_sse(resp):
                    try:
                        payload = json.loads(data)
                    except json.JSONDecodeError:
                        log.warning("ignoring non-JSON SSE event from upstream")
                        continue
                    yield from self._track(_messages(payload))
            else:
                raw = resp.read()
                if raw.strip():
                    yield from self._track(_messages(json.loads(raw)))

    def _track(self, messages: Iterable[Any]) -> Iterator[Any]:
        for msg in messages:
            # Every request after initialize must carry the negotiated version.
            if isinstance(msg, dict) and isinstance(msg.get("result"), dict):
                version = msg["result"].get("protocolVersion")
                if isinstance(version, str) and "serverInfo" in msg["result"]:
                    self.protocol_version = version
            yield msg

    def close(self) -> None:
        """End the session (best effort; servers may answer 405)."""
        if not self.session_id:
            return
        req = urllib.request.Request(self.url, method="DELETE", headers=self._request_headers())
        try:
            self._open(req, timeout=10).close()
        except (urllib.error.URLError, OSError) as exc:
            log.debug("session DELETE failed: %s", exc)
        self.session_id = None

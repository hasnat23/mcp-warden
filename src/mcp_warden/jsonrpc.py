"""Newline-delimited JSON-RPC framing used by the MCP stdio transport."""

from __future__ import annotations

import json
from typing import Any


class Raw(bytes):
    """A line that was not valid JSON; forwarded untouched."""


def decode(line: bytes) -> Any:
    stripped = line.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Raw(line)


def encode(message: Any) -> bytes:
    if isinstance(message, Raw):
        return bytes(message) if message.endswith(b"\n") else bytes(message) + b"\n"
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"

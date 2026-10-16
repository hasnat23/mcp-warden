"""Append-only JSONL audit log."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


class AuditLog:
    def __init__(self, path: str | Path | None):
        self._fh: TextIO | None = None
        self._lock = threading.Lock()
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fh = p.open("a", encoding="utf-8")

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **fields,
        }
        if self._fh is not None:
            line = json.dumps(record, ensure_ascii=False, default=str)
            with self._lock:
                self._fh.write(line + "\n")
                self._fh.flush()
        return record

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

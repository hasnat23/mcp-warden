"""Tool definition pinning ("lockfile") to detect rug-pull attacks.

An MCP server can return harmless tool descriptions when a user first approves
it and swap in malicious ones later. Pinning stores a hash of every tool
definition; any later drift is surfaced before the model ever sees it.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_warden.findings import Finding, Severity

LOCK_VERSION = 1
_HASHED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def tool_fingerprint(tool: dict[str, Any]) -> str:
    material = {k: tool[k] for k in _HASHED_FIELDS if k in tool}
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class Lockfile:
    path: Path
    tools: dict[str, str] = field(default_factory=dict)
    exists: bool = False

    @classmethod
    def load(cls, path: str | Path) -> Lockfile:
        p = Path(path)
        if not p.exists():
            return cls(p)
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("version") != LOCK_VERSION:
            raise ValueError(f"{p}: unsupported lockfile version {data.get('version')!r}")
        return cls(p, dict(data.get("tools", {})), exists=True)

    def save(self) -> None:
        payload = {"version": LOCK_VERSION, "tools": dict(sorted(self.tools.items()))}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write so a crash never leaves a truncated lockfile behind.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".warden-lock-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, self.path)
        self.exists = True

    def pin(self, tools: list[dict[str, Any]]) -> None:
        self.tools = {str(t["name"]): tool_fingerprint(t) for t in tools if "name" in t}

    def check(self, tools: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        current = {str(t.get("name")): tool_fingerprint(t) for t in tools}
        for name, digest in current.items():
            pinned = self.tools.get(name)
            if pinned is None:
                findings.append(
                    Finding(
                        "MW101",
                        Severity.MEDIUM,
                        "tool is not in the lockfile (new since last pin)",
                        name,
                        evidence=digest,
                    )
                )
            elif pinned != digest:
                findings.append(
                    Finding(
                        "MW100",
                        Severity.HIGH,
                        "tool definition changed since it was pinned (possible rug pull)",
                        name,
                        evidence=f"{pinned} -> {digest}",
                    )
                )
        for name in self.tools.keys() - current.keys():
            findings.append(
                Finding("MW102", Severity.LOW, "pinned tool is no longer offered", name)
            )
        return findings

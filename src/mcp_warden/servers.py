"""Multi-server configuration: one mcp-warden process in front of several servers."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_warden.policy import Policy, PolicyError, load_policy

# Tools are exposed to the client as "<server><SEP><tool>".
SEP = "__"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,31}$")


@dataclass
class ServerSpec:
    name: str
    policy: Policy
    command: list[str] = field(default_factory=list)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


def lockfile_for(path: str, server: str) -> str:
    # Lockfiles are keyed by tool name, so servers must never share one.
    p = Path(path)
    return str(p.with_name(f"{p.stem}.{server}{p.suffix or '.json'}"))


def load_servers(path: str | Path) -> list[ServerSpec]:
    """Parse a servers file::

    policy: warden.yaml            # default for every server (optional)
    servers:
      fs:
        command: npx -y @modelcontextprotocol/server-filesystem /srv/data
      tracker:
        url: https://mcp.example.com/mcp
        headers: {Authorization: "Bearer ${TRACKER_TOKEN}"}
        policy: strict.yaml        # per-server override
    """
    p = Path(path)
    base = p.resolve().parent
    data: Any = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        raise PolicyError(f"{p}: expected a 'servers' mapping")
    if not data["servers"]:
        raise PolicyError(f"{p}: 'servers' is empty")

    def policy_at(ref: Any) -> Policy:
        if ref is None:
            return load_policy(None)
        ref_path = Path(str(ref))
        return load_policy(ref_path if ref_path.is_absolute() else base / ref_path)

    default_ref = data.get("policy")
    specs = []
    for name, raw in data["servers"].items():
        name = str(name)
        if not _NAME.match(name) or SEP in name:
            raise PolicyError(
                f"server name {name!r} must be 1-32 letters, digits or '-' (it prefixes tool names)"
            )
        if not isinstance(raw, dict):
            raise PolicyError(f"servers.{name} must be a mapping")
        command = raw.get("command")
        url = raw.get("url")
        if bool(command) == bool(url):
            raise PolicyError(f"servers.{name}: set exactly one of 'command' or 'url'")
        if isinstance(command, str):
            command = shlex.split(command)
        policy = policy_at(raw.get("policy", default_ref))
        if policy.lockfile:
            policy.lockfile = lockfile_for(policy.lockfile, name)
        headers = {
            str(k): os.path.expandvars(str(v)) for k, v in (raw.get("headers") or {}).items()
        }
        specs.append(
            ServerSpec(
                name=name,
                policy=policy,
                command=[os.path.expandvars(str(c)) for c in command or []],
                url=os.path.expandvars(str(url)) if url else None,
                headers=headers,
            )
        )
    return specs

"""Multi-server configuration: one mcp-warden process in front of several servers."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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


@dataclass(frozen=True)
class ClientSpec:
    """A caller of ``mcp-warden serve``, identified by its bearer token."""

    name: str
    token_sha256: str
    servers: frozenset[str] | None = None  # None: every server


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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


def load_clients(path: str | Path, servers: list[ServerSpec]) -> list[ClientSpec]:
    """Parse the optional ``clients`` section, used by ``serve``::

    clients:
      alice:
        token: ${ALICE_TOKEN}         # read from the environment
      ci:
        token_sha256: 9f86d08...      # or store only the hash
        servers: [fs]                 # limit to some servers (default: all)
    """
    p = Path(path)
    data: Any = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    raw_clients = data.get("clients") if isinstance(data, dict) else None
    if raw_clients is None:
        return []
    if not isinstance(raw_clients, dict) or not raw_clients:
        raise PolicyError(f"{p}: 'clients' must be a non-empty mapping")
    known = {s.name for s in servers}
    clients: list[ClientSpec] = []
    for name, raw in raw_clients.items():
        name = str(name)
        if not _NAME.match(name):
            raise PolicyError(f"client name {name!r} must be 1-32 letters, digits or '-'")
        if not isinstance(raw, dict) or ("token" in raw) == ("token_sha256" in raw):
            raise PolicyError(f"clients.{name}: set exactly one of 'token' or 'token_sha256'")
        if "token" in raw:
            token = os.path.expandvars(str(raw["token"] or ""))
            if not token or "$" in token:
                raise PolicyError(f"clients.{name}: token is empty or its variable is unset")
            digest = token_digest(token)
        else:
            digest = str(raw["token_sha256"]).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise PolicyError(f"clients.{name}: token_sha256 must be 64 hex characters")
        allowed = None
        if raw.get("servers") is not None:
            allowed = frozenset(str(s) for s in raw["servers"])
            if unknown := sorted(allowed - known):
                raise PolicyError(f"clients.{name}: unknown server(s) {', '.join(unknown)}")
        if any(c.token_sha256 == digest for c in clients):
            raise PolicyError(f"clients.{name}: token is shared with another client")
        clients.append(ClientSpec(name, digest, allowed))
    return clients


def load_oauth(path: str | Path) -> Any:
    """Parse the optional ``oauth`` section, used by ``serve``::

    oauth:
      issuer: https://login.example.com/realms/acme
      audience: https://warden.example.com/mcp   # this server's public URL
      scopes: [mcp]                              # required in every token
      user_claim: email                          # who the caller is (default: sub)
    """
    from mcp_warden.oauth import OAuthConfig

    p = Path(path)
    data: Any = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    raw = data.get("oauth") if isinstance(data, dict) else None
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyError(f"{p}: 'oauth' must be a mapping")
    values = {k: os.path.expandvars(str(raw[k])) for k in ("issuer", "audience") if raw.get(k)}
    for key in ("issuer", "audience"):
        if key not in values:
            raise PolicyError(f"oauth.{key} is required")
    jwks_uri = os.path.expandvars(str(raw["jwks_uri"])) if raw.get("jwks_uri") else None
    for key, url in [*values.items(), ("jwks_uri", jwks_uri)]:
        if url is None:
            continue
        parts = urlsplit(url)
        local = parts.hostname in ("localhost", "127.0.0.1", "::1")
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            raise PolicyError(f"oauth.{key} must be an https URL, got {url!r}")
    scopes = raw.get("scopes") or []
    if not isinstance(scopes, list):
        raise PolicyError("oauth.scopes must be a list")
    return OAuthConfig(
        issuer=values["issuer"],
        audience=values["audience"],
        scopes=[str(s) for s in scopes],
        user_claim=str(raw.get("user_claim") or "sub"),
        jwks_uri=jwks_uri,
    )

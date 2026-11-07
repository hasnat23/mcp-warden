"""Policy model and YAML loader."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal

import yaml

from mcp_warden.findings import Severity

Mode = Literal["enforce", "monitor"]
Action = Literal["block", "warn", "off"]


@dataclass(frozen=True)
class ArgumentRule:
    """Deny a call when an argument (or any string argument, if ``arg`` is None) matches."""

    tool: str
    pattern: re.Pattern[str]
    arg: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class RateLimit:
    tool: str
    max_calls: int
    per_seconds: float

    @property
    def shared(self) -> bool:
        """Glob limits share one budget across all matching tools."""
        return any(ch in self.tool for ch in "*?[")


@dataclass
class Policy:
    mode: Mode = "enforce"
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    resource_allow: list[str] = field(default_factory=list)
    resource_deny: list[str] = field(default_factory=list)
    prompt_allow: list[str] = field(default_factory=list)
    prompt_deny: list[str] = field(default_factory=list)
    server_request_allow: list[str] = field(default_factory=list)
    server_request_deny: list[str] = field(default_factory=list)
    # Limits on requests the server sends the client (``tool`` holds the method glob).
    server_request_limits: list[RateLimit] = field(default_factory=list)
    # Upper bound on maxTokens in sampling requests, so a server cannot ask for more.
    sampling_max_tokens: int | None = None
    argument_rules: list[ArgumentRule] = field(default_factory=list)
    rate_limits: list[RateLimit] = field(default_factory=list)
    scan_descriptions: Action = "block"
    scan_results: Action = "warn"
    block_severity: Severity = Severity.HIGH
    redact: bool = True
    redact_extra: list[tuple[str, str]] = field(default_factory=list)
    lockfile: str | None = None
    on_change: Action = "block"
    audit_path: str | None = None
    audit_arguments: bool = False
    otel: bool = False
    otel_service_name: str = "mcp-warden"

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    def tool_allowed(self, name: str) -> str | None:
        """Return a denial reason, or None if the tool name passes allow/deny lists."""
        return _check_lists("tool", name, self.allow, self.deny)

    def resource_allowed(self, uri: str) -> str | None:
        """Return a denial reason, or None if the resource URI passes allow/deny lists."""
        return _check_lists("resource", uri, self.resource_allow, self.resource_deny)

    def prompt_allowed(self, name: str) -> str | None:
        """Return a denial reason, or None if the prompt name passes allow/deny lists."""
        return _check_lists("prompt", name, self.prompt_allow, self.prompt_deny)

    def server_request_allowed(self, method: str) -> str | None:
        """Return a denial reason for a request the server sends the client (e.g. sampling)."""
        return _check_lists(
            "server request", method, self.server_request_allow, self.server_request_deny
        )

    def check_arguments(self, name: str, arguments: dict[str, Any]) -> str | None:
        for rule in self.argument_rules:
            if not fnmatchcase(name, rule.tool):
                continue
            if rule.arg is not None:
                candidates = [(rule.arg, arguments.get(rule.arg))]
            else:
                candidates = list(_walk_strings(arguments))
            for key, value in candidates:
                if isinstance(value, str) and rule.pattern.search(value):
                    why = rule.reason or f"matches {rule.pattern.pattern!r}"
                    return f"argument {key!r} of {name!r} denied: {why}"
        return None


def _check_lists(kind: str, name: str, allow: list[str], deny: list[str]) -> str | None:
    for pattern in deny:
        if fnmatchcase(name, pattern):
            return f"{kind} {name!r} matches deny rule {pattern!r}"
    if allow and not any(fnmatchcase(name, p) for p in allow):
        return f"{kind} {name!r} is not in the allow list"
    return None


def _walk_strings(value: Any, path: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.extend(_walk_strings(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.extend(_walk_strings(v, f"{path}[{i}]"))
    elif isinstance(value, str):
        out.append((path, value))
    return out


class PolicyError(ValueError):
    pass


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def _action(value: Any, key: str, default: Action) -> Action:
    if value is None:
        return default
    if value is False:
        return "off"
    _expect(value in ("block", "warn", "off"), f"{key} must be block|warn|off, got {value!r}")
    return value  # type: ignore[no-any-return]


def policy_from_dict(data: dict[str, Any], base_dir: Path | None = None) -> Policy:
    _expect(isinstance(data, dict), "policy must be a mapping")
    version = data.get("version", 1)
    _expect(version == 1, f"unsupported policy version {version!r}")

    def rel(path: str | None) -> str | None:
        if path is None or base_dir is None or Path(path).is_absolute():
            return path
        return str(base_dir / path)

    mode = data.get("mode", "enforce")
    _expect(mode in ("enforce", "monitor"), f"mode must be enforce|monitor, got {mode!r}")

    def lists(key: str) -> tuple[list[str], list[str]]:
        section = data.get(key) or {}
        _expect(isinstance(section, dict), f"{key} must be a mapping with allow/deny lists")
        out = []
        for which in ("allow", "deny"):
            patterns = section.get(which) or []
            _expect(isinstance(patterns, list), f"{key}.{which} must be a list of patterns")
            out.append([str(p) for p in patterns])
        return out[0], out[1]

    allow, deny = lists("tools")
    resource_allow, resource_deny = lists("resources")
    prompt_allow, prompt_deny = lists("prompts")
    server_request_allow, server_request_deny = lists("server_requests")

    arg_rules = []
    for i, raw in enumerate(data.get("arguments") or []):
        _expect("deny_pattern" in raw, f"arguments[{i}] needs deny_pattern")
        try:
            pattern = re.compile(raw["deny_pattern"])
        except re.error as exc:
            raise PolicyError(f"arguments[{i}].deny_pattern: {exc}") from exc
        arg_rules.append(
            ArgumentRule(str(raw.get("tool", "*")), pattern, raw.get("arg"), raw.get("reason"))
        )

    limits: list[RateLimit] = []
    request_limits: list[RateLimit] = []
    for i, raw in enumerate(data.get("rate_limits") or []):
        _expect(isinstance(raw, dict), f"rate_limits[{i}] must be a mapping")
        _expect(
            "max_calls" in raw and "per_seconds" in raw,
            f"rate_limits[{i}] needs max_calls and per_seconds",
        )
        _expect(int(raw["max_calls"]) > 0, f"rate_limits[{i}].max_calls must be positive")
        _expect(float(raw["per_seconds"]) > 0, f"rate_limits[{i}].per_seconds must be positive")
        _expect(
            not ("tool" in raw and "server_request" in raw),
            f"rate_limits[{i}] limits either a tool or a server_request, not both",
        )
        target = raw.get("server_request", raw.get("tool", "*"))
        limit = RateLimit(str(target), int(raw["max_calls"]), float(raw["per_seconds"]))
        (request_limits if "server_request" in raw else limits).append(limit)

    max_tokens = (data.get("server_requests") or {}).get("max_tokens")
    _expect(
        max_tokens is None or (isinstance(max_tokens, int) and max_tokens > 0),
        f"server_requests.max_tokens must be a positive integer, got {max_tokens!r}",
    )

    scan = data.get("scan") or {}
    redact = data.get("redact", {})
    if isinstance(redact, bool):
        redact = {"enabled": redact}
    pinning = data.get("pinning") or {}
    audit = data.get("audit") or {}
    telemetry = data.get("telemetry") or {}

    return Policy(
        mode=mode,
        allow=allow,
        deny=deny,
        resource_allow=resource_allow,
        resource_deny=resource_deny,
        prompt_allow=prompt_allow,
        prompt_deny=prompt_deny,
        server_request_allow=server_request_allow,
        server_request_deny=server_request_deny,
        server_request_limits=request_limits,
        sampling_max_tokens=max_tokens,
        argument_rules=arg_rules,
        rate_limits=limits,
        scan_descriptions=_action(scan.get("descriptions"), "scan.descriptions", "block"),
        scan_results=_action(scan.get("results"), "scan.results", "warn"),
        block_severity=Severity.parse(scan.get("block_severity", "high")),
        redact=bool(redact.get("enabled", True)),
        redact_extra=[(str(p["name"]), str(p["pattern"])) for p in redact.get("patterns") or []],
        lockfile=rel(pinning.get("lockfile")),
        on_change=_action(pinning.get("on_change"), "pinning.on_change", "block"),
        audit_path=rel(audit.get("path")),
        audit_arguments=bool(audit.get("log_arguments", False)),
        otel=bool(telemetry.get("otel", False)),
        otel_service_name=str(telemetry.get("service_name", "mcp-warden")),
    )


def load_policy(path: str | Path | None) -> Policy:
    """Load a policy file. ``None`` gives the default policy (scan + redact, no lists)."""
    if path is None:
        return Policy()
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return policy_from_dict(data, base_dir=p.resolve().parent)

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

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    def tool_allowed(self, name: str) -> str | None:
        """Return a denial reason, or None if the tool name passes allow/deny lists."""
        for pattern in self.deny:
            if fnmatchcase(name, pattern):
                return f"tool {name!r} matches deny rule {pattern!r}"
        if self.allow and not any(fnmatchcase(name, p) for p in self.allow):
            return f"tool {name!r} is not in the allow list"
        return None

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

    tools = data.get("tools") or {}
    allow = [str(p) for p in tools.get("allow") or []]
    deny = [str(p) for p in tools.get("deny") or []]

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

    limits = []
    for i, raw in enumerate(data.get("rate_limits") or []):
        _expect(
            "max_calls" in raw and "per_seconds" in raw,
            f"rate_limits[{i}] needs max_calls and per_seconds",
        )
        _expect(int(raw["max_calls"]) > 0, f"rate_limits[{i}].max_calls must be positive")
        _expect(float(raw["per_seconds"]) > 0, f"rate_limits[{i}].per_seconds must be positive")
        limits.append(
            RateLimit(str(raw.get("tool", "*")), int(raw["max_calls"]), float(raw["per_seconds"]))
        )

    scan = data.get("scan") or {}
    redact = data.get("redact", {})
    if isinstance(redact, bool):
        redact = {"enabled": redact}
    pinning = data.get("pinning") or {}
    audit = data.get("audit") or {}

    return Policy(
        mode=mode,
        allow=allow,
        deny=deny,
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
    )


def load_policy(path: str | Path | None) -> Policy:
    """Load a policy file. ``None`` gives the default policy (scan + redact, no lists)."""
    if path is None:
        return Policy()
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return policy_from_dict(data, base_dir=p.resolve().parent)

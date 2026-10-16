"""Secret redaction for tool results and audit records."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

# Order matters: more specific prefixes first so a key is labelled precisely.
DEFAULT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("openai-key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("stripe-key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    (
        "password-assignment",
        r"(?i)\b(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token)"
        r"[\"']?\s*[:=]\s*[\"']?(?P<secret>[^\s\"',;]{6,})",
    ),
)


def _replacer(name: str) -> Callable[[re.Match[str]], str]:
    label = f"[REDACTED:{name}]"

    def replace(match: re.Match[str]) -> str:
        # Patterns with a named "secret" group keep their context (e.g. "password=").
        if "secret" in match.re.groupindex:
            start, end = match.span("secret")
            offset = match.start()
            whole = match.group(0)
            return whole[: start - offset] + label + whole[end - offset :]
        return label

    return replace


@dataclass
class Redactor:
    patterns: list[tuple[str, re.Pattern[str]]] = field(default_factory=list)

    @classmethod
    def build(cls, extra: Iterable[tuple[str, str]] = ()) -> Redactor:
        compiled = [(name, re.compile(rx)) for name, rx in (*DEFAULT_PATTERNS, *extra)]
        return cls(compiled)

    def redact_text(self, text: str) -> tuple[str, int]:
        count = 0
        for name, pattern in self.patterns:
            text, n = pattern.subn(_replacer(name), text)
            count += n
        return text, count

    def redact(self, value: Any) -> tuple[Any, int]:
        """Return a redacted deep copy of any JSON value and the number of hits."""
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, list):
            total = 0
            out_list = []
            for item in value:
                red, n = self.redact(item)
                out_list.append(red)
                total += n
            return out_list, total
        if isinstance(value, dict):
            total = 0
            out_dict = {}
            for key, item in value.items():
                red, n = self.redact(item)
                out_dict[key] = red
                total += n
            return out_dict, total
        return value, 0

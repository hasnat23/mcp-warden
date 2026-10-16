"""Static detection of tool poisoning and prompt injection in MCP text.

Tool descriptions are read by the model verbatim, so a malicious or compromised
server can hide instructions in them ("tool poisoning"). The same goes for tool
results, which flow back into the context window. The rules here are fast,
explainable regex and character-class checks: they will not catch everything,
but they catch the published attack patterns and give a precise reason when
they fire.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from mcp_warden.findings import Finding, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


_I = re.IGNORECASE | re.DOTALL

RULES: tuple[Rule, ...] = (
    Rule(
        "MW001",
        "instruction-override",
        Severity.HIGH,
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|"
            r"system|other)\b.{0,20}\b(instructions?|prompts?|rules|guidelines|directives)\b",
            _I,
        ),
        "attempts to override the model's instructions",
    ),
    Rule(
        "MW002",
        "hidden-directive-tag",
        Severity.HIGH,
        re.compile(
            r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|critical|"
            r"assistant|sudo)\s*>",
            _I,
        ),
        "contains a pseudo-markup tag commonly used to smuggle directives",
    ),
    Rule(
        "MW003",
        "concealment",
        Severity.HIGH,
        re.compile(
            r"\b(do\s+not|don't|never|without)\s+(tell(ing)?|inform(ing)?|mention(ing)?|"
            r"reveal(ing)?|notify(ing)?|alert(ing)?|show(ing)?)\b.{0,30}\b(user|human|operator)\b",
            _I,
        ),
        "asks the model to hide behaviour from the user",
    ),
    Rule(
        "MW004",
        "sensitive-path",
        Severity.HIGH,
        re.compile(
            r"(~|\$HOME|/home/\w+|/Users/\w+)?/?\.(ssh|aws|gnupg|kube|docker)\b|"
            r"\bid_(rsa|ed25519|ecdsa)\b|\.env\b|credentials\.json|/etc/(passwd|shadow)|"
            r"\bmcp\.json\b|claude_desktop_config\.json",
            _I,
        ),
        "references credentials or other sensitive files",
    ),
    Rule(
        "MW006",
        "tool-shadowing",
        Severity.MEDIUM,
        re.compile(
            r"\b(before|after|instead\s+of|whenever|when)\s+(using|calling|invoking|running)\s+"
            # "before using this tool" is self-referential and normal; naming another one is not.
            r"(the\s+|any\s+)?(?!this\b)[`'\"]?[\w.-]+[`'\"]?\s+(tool|function)",
            _I,
        ),
        "tries to change how the model uses other tools",
    ),
    Rule(
        "MW007",
        "exfiltration",
        Severity.MEDIUM,
        re.compile(
            r"\b(send|post|upload|forward|transmit|exfiltrate|leak)\b.{0,60}"
            r"(https?://|\bwebhook\b|\b[\w.-]+@[\w-]+\.[\w.]+\b|\bsidenote\b)|"
            r"\b(pass|put|place|include|embed)\b.{0,60}\b(contents?|keys?|tokens?|passwords?|"
            r"secrets?|credentials?)\b.{0,40}\b(param(eter)?|argument|field|sidenote)\b",
            _I,
        ),
        "instructs data to be sent somewhere or smuggled through a parameter",
    ),
    Rule(
        "MW009",
        "shell-payload",
        Severity.MEDIUM,
        re.compile(
            r"(curl|wget)\s+[^\s|]+\s*\|\s*(ba|z)?sh\b|\brm\s+-rf\s+[/~]|base64\s+(-d|--decode)",
            _I,
        ),
        "contains a shell payload",
    ),
)

# Characters that render as nothing, or reorder text, so a human reviewer reading
# the description in a UI sees something different from what the model reads.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")

MAX_DESCRIPTION_CHARS = 2000


def _visible(text: str, limit: int = 80) -> str:
    cleaned = _INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)
    cleaned = " ".join(cleaned.split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _decode_tag_chars(text: str) -> str:
    """Unicode 'tag' characters (U+E0020..U+E007E) mirror ASCII and are invisible."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def scan_text(text: str, *, tool: str | None = None, location: str | None = None) -> list[Finding]:
    """Run every rule over one piece of text."""
    findings: list[Finding] = []
    invisible = _INVISIBLE.findall(text)
    if invisible:
        hidden = _decode_tag_chars(text)
        detail = f"{len(invisible)} invisible/bidi character(s)"
        if hidden:
            detail += f"; hidden ASCII via tag characters: {_visible(hidden)!r}"
        findings.append(Finding("MW005", Severity.HIGH, detail, tool, location, _visible(text)))
        # Scan the smuggled text too, so the real directive gets its own finding.
        if hidden:
            findings.extend(scan_text(hidden, tool=tool, location=f"{location}#hidden"))

    normalized = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    for rule in RULES:
        match = rule.pattern.search(normalized)
        if match:
            findings.append(
                Finding(
                    rule.id,
                    rule.severity,
                    f"{rule.name}: {rule.message}",
                    tool,
                    location,
                    _visible(match.group(0)),
                )
            )
    return findings


def _schema_strings(schema: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield (path, text) for every human-readable string inside a JSON schema."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            child = f"{path}.{key}"
            if key in ("description", "title") and isinstance(value, str):
                yield child, value
            elif key in ("default", "examples", "enum", "const"):
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, str):
                        yield child, item
            else:
                yield from _schema_strings(value, child)
    elif isinstance(schema, list):
        for i, item in enumerate(schema):
            yield from _schema_strings(item, f"{path}[{i}]")


def scan_tool(tool: dict[str, Any]) -> list[Finding]:
    """Scan one entry of a ``tools/list`` result."""
    name = str(tool.get("name", "<unnamed>"))
    findings: list[Finding] = []
    description = tool.get("description") or ""
    if isinstance(description, str):
        findings.extend(scan_text(description, tool=name, location="description"))
        if len(description) > MAX_DESCRIPTION_CHARS:
            findings.append(
                Finding(
                    "MW008",
                    Severity.LOW,
                    f"description is {len(description)} chars; long descriptions are a common "
                    "place to bury instructions",
                    name,
                    "description",
                )
            )
    for key in ("inputSchema", "outputSchema"):
        for path, text in _schema_strings(tool.get(key), key):
            findings.extend(scan_text(text, tool=name, location=path))
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and isinstance(annotations.get("title"), str):
        findings.extend(scan_text(annotations["title"], tool=name, location="annotations.title"))
    if tool.get("title") and isinstance(tool["title"], str):
        findings.extend(scan_text(tool["title"], tool=name, location="title"))
    return findings


def scan_tools(tools: Iterable[dict[str, Any]]) -> list[Finding]:
    tools = list(tools)
    findings: list[Finding] = []
    names = [str(t.get("name")) for t in tools]
    seen: set[str] = set()
    for name in names:
        if name in seen:
            findings.append(
                Finding("MW010", Severity.MEDIUM, "duplicate tool name in one server", name)
            )
        seen.add(name)
    for tool in tools:
        findings.extend(scan_tool(tool))
    return findings


def scan_result(result: Any, tool: str | None = None) -> list[Finding]:
    """Scan the text blocks of a ``tools/call`` result for injected directives."""
    findings: list[Finding] = []
    if not isinstance(result, dict):
        return findings
    for i, block in enumerate(result.get("content") or []):
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            findings.extend(scan_text(block["text"], tool=tool, location=f"content[{i}]"))
    return findings


def max_severity(findings: Iterable[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)

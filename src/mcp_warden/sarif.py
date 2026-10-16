"""SARIF 2.1.0 output, so `scan` results show up in GitHub code scanning."""

from __future__ import annotations

from typing import Any

from mcp_warden import __version__
from mcp_warden.findings import Finding, Severity
from mcp_warden.scanner import RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/hasnat23/mcp-warden"

# Rules that are not regex based, so they are not in scanner.RULES.
_EXTRA_RULES: dict[str, tuple[str, str, Severity]] = {
    "MW005": ("invisible-unicode", "invisible or bidi Unicode characters", Severity.HIGH),
    "MW008": ("long-description", "unusually long tool description", Severity.LOW),
    "MW010": ("duplicate-tool", "duplicate tool name in one server", Severity.MEDIUM),
    "MW100": ("pin-changed", "tool definition changed since it was pinned", Severity.HIGH),
    "MW101": ("pin-new", "tool is not in the lockfile", Severity.MEDIUM),
    "MW102": ("pin-removed", "pinned tool is no longer offered", Severity.LOW),
}

_LEVEL = {Severity.LOW: "note", Severity.MEDIUM: "warning", Severity.HIGH: "error"}
# GitHub sorts code scanning alerts by this 0-10 score.
_SECURITY_SEVERITY = {Severity.LOW: "3.0", Severity.MEDIUM: "6.0", Severity.HIGH: "8.5"}


def rule_catalog() -> dict[str, tuple[str, str, Severity]]:
    catalog = {r.id: (r.name, r.message, r.severity) for r in RULES}
    catalog.update(_EXTRA_RULES)
    return dict(sorted(catalog.items()))


def _rule_descriptor(rule_id: str, name: str, text: str, severity: Severity) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": text},
        "helpUri": f"{INFO_URI}#detection-rules",
        "defaultConfiguration": {"level": _LEVEL[severity]},
        "properties": {
            "tags": ["security", "mcp"],
            "security-severity": _SECURITY_SEVERITY[severity],
        },
    }


def to_sarif(findings: list[Finding], artifact_uri: str) -> dict[str, Any]:
    """Build a SARIF log. ``artifact_uri`` is the file results are anchored to."""
    catalog = rule_catalog()
    rule_ids = list(catalog)
    results = []
    for f in findings:
        where = f.tool or "server"
        if f.location:
            where += f" ({f.location})"
        result: dict[str, Any] = {
            "ruleId": f.rule,
            "ruleIndex": rule_ids.index(f.rule) if f.rule in catalog else -1,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{where}: {f.message}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [
                        {"name": f.tool or "server", "kind": "function"},
                    ],
                }
            ],
            # Stable across runs so code scanning tracks one alert per tool and rule.
            "partialFingerprints": {"mcpWarden/v1": f"{f.rule}:{f.tool}:{f.location}"},
        }
        if f.evidence:
            result["properties"] = {"evidence": f.evidence}
        if result["ruleIndex"] < 0:
            del result["ruleIndex"]
        results.append(result)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-warden",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_rule_descriptor(k, *v) for k, v in catalog.items()],
                    }
                },
                "results": results,
            }
        ],
    }

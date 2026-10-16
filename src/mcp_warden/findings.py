"""Shared types for scanner and pinning findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}, expected low|medium|high") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    message: str
    tool: str | None = None
    location: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        return {k: v for k, v in data.items() if v is not None}

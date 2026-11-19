"""Prometheus metrics built from audit records, served by ``serve --metrics``.

The sink sees the same redacted records as the audit log and keeps counters
in memory; :meth:`MetricsSink.render` writes them in the Prometheus text
exposition format (version 0.0.4). There is no dependency on a client library.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
# Tool call latency buckets, in seconds.
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)

Labels = tuple[tuple[str, str], ...]

# Audit events counted in mcp_warden_requests_total, by the record field naming the method.
REQUEST_EVENTS = {
    "resource_read": "resources/read",
    "resource_subscribe": "resources/subscribe",
    "prompt_get": "prompts/get",
}


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(labels: Labels, extra: Iterable[tuple[str, str]] = ()) -> str:
    pairs = [*labels, *extra]
    if not pairs:
        return ""
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in pairs) + "}"


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


class MetricsSink:
    """An audit sink that counts warden decisions for Prometheus."""

    def __init__(self, gauges: dict[str, tuple[str, Callable[[], float]]] | None = None):
        self._lock = threading.Lock()
        self._counters: dict[str, dict[Labels, float]] = defaultdict(lambda: defaultdict(float))
        self._buckets: dict[Labels, list[int]] = {}
        self._sums: dict[Labels, float] = defaultdict(float)
        # name -> (help text, read the current value), e.g. open sessions.
        self.gauges = dict(gauges or {})

    def __call__(self, record: dict[str, Any]) -> None:
        event = record.get("event")
        server = str(record.get("server", ""))
        base: Labels = (("server", server),)
        if record.get("user"):
            base = (*base, ("user", str(record["user"])))
        with self._lock:
            if event == "tool_call":
                decision = str(record.get("decision", ""))
                if record.get("result_blocked"):
                    decision = "result_blocked"
                labels = (*base, ("tool", str(record.get("tool", ""))), ("decision", decision))
                self._counters["mcp_warden_tool_calls_total"][labels] += 1
                if isinstance(record.get("latency_ms"), (int, float)):
                    self._observe((("server", server),), record["latency_ms"] / 1000)
            elif event == "server_request" or event in REQUEST_EVENTS:
                method = str(record.get("method") or REQUEST_EVENTS.get(str(event), event))
                decision = str(record.get("decision", ""))
                if record.get("blocked"):
                    decision = "content_blocked"
                elif record.get("error"):
                    decision = "error"
                labels = (*base, ("method", method), ("decision", decision))
                self._counters["mcp_warden_requests_total"][labels] += 1
            elif event == "tools_list":
                hidden = record.get("hidden") or []
                self._counters["mcp_warden_hidden_tools_total"][(("server", server),)] += len(
                    hidden
                )
            redactions = record.get("redactions")
            if isinstance(redactions, int) and redactions:
                self._counters["mcp_warden_redactions_total"][(("server", server),)] += redactions
            for finding in record.get("findings") or []:
                if isinstance(finding, dict):
                    labels = (
                        ("server", server),
                        ("rule", str(finding.get("rule", ""))),
                        ("severity", str(finding.get("severity", ""))),
                    )
                    self._counters["mcp_warden_findings_total"][labels] += 1

    def _observe(self, labels: Labels, seconds: float) -> None:
        counts = self._buckets.setdefault(labels, [0] * (len(BUCKETS) + 1))
        for i, bound in enumerate(BUCKETS):
            if seconds <= bound:
                counts[i] += 1
        counts[-1] += 1  # +Inf
        self._sums[labels] += seconds

    def render(self) -> str:
        helps = {
            "mcp_warden_tool_calls_total": "Tool calls by server, tool and warden decision.",
            "mcp_warden_requests_total": "Resource reads, prompt gets and server requests.",
            "mcp_warden_hidden_tools_total": "Tools hidden from listings (poisoned or drifted).",
            "mcp_warden_redactions_total": "Secrets redacted from what servers returned.",
            "mcp_warden_findings_total": "Scanner findings by rule and severity.",
        }
        out: list[str] = []
        with self._lock:
            for name, help_text in helps.items():
                out += [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
                for labels, value in sorted(self._counters.get(name, {}).items()):
                    out.append(f"{name}{_labels(labels)} {_number(value)}")
            name = "mcp_warden_tool_call_duration_seconds"
            out += [
                f"# HELP {name} Tool call latency through the warden.",
                f"# TYPE {name} histogram",
            ]
            for labels, counts in sorted(self._buckets.items()):
                bounds = [*(_number(b) for b in BUCKETS), "+Inf"]
                for le, count in zip(bounds, counts, strict=True):
                    out.append(f"{name}_bucket{_labels(labels, [('le', le)])} {count}")
                out.append(f"{name}_sum{_labels(labels)} {_number(self._sums[labels])}")
                out.append(f"{name}_count{_labels(labels)} {counts[-1]}")
        for name, (help_text, read) in sorted(self.gauges.items()):
            out += [
                f"# HELP {name} {help_text}",
                f"# TYPE {name} gauge",
                f"{name} {_number(read())}",
            ]
        return "\n".join(out) + "\n"

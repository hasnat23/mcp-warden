"""OpenTelemetry export of warden decisions (optional: ``pip install mcp-warden[otel]``).

Every tool call becomes a span named ``execute_tool <name>`` with the GenAI
semantic-convention attributes plus the warden's decision, redaction count and
rule hits, so MCP traffic shows up next to the rest of an agent's traces.

The exporter is configured with the standard ``OTEL_*`` environment variables
(``OTEL_EXPORTER_OTLP_ENDPOINT``, ``OTEL_EXPORTER_OTLP_HEADERS``, ...). If the
process already has a global tracer provider, for example under
``opentelemetry-instrument``, that provider is used instead. Nothing is ever
written to stdout, which carries the MCP protocol.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from mcp_warden import __version__

SCOPE = "mcp_warden"


class TelemetryUnavailable(RuntimeError):
    pass


def _attr_list(values: Iterable[Any]) -> list[str]:
    return sorted({str(v) for v in values})


class OTelSink:
    """An audit sink that turns warden records into OpenTelemetry spans."""

    def __init__(self, tracer: Any = None, service_name: str = "mcp-warden"):
        try:
            from opentelemetry import trace
            from opentelemetry.trace import Status, StatusCode
        except ImportError as exc:
            raise TelemetryUnavailable(
                "OpenTelemetry is not installed; run: pip install 'mcp-warden[otel]'"
            ) from exc
        self._Status, self._StatusCode = Status, StatusCode
        self._provider: Any = None
        if tracer is None:
            tracer = self._default_tracer(trace, service_name)
        self._tracer = tracer

    def _default_tracer(self, trace: Any, service_name: str) -> Any:
        from opentelemetry.sdk.trace import TracerProvider

        current = trace.get_tracer_provider()
        if isinstance(current, TracerProvider):
            return current.get_tracer(SCOPE, __version__)
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError as exc:
            raise TelemetryUnavailable(
                "the OTLP exporter is not installed; run: pip install 'mcp-warden[otel]'"
            ) from exc
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        self._provider = provider
        return provider.get_tracer(SCOPE, __version__)

    def __call__(self, record: dict[str, Any]) -> None:
        event = record.get("event")
        if event == "tool_call":
            self._tool_call(record)
        elif event == "tools_list":
            self._tools_list(record)

    def _span(self, name: str, record: dict[str, Any], attributes: dict[str, Any]) -> Any:
        end = time.time_ns()
        start = end - int(float(record.get("latency_ms") or 0) * 1_000_000)
        span = self._tracer.start_span(name, start_time=start, attributes=attributes)
        return span, end

    def _tool_call(self, record: dict[str, Any]) -> None:
        tool = str(record.get("tool", ""))
        findings = record.get("findings") or []
        attrs: dict[str, Any] = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": tool,
            "mcp_warden.decision": str(record.get("decision")),
            "mcp_warden.redactions": int(record.get("redactions") or 0),
            "mcp_warden.findings": len(findings),
        }
        if findings:
            attrs["mcp_warden.rules"] = _attr_list(f.get("rule") for f in findings)
        if record.get("server"):
            attrs["mcp_warden.server"] = str(record["server"])
        if record.get("remote"):
            attrs["client.address"] = str(record["remote"])
        if record.get("session"):
            attrs["mcp_warden.session"] = str(record["session"])
        if record.get("reason"):
            attrs["mcp_warden.reason"] = str(record["reason"])
        if record.get("result_blocked"):
            attrs["mcp_warden.result_blocked"] = True
        if record.get("cancelled"):
            attrs["mcp_warden.cancelled"] = True

        error_type = None
        if record.get("decision") == "deny":
            error_type = "mcp_warden.denied"
        elif record.get("error"):
            error_type = f"jsonrpc.{record['error'].get('code', 'error')}"
        elif record.get("is_error"):
            error_type = "tool_error"
        if error_type:
            attrs["error.type"] = error_type

        span, end = self._span(f"execute_tool {tool}", record, attrs)
        if error_type:
            span.set_status(self._Status(self._StatusCode.ERROR, error_type))
        span.end(end_time=end)

    def _tools_list(self, record: dict[str, Any]) -> None:
        findings = record.get("findings") or []
        attrs: dict[str, Any] = {
            "mcp_warden.tools": int(record.get("tools") or 0),
            "mcp_warden.hidden": _attr_list(record.get("hidden") or []),
            "mcp_warden.findings": len(findings),
        }
        if findings:
            attrs["mcp_warden.rules"] = _attr_list(f.get("rule") for f in findings)
        if record.get("server"):
            attrs["mcp_warden.server"] = str(record["server"])
        span, end = self._span("mcp_warden tools/list", record, attrs)
        span.end(end_time=end)

    def close(self) -> None:
        if self._provider is not None:
            self._provider.shutdown()

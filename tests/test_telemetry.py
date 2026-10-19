import importlib.util
import itertools

import pytest
from conftest import POISONED_TOOL
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from mcp_warden.audit import AuditLog
from mcp_warden.cli import main
from mcp_warden.policy import policy_from_dict
from mcp_warden.telemetry import OTelSink, TelemetryUnavailable
from mcp_warden.warden import Warden


@pytest.fixture
def spans():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    sink = OTelSink(tracer=provider.get_tracer("test"))
    return sink, exporter


def call(msg_id, name, **arguments):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def test_tool_call_spans(spans):
    sink, exporter = spans
    clock = itertools.chain([0.0, 0.0, 0.25], itertools.repeat(1.0)).__next__
    w = Warden(
        policy_from_dict({"tools": {"deny": ["rm_*"]}}),
        audit=AuditLog(None),
        sinks=[sink],
        clock=clock,
    )

    w.from_client(call(1, "get_env"))
    w.from_server(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "AKIAIOSFODNN7EXAMPLE"}]},
        }
    )
    w.from_client(call(2, "rm_all"))

    ok, denied = exporter.get_finished_spans()
    assert ok.name == "execute_tool get_env"
    assert ok.attributes["gen_ai.operation.name"] == "execute_tool"
    assert ok.attributes["gen_ai.tool.name"] == "get_env"
    assert ok.attributes["mcp_warden.decision"] == "allow"
    assert ok.attributes["mcp_warden.redactions"] == 1
    assert ok.end_time - ok.start_time == pytest.approx(250_000_000, abs=1_000)
    assert ok.status.status_code is StatusCode.UNSET

    assert denied.attributes["mcp_warden.decision"] == "deny"
    assert denied.attributes["error.type"] == "mcp_warden.denied"
    assert "deny rule" in denied.attributes["mcp_warden.reason"]
    assert denied.status.status_code is StatusCode.ERROR


def test_tools_list_span_records_hidden_tools(spans):
    sink, exporter = spans
    w = Warden(policy_from_dict({}), audit=AuditLog(None), sinks=[sink])
    w.from_client({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    w.from_server({"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL]}})
    (span,) = exporter.get_finished_spans()
    assert span.name == "mcp_warden tools/list"
    assert span.attributes["mcp_warden.hidden"] == ("add",)
    assert "MW002" in span.attributes["mcp_warden.rules"]


def test_jsonrpc_errors_and_tool_errors_mark_span(spans):
    sink, exporter = spans
    w = Warden(policy_from_dict({}), audit=AuditLog(None), sinks=[sink])
    w.from_client(call(1, "a"))
    w.from_server({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad"}})
    w.from_client(call(2, "b"))
    w.from_server({"jsonrpc": "2.0", "id": 2, "result": {"content": [], "isError": True}})
    first, second = exporter.get_finished_spans()
    assert first.attributes["error.type"] == "jsonrpc.-32602"
    assert second.attributes["error.type"] == "tool_error"


def test_failing_sink_never_breaks_the_proxy(caplog):
    def broken(record):
        raise RuntimeError("collector down")

    w = Warden(policy_from_dict({}), audit=AuditLog(None), sinks=[broken])
    assert w.from_client(call(1, "x")).to_server
    out = w.from_server({"jsonrpc": "2.0", "id": 1, "result": {"content": []}})
    assert out.to_client
    assert "collector down" in caplog.text


def test_policy_telemetry_section():
    p = policy_from_dict({"telemetry": {"otel": True, "service_name": "agents-prod"}})
    assert p.otel and p.otel_service_name == "agents-prod"
    assert policy_from_dict({}).otel is False


def _has_otlp_exporter():
    try:
        return importlib.util.find_spec("opentelemetry.exporter.otlp") is not None
    except ModuleNotFoundError:
        return False


@pytest.mark.skipif(_has_otlp_exporter(), reason="OTLP exporter installed")
def test_missing_exporter_is_a_clear_error(capsys):
    with pytest.raises(TelemetryUnavailable, match="mcp-warden\\[otel\\]"):
        OTelSink()
    assert main(["run", "--otel", "--", "true"]) == 2
    assert "pip install" in capsys.readouterr().err

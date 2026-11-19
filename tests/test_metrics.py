"""Prometheus metrics from audit records."""

import re

from mcp_warden.metrics import MetricsSink

SAMPLE = re.compile(r'^[a-z_]+(\{([a-z_]+="([^"\\]|\\.)*",?)+\})? [0-9.e+-]+$')


def samples(text):
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert all(SAMPLE.match(line) for line in lines), lines
    return {line.rsplit(" ", 1)[0]: float(line.rsplit(" ", 1)[1]) for line in lines}


def test_counts_decisions_findings_and_latency():
    sink = MetricsSink({"mcp_warden_sessions": ("Open sessions.", lambda: 3)})
    call = {"event": "tool_call", "server": "fs", "tool": "read", "decision": "allow"}
    sink({**call, "latency_ms": 12.0, "redactions": 2, "user": "alice"})
    sink(
        {
            **call,
            "latency_ms": 700.0,
            "result_blocked": True,
            "findings": [{"rule": "MW001", "severity": "high"}],
        }
    )
    sink({**call, "decision": "deny", "reason": "deny rule"})
    sink(
        {
            "event": "server_request",
            "server": "fs",
            "method": "sampling/createMessage",
            "decision": "deny",
        }
    )
    sink(
        {"event": "resource_read", "server": "fs", "uri": "x", "decision": "allow", "blocked": True}
    )
    sink({"event": "prompt_get", "server": "fs", "decision": "allow", "error": {"code": -32602}})
    sink({"event": "tools_list", "server": "fs", "hidden": ["add"]})
    sink({"event": "something_else"})
    got = samples(sink.render())

    calls = "mcp_warden_tool_calls_total"
    assert got[f'{calls}{{server="fs",user="alice",tool="read",decision="allow"}}'] == 1
    assert got[f'{calls}{{server="fs",tool="read",decision="result_blocked"}}'] == 1
    assert got[f'{calls}{{server="fs",tool="read",decision="deny"}}'] == 1
    requests = "mcp_warden_requests_total"
    assert got[f'{requests}{{server="fs",method="sampling/createMessage",decision="deny"}}'] == 1
    assert got[f'{requests}{{server="fs",method="resources/read",decision="content_blocked"}}'] == 1
    assert got[f'{requests}{{server="fs",method="prompts/get",decision="error"}}'] == 1
    assert got['mcp_warden_hidden_tools_total{server="fs"}'] == 1
    assert got['mcp_warden_redactions_total{server="fs"}'] == 2
    assert got['mcp_warden_findings_total{server="fs",rule="MW001",severity="high"}'] == 1

    hist = "mcp_warden_tool_call_duration_seconds"
    assert got[f'{hist}_bucket{{server="fs",le="0.025"}}'] == 1
    assert got[f'{hist}_bucket{{server="fs",le="1"}}'] == 2
    assert got[f'{hist}_bucket{{server="fs",le="+Inf"}}'] == 2
    assert got[f'{hist}_count{{server="fs"}}'] == 2
    assert abs(got[f'{hist}_sum{{server="fs"}}'] - 0.712) < 1e-9
    assert got["mcp_warden_sessions"] == 3


def test_label_values_are_escaped():
    sink = MetricsSink()
    sink({"event": "tool_call", "server": "s", "tool": 'we"ird\\name\n', "decision": "allow"})
    assert 'tool="we\\"ird\\\\name\\n"' in sink.render()

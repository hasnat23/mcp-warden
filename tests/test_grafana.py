"""The example Grafana dashboard only queries metrics and labels mcp-warden exports."""

import json
import re
from pathlib import Path

from mcp_warden.metrics import MetricsSink

DASHBOARD = Path(__file__).parent.parent / "examples" / "grafana" / "mcp-warden.json"
METRIC = re.compile(r"\b(mcp_warden_[a-z_]+)")
GROUPING = re.compile(r"\bby \(([^)]*)\)")
MATCHER = re.compile(r'([a-z_]+)\s*(?:=~|!~|!=|=)\s*"')


def exported():
    """Each exported series name, with the labels it carries."""
    sink = MetricsSink(
        {"mcp_warden_sessions": ("", lambda: 1), "mcp_warden_servers": ("", lambda: 1)}
    )
    call = {"event": "tool_call", "server": "s", "tool": "t", "decision": "allow"}
    sink(
        {
            **call,
            "user": "u",
            "latency_ms": 5,
            "redactions": 1,
            "findings": [{"rule": "MW001", "severity": "high"}],
        }
    )
    sink({"event": "server_request", "server": "s", "method": "m", "decision": "allow"})
    sink({"event": "tools_list", "server": "s", "hidden": ["x"]})
    series = {}
    for line in sink.render().splitlines():
        if line and not line.startswith("#"):
            name, _, rest = line.partition("{")
            name = name.split(" ")[0]
            series.setdefault(name, set()).update(re.findall(r'([a-z_]+)="', rest))
    return series


def queries():
    dashboard = json.loads(DASHBOARD.read_text())
    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            yield panel["title"], target["expr"]
    for var in dashboard["templating"]["list"]:
        if var["type"] == "query":
            yield var["name"], var["definition"]


def test_dashboard_queries_known_metrics_and_labels():
    series = exported()
    checked = 0
    for title, expr in queries():
        names = set(METRIC.findall(expr))
        assert names, f"{title}: no mcp-warden metric in {expr}"
        for name in names:
            assert name in series, f"{title}: {name} is not exported"
            labels = series[name] | {"le"} if name.endswith("_bucket") else series[name]
            used = {m for m in MATCHER.findall(expr)}
            for group in GROUPING.findall(expr):
                used |= {label.strip() for label in group.split(",") if label.strip()}
            assert used <= labels | {"le"}, f"{title}: {name} has no {used - labels}"
            checked += 1
    assert checked >= 15


def test_dashboard_is_importable_json():
    dashboard = json.loads(DASHBOARD.read_text())
    assert dashboard["uid"] == "mcp-warden" and dashboard["title"] == "mcp-warden"
    ids = [p["id"] for p in dashboard["panels"]]
    assert len(ids) == len(set(ids))
    for panel in dashboard["panels"]:
        grid = panel["gridPos"]
        assert grid["x"] >= 0 and grid["x"] + grid["w"] <= 24
        for target in panel.get("targets", []):
            assert target["datasource"]["uid"] == "${datasource}"

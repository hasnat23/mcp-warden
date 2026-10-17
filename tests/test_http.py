import io
import json
import subprocess
import sys

import pytest
from conftest import POISONED_TOOL
from http_server import SESSION, serve

from mcp_warden.cli import main
from mcp_warden.client import fetch_tools_http
from mcp_warden.http_transport import StreamableHTTP, TransportError, iter_sse, parse_header

TOOLS = [
    {"name": "get_env", "description": "Return deployment configuration."},
    {"name": "delete_db", "description": "Drop the database."},
]


@pytest.fixture
def server():
    srv = serve(TOOLS)
    yield srv
    srv.shutdown()


def test_iter_sse_handles_multiline_crlf_and_comments():
    raw = b': comment\r\nevent: message\r\ndata: {"a":\r\ndata: 1}\r\n\r\ndata: last\n'
    assert list(iter_sse(io.BytesIO(raw))) == ['{"a":\n1}', "last"]


def test_parse_header():
    assert parse_header("Authorization: Bearer x:y") == ("Authorization", "Bearer x:y")
    with pytest.raises(ValueError):
        parse_header("no-colon")


def test_fetch_tools_over_http_tracks_session_and_deletes_it(server):
    info, tools = fetch_tools_http(server.url)
    assert info["name"] == "fake-http"
    assert [t["name"] for t in tools] == ["get_env", "delete_db"]
    assert server.deleted
    assert server.received[1] == {"jsonrpc": "2.0", "method": "notifications/initialized"}


def test_auth_header_and_http_errors():
    srv = serve(TOOLS, require_auth="Bearer s3cret")
    try:
        with pytest.raises(TransportError) as err:
            list(StreamableHTTP(srv.url).post({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        assert err.value.status == 401
        info, _ = fetch_tools_http(srv.url, {"Authorization": "Bearer s3cret"})
        assert info["version"] == "2.0.0"
    finally:
        srv.shutdown()


def test_unreachable_server():
    t = StreamableHTTP("http://127.0.0.1:9/mcp", timeout=2)
    with pytest.raises(TransportError, match="cannot reach"):
        list(t.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}))


def test_scan_cli_with_url(capsys):
    srv = serve([POISONED_TOOL], require_auth="Bearer t")
    try:
        assert main(["scan", "--url", srv.url, "-H", "Authorization: Bearer t"]) == 1
        out = capsys.readouterr().out
        assert "fake-http 2.0.0" in out and "MW002" in out
    finally:
        srv.shutdown()


INIT = [
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
]


def bridge(url, messages, *extra):
    payload = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_warden", "-q", "run", "--url", url, *extra],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
    )
    lines = [json.loads(x) for x in proc.stdout.splitlines() if x.strip()]
    return proc, lines


def test_http_bridge_end_to_end(tmp_path):
    srv = serve([*TOOLS, POISONED_TOOL])
    policy = tmp_path / "w.yaml"
    policy.write_text("tools: {deny: ['delete_*']}\n")
    try:
        proc, lines = bridge(
            srv.url,
            [
                *INIT,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "get_env", "arguments": {}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "delete_db", "arguments": {}},
                },
            ],
            "-p",
            str(policy),
        )
    finally:
        srv.shutdown()
    assert proc.returncode == 0, proc.stderr
    by_id = {m["id"]: m for m in lines if "id" in m}
    assert by_id[0]["result"]["serverInfo"]["name"] == "fake-http"
    assert [t["name"] for t in by_id[1]["result"]["tools"]] == ["get_env", "delete_db"]
    assert by_id[2]["result"]["content"][0]["text"] == "token [REDACTED:github-token]"
    assert by_id[3]["result"]["isError"] is True
    # The SSE notification streamed before the tools/list result reached the client.
    assert any(m.get("method") == "notifications/message" for m in lines)
    # The denied call never reached the server; the session was closed on EOF.
    called = [m["params"]["name"] for m in srv.received if m.get("method") == "tools/call"]
    assert called == ["get_env"]
    assert srv.deleted
    assert srv.received[0]["method"] == "initialize"


def test_http_bridge_reports_upstream_failure_as_jsonrpc_error():
    proc, lines = bridge("http://127.0.0.1:9/mcp", INIT[:1])
    assert proc.returncode == 1
    assert lines[0]["id"] == 0 and "upstream error" in lines[0]["error"]["message"]


def test_session_header_constant_is_echoed(server):
    t = StreamableHTTP(server.url)
    list(t.post(INIT[0]))
    assert t.session_id == SESSION and t.protocol_version == "2025-06-18"
    t.close()
    assert server.deleted and t.session_id is None


def test_scan_cli_unreachable_url_is_a_clean_error(capsys):
    assert main(["scan", "--url", "http://127.0.0.1:9/mcp", "--timeout", "2"]) == 2
    assert "cannot reach" in capsys.readouterr().err


def test_run_requires_exactly_one_target(capsys):
    assert main(["run", "--url", "http://x/mcp", "--", "echo"]) == 2

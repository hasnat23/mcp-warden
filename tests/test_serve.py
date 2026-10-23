"""mcp-warden serve: the gateway behind a Streamable HTTP endpoint."""

import json
import sys
import threading
import urllib.error
import urllib.request

import pytest
from conftest import FAKE_SERVER, POISONED_TOOL

from mcp_warden.cli import main
from mcp_warden.http_transport import StreamableHTTP, TransportError
from mcp_warden.policy import load_policy
from mcp_warden.serve import GatewayServer, origin_allowed
from mcp_warden.servers import ServerSpec

INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}


def call(msg_id, name, **arguments):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


@pytest.fixture
def make_server(tmp_path):
    started = []

    def make(**kwargs):
        tools = tmp_path / "tools.json"
        tools.write_text(json.dumps([POISONED_TOOL, {"name": "get_env", "description": "Env."}]))
        policy = tmp_path / "warden.yaml"
        policy.write_text(f"audit: {{path: {json.dumps(str(tmp_path / 'audit.jsonl'))}}}\n")
        specs = [
            ServerSpec("local", load_policy(policy), [sys.executable, str(FAKE_SERVER)]),
            ServerSpec(
                "shady", load_policy(policy), [sys.executable, str(FAKE_SERVER), str(tools)]
            ),
        ]
        server = GatewayServer(specs, port=0, **kwargs)
        server.start()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return server

    yield make
    for server in started:
        server.shutdown()
        server.close()


def raw(url, method="POST", body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read()
            return resp.status, dict(resp.headers), json.loads(text) if text else None
    except urllib.error.HTTPError as exc:
        text = exc.read()
        return exc.code, dict(exc.headers), json.loads(text) if text else None


def rpc(transport, msg):
    (reply,) = list(transport.post(msg))
    return reply


def test_session_flow_through_our_own_client(make_server, tmp_path):
    server = make_server()
    client = StreamableHTTP(server.url)
    init = rpc(client, INIT)
    assert client.session_id and init["result"]["capabilities"]["tools"]["listChanged"] is False
    assert list(client.post({"jsonrpc": "2.0", "method": "notifications/initialized"})) == []

    tools = rpc(client, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    assert sorted(t["name"] for t in tools) == [
        "local__get_env",
        "local__read_file",
        "shady__get_env",
    ]
    read = rpc(client, call(2, "local__read_file", path="a.txt"))
    assert read["result"]["content"][0]["text"] == "hello from a.txt"
    env = rpc(client, call(3, "local__get_env"))
    assert "sk-proj-" not in json.dumps(env)

    records = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    calls = [r for r in records if r["event"] == "tool_call"]
    assert {r["session"] for r in calls} == {client.session_id[:8]}
    assert {r["remote"] for r in calls} == {"127.0.0.1"}

    client.close()
    with pytest.raises(TransportError) as err:
        rpc(client, {"jsonrpc": "2.0", "id": 4, "method": "ping"})
    assert err.value.status == 400  # the client forgot the session, so it sends none


def test_poisoned_tool_is_hidden_before_any_listing(make_server):
    server = make_server()
    client = StreamableHTTP(server.url)
    rpc(client, INIT)
    reply = rpc(client, call(1, "shady__add", a=1, b=2))
    assert "Blocked by mcp-warden" in reply["result"]["content"][0]["text"]


def test_sessions_are_required_and_can_end(make_server):
    server = make_server()
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert raw(server.url, body=ping)[0] == 400
    assert raw(server.url, body=ping, headers={"Mcp-Session-Id": "nope"})[0] == 404

    status, headers, _ = raw(server.url, body=INIT)
    sid = headers["Mcp-Session-Id"]
    assert status == 200
    assert raw(server.url, body=ping, headers={"Mcp-Session-Id": sid})[2]["result"] == {}
    batch = raw(server.url, body=[ping, {**ping, "id": 2}], headers={"Mcp-Session-Id": sid})
    assert [r["id"] for r in batch[2]] == [1, 2]
    assert raw(server.url, method="DELETE", headers={"Mcp-Session-Id": sid})[0] == 200
    assert raw(server.url, body=ping, headers={"Mcp-Session-Id": sid})[0] == 404


def test_bearer_token(make_server):
    server = make_server(token="s3cret")
    status, headers, _ = raw(server.url, body=INIT)
    assert status == 401 and headers["WWW-Authenticate"] == "Bearer"
    assert raw(server.url, body=INIT, headers={"Authorization": "Bearer wrong"})[0] == 401
    client = StreamableHTTP(server.url, {"Authorization": "Bearer s3cret"})
    assert rpc(client, INIT)["result"]["serverInfo"]["name"] == "mcp-warden"


def test_origin_and_misc_routes(make_server):
    server = make_server(allowed_origins=["https://app.example.com"])
    assert raw(server.url, body=INIT, headers={"Origin": "https://evil.example"})[0] == 403
    for origin in ("http://localhost:3000", "https://app.example.com"):
        assert raw(server.url, body=INIT, headers={"Origin": origin})[0] == 200
    assert raw(server.url, method="GET")[0] == 405
    base = server.url.rsplit("/", 1)[0]
    assert raw(base + "/healthz", method="GET")[:3:2] == (200, {"status": "ok"})
    assert raw(base + "/other", body=INIT)[0] == 404
    req = urllib.request.Request(server.url, data=b"{not json", method="POST")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req, timeout=10)
    assert err.value.code == 400


def test_origin_allowed():
    assert origin_allowed(None, [])
    assert origin_allowed("http://127.0.0.1:6274", [])
    assert not origin_allowed("http://localhost.evil.com", [])
    assert origin_allowed("https://x.dev", ["*"])


def test_serve_cli_requires_token_when_asked(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WARDEN_TOKEN", raising=False)
    cfg = tmp_path / "servers.yaml"
    cfg.write_text("servers: {a: {command: x}}\n")
    assert main(["serve", "--config", str(cfg), "--token-env", "WARDEN_TOKEN"]) == 2
    assert "WARDEN_TOKEN" in capsys.readouterr().err

"""mcp-warden serve: the gateway behind a Streamable HTTP endpoint."""

import json
import sys
import threading
import time
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
    assert client.session_id and init["result"]["capabilities"]["tools"]["listChanged"]
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


def test_per_client_tokens_scope_servers_and_sessions(make_server, tmp_path):
    from mcp_warden.servers import ClientSpec, token_digest

    clients = [
        ClientSpec("alice", token_digest("alice-token")),
        ClientSpec("ci", token_digest("ci-token"), frozenset({"local"})),
    ]
    server = make_server(clients=clients)
    assert raw(server.url, body=INIT, headers={"Authorization": "Bearer nope"})[0] == 401

    alice = StreamableHTTP(server.url, {"Authorization": "Bearer alice-token"})
    ci = StreamableHTTP(server.url, {"Authorization": "Bearer ci-token"})
    rpc(alice, INIT)
    rpc(ci, INIT)
    listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert len(rpc(alice, listing)["result"]["tools"]) == 3
    ci_tools = sorted(t["name"] for t in rpc(ci, listing)["result"]["tools"])
    assert ci_tools == ["local__get_env", "local__read_file"]

    denied = rpc(ci, call(2, "shady__get_env"))
    assert denied["error"]["code"] == -32602
    assert "REDACTED" in rpc(alice, call(2, "shady__get_env"))["result"]["content"][0]["text"]

    # A session belongs to the client that opened it.
    stolen = {"Authorization": "Bearer ci-token", "Mcp-Session-Id": alice.session_id}
    ping = {"jsonrpc": "2.0", "id": 3, "method": "ping"}
    assert raw(server.url, body=ping, headers=stolen)[0] == 404
    assert raw(server.url, method="DELETE", headers=stolen)[0] == 404

    records = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    calls = [(r["user"], r["server"], r["decision"]) for r in records if r["event"] == "tool_call"]
    assert ("ci", "shady", "deny") in calls and ("alice", "shady", "allow") in calls


def test_shared_token_and_clients_are_exclusive():
    from mcp_warden.servers import ClientSpec

    with pytest.raises(ValueError):
        GatewayServer([], token="t", clients=[ClientSpec("a", "0" * 64)])


def write_clients(tmp_path, clients_yaml):
    cfg = tmp_path / "servers.yaml"
    cfg.write_text("servers:\n  fs: {command: x}\n  db: {command: y}\n" + clients_yaml)
    return cfg


def test_load_clients(tmp_path, monkeypatch):
    from mcp_warden.servers import load_clients, load_servers, token_digest

    monkeypatch.setenv("ALICE_TOKEN", "a1")
    cfg = write_clients(
        tmp_path,
        "clients:\n"
        "  alice: {token: '${ALICE_TOKEN}'}\n"
        f"  ci: {{token_sha256: {token_digest('c1').upper()}, servers: [fs]}}\n",
    )
    alice, ci = load_clients(cfg, load_servers(cfg))
    assert alice.token_sha256 == token_digest("a1") and alice.servers is None
    assert ci.token_sha256 == token_digest("c1") and ci.servers == {"fs"}
    assert load_clients(write_clients(tmp_path, ""), []) == []


@pytest.mark.parametrize(
    "clients_yaml, error",
    [
        ("clients: {a: {token: '${UNSET_WARDEN_VAR}'}}\n", "unset"),
        ("clients: {a: {token: x, token_sha256: y}}\n", "exactly one"),
        ("clients: {a: {token_sha256: abc}}\n", "64 hex"),
        ("clients: {a: {token: x, servers: [web]}}\n", "unknown server"),
        ("clients: {a: {token: x}, b: {token: x}}\n", "shared"),
        ("clients: {}\n", "non-empty"),
    ],
)
def test_load_clients_rejects_bad_config(tmp_path, monkeypatch, clients_yaml, error):
    from mcp_warden.policy import PolicyError
    from mcp_warden.servers import load_clients, load_servers

    monkeypatch.delenv("UNSET_WARDEN_VAR", raising=False)
    cfg = write_clients(tmp_path, clients_yaml)
    with pytest.raises(PolicyError, match=error):
        load_clients(cfg, load_servers(cfg))


def test_serve_cli_rejects_token_env_with_clients(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_TOKEN", "t")
    cfg = write_clients(tmp_path, "clients: {a: {token: x}}\n")
    assert main(["serve", "--config", str(cfg), "--token-env", "WARDEN_TOKEN"]) == 2
    assert "cannot be combined" in capsys.readouterr().err


def with_progress(msg_id, name, token, **arguments):
    msg = call(msg_id, name, **arguments)
    msg["params"]["_meta"] = {"progressToken": token}
    return msg


def test_tool_call_streams_progress_then_result(make_server):
    server = make_server()
    client = StreamableHTTP(server.url)
    rpc(client, INIT)
    out = list(client.post(with_progress(1, "local__get_env", "tok-1")))
    assert [m.get("method") for m in out] == ["notifications/progress"] * 2 + [None]
    assert {m["params"]["progressToken"] for m in out[:2]} == {"tok-1"}
    assert "ghp_" not in json.dumps(out) and "REDACTED" in out[1]["params"]["message"]
    assert out[2]["id"] == 1 and "result" in out[2]

    # A client that only takes JSON still gets its result, without the progress.
    headers = {"Mcp-Session-Id": client.session_id, "Accept": "application/json"}
    status, _, reply = raw(server.url, body=with_progress(2, "local__get_env", 5), headers=headers)
    assert status == 200 and reply["id"] == 2


class SSEReader:
    """Reads the data events of a GET stream on a background thread."""

    def __init__(self, url, headers):
        req = urllib.request.Request(
            url, headers={"Accept": "text/event-stream", **headers}, method="GET"
        )
        self.resp = urllib.request.urlopen(req, timeout=10)
        self.events = []
        self.ended = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        try:
            for line in self.resp:
                if line.startswith(b"data:"):
                    self.events.append(json.loads(line[5:]))
        except OSError:
            pass
        self.ended.set()

    def wait_for(self, count, timeout=10):
        deadline = time.monotonic() + timeout
        while len(self.events) < count and time.monotonic() < deadline:
            time.sleep(0.02)
        return self.events


def test_standing_stream_gets_list_changed_for_allowed_servers(make_server):
    from mcp_warden.servers import ClientSpec, token_digest

    server = make_server(
        clients=[
            ClientSpec("alice", token_digest("a")),
            ClientSpec("ci", token_digest("c"), frozenset({"local"})),
        ]
    )
    alice = StreamableHTTP(server.url, {"Authorization": "Bearer a"})
    ci = StreamableHTTP(server.url, {"Authorization": "Bearer c"})
    rpc(alice, INIT)
    rpc(ci, INIT)
    auth = {"Authorization": "Bearer a"}
    assert raw(server.url, method="GET", headers=auth)[0] == 405  # no Accept
    no_session = urllib.request.Request(
        server.url, method="GET", headers={**auth, "Accept": "text/event-stream"}
    )
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(no_session, timeout=10)
    assert err.value.code == 400

    alice_stream = SSEReader(server.url, {**auth, "Mcp-Session-Id": alice.session_id})
    ci_stream = SSEReader(
        server.url, {"Authorization": "Bearer c", "Mcp-Session-Id": ci.session_id}
    )
    time.sleep(0.2)  # let both streams register
    rpc(alice, call(1, "shady__announce"))
    rpc(alice, call(2, "local__announce"))
    changed = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    assert alice_stream.wait_for(2) == [changed, changed]
    assert ci_stream.wait_for(1) == [changed]
    time.sleep(0.3)
    assert ci_stream.events == [changed]  # nothing from the server ci cannot use

    # Ending the session ends its stream.
    alice.close()
    assert alice_stream.ended.wait(5)


def test_resource_updates_reach_subscribed_sessions_only(tmp_path):
    policy = load_policy(None)
    command = [sys.executable, str(FAKE_SERVER), "-", "--resources", "a"]
    server = GatewayServer([ServerSpec("a", policy, command)], port=0)
    server.start()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        alice, bob = StreamableHTTP(server.url), StreamableHTTP(server.url)
        init = rpc(alice, INIT)
        assert init["result"]["capabilities"]["resources"]["subscribe"] is True
        rpc(bob, INIT)
        streams = [SSEReader(server.url, {"Mcp-Session-Id": c.session_id}) for c in (alice, bob)]
        time.sleep(0.2)
        subscribe = {"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe"}
        assert rpc(alice, {**subscribe, "params": {"uri": "memo://a/notes"}})["result"] == {}

        rpc(bob, call(2, "a__touch"))
        (update,) = streams[0].wait_for(1)
        assert update["method"] == "notifications/resources/updated"
        assert update["params"]["uri"] == "memo://a/notes"
        assert "ghp_" not in json.dumps(update)
        time.sleep(0.3)
        assert streams[1].events == []

        # Ending alice's session releases the upstream subscription.
        alice.close()
        deadline = time.monotonic() + 5
        while server.gateway._subscriptions and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.gateway._subscriptions == {}
    finally:
        server.shutdown()
        server.close()


def test_server_requests_reach_the_calling_session(make_server):
    server = make_server()
    alice, bob = StreamableHTTP(server.url), StreamableHTTP(server.url)
    init = {**INIT, "params": {**INIT["params"], "capabilities": {"sampling": {}}}}
    rpc(alice, init)
    rpc(bob, init)
    streams = [SSEReader(server.url, {"Mcp-Session-Id": c.session_id}) for c in (alice, bob)]
    time.sleep(0.2)

    def respond(request, text):
        result = {"role": "assistant", "content": {"type": "text", "text": text}, "model": "m"}
        answer = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        status, _, _ = raw(server.url, body=answer, headers={"Mcp-Session-Id": alice.session_id})
        assert status == 202

    # A plain JSON call: the request comes on alice's GET stream.
    done = {}
    worker = threading.Thread(
        target=lambda: done.update(reply=rpc(alice, call(1, "local__sample", prompt="hi")))
    )
    worker.start()
    (request,) = streams[0].wait_for(1)
    assert request["method"] == "sampling/createMessage"
    respond(request, "from the GET stream")
    worker.join(10)
    assert "from the GET stream" in done["reply"]["result"]["content"][0]["text"]

    # A streamed call: the request comes inside the call's own SSE response.
    out = []
    for msg in alice.post(with_progress(2, "local__sample", "tok", prompt="hi")):
        out.append(msg)
        if msg.get("method") == "sampling/createMessage":
            respond(msg, "from the call stream")
    assert "from the call stream" in out[-1]["result"]["content"][0]["text"]
    assert len(streams[0].events) == 1  # nothing more on the GET stream
    assert streams[1].events == []  # bob is never asked


def test_per_client_rate_limits(tmp_path):
    from mcp_warden.policy import policy_from_dict
    from mcp_warden.servers import ClientSpec, token_digest

    policy = policy_from_dict(
        {"rate_limits": [{"tool": "get_env", "max_calls": 1, "per_seconds": 60, "per": "client"}]}
    )
    spec = ServerSpec("local", policy, [sys.executable, str(FAKE_SERVER)])
    server = GatewayServer(
        [spec],
        port=0,
        clients=[ClientSpec("alice", token_digest("a")), ClientSpec("bob", token_digest("b"))],
    )
    server.start()
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def session(token):
        client = StreamableHTTP(server.url, {"Authorization": f"Bearer {token}"})
        rpc(client, INIT)
        return client

    def blocked(client, msg_id):
        return rpc(client, call(msg_id, "local__get_env"))["result"].get("isError", False)

    try:
        alice = session("a")
        assert not blocked(alice, 1)
        assert blocked(alice, 2)
        assert not blocked(session("b"), 3)  # bob has a separate budget
        assert blocked(session("a"), 4)  # a new session does not reset alice's budget
    finally:
        server.shutdown()
        server.close()


def test_reload_applies_new_policies_and_clients(tmp_path):
    from mcp_warden.policy import policy_from_dict
    from mcp_warden.servers import ClientSpec, token_digest

    command = [sys.executable, str(FAKE_SERVER)]
    alice, bob = ClientSpec("alice", token_digest("a")), ClientSpec("bob", token_digest("b"))
    server = GatewayServer(
        [ServerSpec("local", policy_from_dict({}), command)], port=0, clients=[alice, bob]
    )
    server.start()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = StreamableHTTP(server.url, {"Authorization": "Bearer a"})
        rpc(client, INIT)
        stream = SSEReader(
            server.url, {"Authorization": "Bearer a", "Mcp-Session-Id": client.session_id}
        )
        time.sleep(0.2)
        assert not rpc(client, call(1, "local__get_env"))["result"]["isError"]

        strict = policy_from_dict({"tools": {"deny": ["get_env"]}})
        notes = server.reload([ServerSpec("local", strict, command)], [alice])
        assert notes == []
        # Same session, new policy; and the client is told to list tools again.
        assert rpc(client, call(2, "local__get_env"))["result"]["isError"]
        assert stream.wait_for(1)[0]["method"] == "notifications/tools/list_changed"
        # bob was removed from the clients.
        assert raw(server.url, body=INIT, headers={"Authorization": "Bearer b"})[0] == 401

        # Servers come and go: "other" starts, "local" stops, sessions carry on.
        other = ServerSpec("other", policy_from_dict({}), command)
        assert server.reload([other], [alice]) == []
        assert set(server.gateway.upstreams) == {"other"}
        assert not rpc(client, call(3, "other__get_env"))["result"]["isError"]
        assert rpc(client, call(4, "local__get_env"))["error"]["code"] == -32602
        tools = rpc(client, {"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
        assert {t["name"].split("__")[0] for t in tools["result"]["tools"]} == {"other"}

        # A changed command restarts the server; a broken one is reported.
        broken = ServerSpec("other", policy_from_dict({}), [sys.executable, "-c", "pass"])
        assert server.reload([broken], [alice]) == ["server 'other' failed to start"]
        assert server.reload([other], [alice]) == []
        assert not rpc(client, call(6, "other__get_env"))["result"]["isError"]
    finally:
        server.shutdown()
        server.close()


@pytest.mark.skipif(sys.platform == "win32", reason="no SIGHUP on Windows")
def test_sighup_reloads_the_config(tmp_path):
    import signal
    import socket
    import subprocess

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    policy = tmp_path / "policy.yaml"
    policy.write_text("{}\n")
    config = tmp_path / "servers.yaml"
    config.write_text(
        f"policy: policy.yaml\nservers:\n  local:\n"
        f"    command: [{json.dumps(sys.executable)}, {json.dumps(str(FAKE_SERVER))}]\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_warden", "serve", "--config", str(config), "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert "serving" in proc.stdout.readline()
        client = StreamableHTTP(f"http://127.0.0.1:{port}/mcp")
        rpc(client, INIT)
        assert not rpc(client, call(1, "local__get_env"))["result"]["isError"]

        policy.write_text("tools: {deny: [get_env]}\n")
        proc.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if rpc(client, call(2, "local__get_env"))["result"]["isError"]:
                break
            time.sleep(0.1)
        else:
            pytest.fail("the new policy was not applied")

        # A broken config is refused and the running one kept.
        policy.write_text("mode: yolo\n")
        proc.send_signal(signal.SIGHUP)
        time.sleep(0.5)
        assert rpc(client, call(3, "local__get_env"))["result"]["isError"]
    finally:
        proc.terminate()
        _, err = proc.communicate(timeout=10)
    assert "reload failed" in err and "mode must be enforce|monitor" in err

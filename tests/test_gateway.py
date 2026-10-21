"""Multi-server mode: one client session in front of several upstream servers."""

import json
import subprocess
import sys

import pytest
from conftest import FAKE_SERVER, POISONED_TOOL
from http_server import serve
from test_e2e import INIT, WARDEN

from mcp_warden.policy import PolicyError
from mcp_warden.servers import load_servers


def write_config(tmp_path, body):
    path = tmp_path / "servers.yaml"
    path.write_text(body)
    return path


def call(msg_id, name, **arguments):
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def test_load_servers(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACKER_TOKEN", "t0k")
    (tmp_path / "base.yaml").write_text("pinning: {lockfile: warden.lock.json}\n")
    (tmp_path / "strict.yaml").write_text("mode: monitor\ntools: {deny: ['*']}\n")
    cfg = write_config(
        tmp_path,
        "policy: base.yaml\n"
        "servers:\n"
        "  fs:\n"
        "    command: python -m server --root '/srv/my data'\n"
        "  tracker:\n"
        "    url: https://mcp.example.com/mcp\n"
        "    headers: {Authorization: 'Bearer ${TRACKER_TOKEN}'}\n"
        "    policy: strict.yaml\n",
    )
    fs, tracker = load_servers(cfg)
    assert fs.command == ["python", "-m", "server", "--root", "/srv/my data"]
    assert fs.policy.lockfile == str(tmp_path / "warden.lock.fs.json")
    assert tracker.url == "https://mcp.example.com/mcp"
    assert tracker.headers == {"Authorization": "Bearer t0k"}
    assert tracker.policy.mode == "monitor" and tracker.policy.lockfile is None


@pytest.mark.parametrize(
    "body, error",
    [
        ("servers: {}\n", "empty"),
        ("policy: x.yaml\n", "'servers' mapping"),
        ("servers: {a__b: {command: x}}\n", "server name"),
        ("servers: {fs: {command: x, url: http://h}}\n", "exactly one"),
        ("servers: {fs: {}}\n", "exactly one"),
    ],
)
def test_load_servers_rejects_bad_config(tmp_path, body, error):
    with pytest.raises(PolicyError, match=error):
        load_servers(write_config(tmp_path, body))


def test_gateway_end_to_end(tmp_path):
    poisoned = tmp_path / "tools.json"
    poisoned.write_text(json.dumps([POISONED_TOOL, {"name": "echo", "description": "Echo."}]))
    (tmp_path / "base.yaml").write_text("audit: {path: audit.jsonl}\n")
    (tmp_path / "strict.yaml").write_text("tools: {deny: ['read_*']}\naudit: {path: audit.jsonl}\n")
    http = serve([{"name": "get_env", "description": "Deployment configuration."}])
    py = json.dumps(sys.executable)
    cfg = write_config(
        tmp_path,
        "policy: base.yaml\n"
        "servers:\n"
        f"  local:\n    command: [{py}, {json.dumps(str(FAKE_SERVER))}]\n"
        f"  shady:\n    command: [{py}, {json.dumps(str(FAKE_SERVER))}, "
        f"{json.dumps(str(poisoned))}]\n"
        "    policy: strict.yaml\n"
        f"  remote:\n    url: {http.url}\n",
    )
    messages = [*INIT, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]
    payload = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.Popen(
        [*WARDEN, "run", "--config", str(cfg)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write(payload)
    proc.stdin.flush()
    out = []
    # Calls go out only after the listing, so hidden tools are known to the warden.
    while not any(m.get("id") == 1 for m in out):
        out.append(json.loads(proc.stdout.readline()))
    proc.stdin.write(
        "".join(
            json.dumps(m) + "\n"
            for m in [
                call(2, "local__read_file", path="notes.txt"),
                call(3, "shady__add", a=1, b=2),
                call(4, "remote__get_env"),
                call(5, "nope__x"),
                call(6, "shady__echo"),
                {"jsonrpc": "2.0", "id": 7, "method": "ping"},
            ]
        )
    )
    proc.stdin.close()
    out += [json.loads(line) for line in proc.stdout if line.strip()]
    assert proc.wait(timeout=20) == 0
    replies = {m["id"]: m for m in out if "id" in m}

    assert replies[0]["result"]["capabilities"] == {"tools": {"listChanged": True}}
    names = sorted(t["name"] for t in replies[1]["result"]["tools"])
    assert names == [
        "local__get_env",
        "local__read_file",
        "remote__get_env",
        "shady__echo",
    ]  # shady__add is poisoned and hidden
    assert replies[2]["result"]["content"][0]["text"] == "hello from notes.txt"
    assert "Blocked by mcp-warden" in replies[3]["result"]["content"][0]["text"]
    assert "ghp_" not in json.dumps(replies[4])
    assert replies[5]["error"]["code"] == -32602
    assert replies[6]["result"]["content"][0]["text"] == "ok"
    assert replies[7]["result"] == {}
    # The HTTP server's log notification is passed through.
    assert any(m.get("method") == "notifications/message" for m in out)

    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    calls = {(r["server"], r["tool"]): r for r in records if r["event"] == "tool_call"}
    assert calls[("local", "read_file")]["decision"] == "allow"
    assert calls[("shady", "add")]["decision"] == "deny"
    assert calls[("remote", "get_env")]["redactions"] == 1
    lists = {r["server"]: r for r in records if r["event"] == "tools_list"}
    assert lists["shady"]["hidden"] == ["add"]
    assert http.deleted


def test_gateway_survives_a_dead_server(tmp_path):
    cfg = write_config(
        tmp_path,
        "servers:\n"
        f"  ok:\n    command: [{json.dumps(sys.executable)}, {json.dumps(str(FAKE_SERVER))}]\n"
        "  gone:\n    url: http://127.0.0.1:9/mcp\n",
    )
    messages = [
        *INIT,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        call(2, "gone__anything"),
    ]
    proc = subprocess.run(
        [*WARDEN, "run", "--config", str(cfg)],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True,
        text=True,
        timeout=30,
    )
    replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines()) if "id" in r}
    assert sorted(t["name"] for t in replies[1]["result"]["tools"]) == [
        "ok__get_env",
        "ok__read_file",
    ]
    assert replies[2]["error"]["code"] == -32000

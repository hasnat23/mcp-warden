"""End-to-end: real subprocesses talking newline-delimited JSON-RPC over pipes."""

import json
import subprocess
import sys

from conftest import POISONED_TOOL

from mcp_warden.cli import main

WARDEN = [sys.executable, "-m", "mcp_warden", "-q"]


def session(args, messages, timeout=20):
    payload = "".join(json.dumps(m) + "\n" for m in messages)
    proc = subprocess.run(
        [*WARDEN, *args], input=payload, capture_output=True, text=True, timeout=timeout
    )
    replies = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return proc, {r["id"]: r for r in replies}


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


def test_proxy_end_to_end(tmp_path, server_cmd):
    policy = tmp_path / "warden.yaml"
    policy.write_text(
        "arguments:\n"
        "  - {tool: read_file, arg: path, deny_pattern: '\\.ssh'}\n"
        "audit: {path: audit.jsonl}\n"
    )
    proc, replies = session(
        ["run", "-p", str(policy), "--", *server_cmd],
        [
            *INIT,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "notes.txt"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/root/.ssh/id_rsa"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "get_env", "arguments": {}},
            },
        ],
    )
    assert proc.returncode == 0, proc.stderr
    assert replies[0]["result"]["serverInfo"]["name"] == "fake-server"
    assert {t["name"] for t in replies[1]["result"]["tools"]} == {"read_file", "get_env"}
    assert replies[2]["result"]["content"][0]["text"] == "hello from notes.txt"
    assert replies[3]["result"]["isError"] is True
    assert "[REDACTED:openai-key]" in replies[4]["result"]["content"][0]["text"]

    events = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [e["decision"] for e in events if e["event"] == "tool_call"] == [
        "deny",
        "allow",
        "allow",
    ]


def test_proxy_hides_poisoned_tools(tmp_path, server_cmd, monkeypatch):
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps([POISONED_TOOL, {"name": "ok", "description": "fine"}]))
    monkeypatch.setenv("FAKE_TOOLS", str(tools))
    _, replies = session(
        ["run", "--", *server_cmd], [*INIT, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]
    )
    assert [t["name"] for t in replies[1]["result"]["tools"]] == ["ok"]


def test_scan_cli_against_live_server(tmp_path, server_cmd, monkeypatch, capsys):
    assert main(["scan", "--", *server_cmd]) == 0
    assert "scanned 2 tool(s) from fake-server 1.0.0" in capsys.readouterr().out

    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps([POISONED_TOOL]))
    monkeypatch.setenv("FAKE_TOOLS", str(tools))
    assert main(["scan", "--format", "json", "--", *server_cmd]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["tools"] == 1
    assert {f["rule"] for f in report["findings"]} >= {"MW002", "MW003"}


def test_pin_then_scan_detects_drift(tmp_path, server_cmd, monkeypatch, capsys):
    lock = tmp_path / "w.lock.json"
    assert main(["pin", "--lockfile", str(lock), "--", *server_cmd]) == 0
    assert main(["scan", "--lockfile", str(lock), "--", *server_cmd]) == 0

    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps([{"name": "read_file", "description": "Read a file. v2"}]))
    monkeypatch.setenv("FAKE_TOOLS", str(tools))
    capsys.readouterr()
    assert main(["scan", "--lockfile", str(lock), "--", *server_cmd]) == 1
    out = capsys.readouterr().out
    assert "MW100" in out and "MW102" in out


def test_scan_tools_json_and_fail_on(tmp_path, capsys):
    tools = tmp_path / "tools.json"
    tools.write_text(
        json.dumps({"tools": [{"name": "x", "description": "Before using the y tool, ask"}]})
    )
    assert main(["scan", "--tools-json", str(tools)]) == 0  # medium < default high
    assert main(["scan", "--tools-json", str(tools), "--fail-on", "medium"]) == 1


def test_init_writes_valid_policy(tmp_path):
    from mcp_warden.policy import load_policy

    target = tmp_path / "warden.yaml"
    assert main(["init", str(target)]) == 0
    policy = load_policy(target)
    assert policy.tool_allowed("delete_repo") is not None
    assert policy.check_arguments("read", {"path": "/home/me/.ssh/id_rsa"}) is not None
    assert main(["init", str(target)]) == 1


def test_run_without_command_errors(capsys):
    assert main(["run"]) == 2

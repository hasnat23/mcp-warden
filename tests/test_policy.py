import pytest

from mcp_warden.findings import Severity
from mcp_warden.policy import PolicyError, load_policy, policy_from_dict


def test_defaults():
    p = load_policy(None)
    assert p.enforcing and p.redact and p.scan_descriptions == "block"
    assert p.tool_allowed("anything") is None


def test_allow_and_deny_globs():
    p = policy_from_dict({"tools": {"allow": ["read_*", "list_*"], "deny": ["read_secret*"]}})
    assert p.tool_allowed("read_file") is None
    assert "deny rule" in p.tool_allowed("read_secrets")
    assert "allow list" in p.tool_allowed("write_file")


def test_argument_rules_specific_and_any():
    p = policy_from_dict(
        {
            "arguments": [
                {"tool": "read_*", "arg": "path", "deny_pattern": r"\.ssh", "reason": "no keys"},
                {"tool": "*", "deny_pattern": r"rm\s+-rf"},
            ]
        }
    )
    assert "no keys" in p.check_arguments("read_file", {"path": "/home/u/.ssh/id_rsa"})
    assert p.check_arguments("write_file", {"path": "/home/u/.ssh/x"}) is None
    reason = p.check_arguments("shell", {"opts": {"cmd": ["ls", "rm -rf /"]}})
    assert reason and "opts.cmd[1]" in reason


def test_yaml_file_resolves_paths_relative_to_policy(tmp_path):
    f = tmp_path / "warden.yaml"
    f.write_text(
        "mode: monitor\n"
        "scan: {results: block, block_severity: medium}\n"
        "pinning: {lockfile: locks/w.json}\n"
        "audit: {path: audit.jsonl}\n"
        "redact: false\n"
    )
    p = load_policy(f)
    assert p.mode == "monitor" and not p.enforcing
    assert p.block_severity is Severity.MEDIUM
    assert p.lockfile == str(tmp_path / "locks/w.json")
    assert p.audit_path == str(tmp_path / "audit.jsonl")
    assert p.redact is False


@pytest.mark.parametrize(
    "data",
    [
        {"version": 2},
        {"mode": "yolo"},
        {"scan": {"descriptions": "maybe"}},
        {"arguments": [{"tool": "x"}]},
        {"arguments": [{"deny_pattern": "("}]},
        {"rate_limits": [{"max_calls": 0, "per_seconds": 1}]},
    ],
)
def test_invalid_policies(data):
    with pytest.raises(PolicyError):
        policy_from_dict(data)

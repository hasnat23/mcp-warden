import json

from conftest import POISONED_TOOL

from mcp_warden.cli import main
from mcp_warden.findings import Finding, Severity
from mcp_warden.sarif import rule_catalog, to_sarif
from mcp_warden.scanner import RULES


def test_catalog_covers_every_rule_id_the_code_can_emit():
    ids = set(rule_catalog())
    assert {r.id for r in RULES} <= ids
    assert {"MW005", "MW008", "MW010", "MW100", "MW101", "MW102"} <= ids


def test_sarif_structure():
    findings = [
        Finding("MW002", Severity.HIGH, "tag", "add", "description", "<IMPORTANT>"),
        Finding("MW101", Severity.MEDIUM, "new", "x"),
    ]
    log = to_sarif(findings, "mcp.json")
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    first, second = run["results"]
    assert log["version"] == "2.1.0"
    assert rules[first["ruleIndex"]]["id"] == "MW002"
    assert first["level"] == "error" and second["level"] == "warning"
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "mcp.json"
    assert first["message"]["text"].startswith("add (description): ")
    assert first["properties"]["evidence"] == "<IMPORTANT>"
    assert "properties" not in second
    assert first["partialFingerprints"] != second["partialFingerprints"]


def test_cli_writes_sarif_file_and_prints_text(tmp_path, capsys):
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps([POISONED_TOOL]))
    out = tmp_path / "report.sarif"
    code = main(["scan", "--tools-json", str(tools), "--format", "sarif", "-o", str(out)])
    assert code == 1
    assert "finding(s)" in capsys.readouterr().out
    log = json.loads(out.read_text())
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in log["runs"][0]["results"]
    }
    assert uris == {str(tools)}


def test_cli_sarif_to_stdout(tmp_path, capsys):
    tools = tmp_path / "tools.json"
    tools.write_text("[]")
    assert main(["scan", "--tools-json", str(tools), "--format", "sarif"]) == 0
    assert json.loads(capsys.readouterr().out)["runs"][0]["results"] == []

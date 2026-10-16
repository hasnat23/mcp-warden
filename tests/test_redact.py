from mcp_warden.redact import Redactor


def test_redacts_common_secrets():
    r = Redactor.build()
    text = (
        "aws AKIAIOSFODNN7EXAMPLE gh ghp_"
        + "a" * 36
        + " ant sk-ant-api03-"
        + "b" * 30
        + " openai sk-proj-"
        + "c" * 30
        + " password=hunter2hunter2"
    )
    out, n = r.redact_text(text)
    assert n == 5
    for label in ("aws-access-key", "github-token", "anthropic-key", "openai-key"):
        assert f"[REDACTED:{label}]" in out
    assert "password=[REDACTED:password-assignment]" in out
    assert "hunter2" not in out


def test_private_key_block():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----"
    out, n = Redactor.build().redact_text(f"key:\n{pem}\nend")
    assert n == 1 and "abc" not in out and out.endswith("end")


def test_redacts_nested_json_without_mutating_input():
    value = {"content": [{"type": "text", "text": "token xoxb-1234567890-abcdef"}], "n": 3}
    out, n = Redactor.build().redact(value)
    assert n == 1
    assert out["content"][0]["text"] == "token [REDACTED:slack-token]"
    assert value["content"][0]["text"].startswith("token xoxb")
    assert out["n"] == 3


def test_extra_patterns():
    r = Redactor.build([("employee-id", r"EMP-\d{6}")])
    assert r.redact_text("id EMP-123456")[0] == "id [REDACTED:employee-id]"


def test_plain_text_untouched():
    text = "The skiing season starts in December; ask the desk for a pass."
    assert Redactor.build().redact_text(text) == (text, 0)

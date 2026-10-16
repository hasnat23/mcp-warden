# Contributing

Issues and pull requests are welcome, especially:

- **New detection rules** with a real-world example of the attack and a test proving the rule
  fires on it. Every rule must also stay silent on the reference servers (the `smoke` CI job).
- **False positives**: paste the tool description that was flagged; it becomes a regression test.
- **Transports and client integrations.**

## Setup

```bash
uv venv && uv pip install -e '.[dev]'
pytest
ruff check . && ruff format --check . && mypy
```

Keep security decisions in `Warden` (pure, synchronous) and I/O in the transport layer, so every
decision can be unit tested without processes.

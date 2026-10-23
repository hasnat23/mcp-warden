# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Remote MCP servers over Streamable HTTP: `run`, `scan` and `pin` accept `--url` and
  repeatable `-H 'Name: value'` headers, with session handling and SSE streaming (#5).
- OpenTelemetry spans for tool calls and tool listings via `run --otel` or
  `telemetry: {otel: true}`, using the GenAI semantic conventions; optional extra
  `mcp-warden[otel]` (#6).
- Multi-server mode: `run --config servers.yaml` fronts several stdio and HTTP servers as one,
  exposing tools as `server__tool` with a policy, lockfile and rate limits per server.
  Audit records and spans carry the server name.
- `mcp-warden serve`: the multi-server gateway over Streamable HTTP for shared team use, with
  spec sessions, optional bearer token, Origin checks, `/healthz`, and the caller's address
  and session in audit records and spans.

### Fixed
- Cancelled tool calls (`notifications/cancelled`) are audited and no longer leak pending
  state; responses with an untracked id are still redacted (#3, #4).
- Transport and server errors in the CLI print a one-line message instead of a traceback (#5).

## [0.1.0] - 2026-10-16

### Added
- stdio proxy and transport-agnostic `Warden` policy engine (#1).
- Tool-poisoning and prompt-injection scanner, rules MW001 to MW010 (#1).
- Tool definition pinning with a lockfile to detect rug pulls, MW100 to MW102 (#1).
- Policy file: allow/deny globs, argument deny patterns, rate limits, `enforce` and
  `monitor` modes (#1).
- Secret redaction in tool results and a JSONL audit log (#1).
- CLI commands `run`, `scan`, `pin` and `init` (#1).
- SARIF output and a composite GitHub Action for code scanning (#2).

[Unreleased]: https://github.com/hasnat23/mcp-warden/compare/2b0f14a...main
[0.1.0]: https://github.com/hasnat23/mcp-warden/tree/2b0f14a

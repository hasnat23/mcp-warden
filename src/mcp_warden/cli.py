"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp_warden import __version__
from mcp_warden.client import MCPError
from mcp_warden.findings import Finding, Severity
from mcp_warden.http_transport import TransportError
from mcp_warden.pinning import Lockfile
from mcp_warden.policy import PolicyError, load_policy
from mcp_warden.scanner import scan_tools

EXAMPLE_POLICY = """\
# mcp-warden policy. Docs: https://github.com/hasnat23/mcp-warden#policy-reference
version: 1
mode: enforce            # enforce | monitor (log what would be blocked, block nothing)

tools:
  allow: []              # glob patterns; empty means every tool not denied is allowed
  deny:
    - "delete_*"
    - "*_execute*"

arguments:
  - tool: "*"
    deny_pattern: "(^|/)\\\\.(ssh|aws|gnupg)(/|$)|id_(rsa|ed25519)|\\\\.env$"
    reason: "credential files are off limits"

rate_limits:
  - tool: "*"
    max_calls: 120
    per_seconds: 60

scan:
  descriptions: block    # hide tools whose description looks poisoned
  results: warn          # block | warn | off
  block_severity: high   # low | medium | high

redact:
  enabled: true
  patterns: []           # extra: [{name: internal-id, pattern: "ACME-[0-9]{8}"}]

pinning:
  lockfile: warden.lock.json
  on_change: block       # hide tools whose definition changed since pinning

audit:
  path: warden-audit.jsonl
  log_arguments: false
"""


def _command(args: argparse.Namespace) -> list[str]:
    cmd = list(args.command or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    return cmd


def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.WARNING
    logging.basicConfig(level=level, format="mcp-warden: %(message)s", stream=sys.stderr)


def _headers(args: argparse.Namespace) -> dict[str, str]:
    from mcp_warden.http_transport import parse_header

    return dict(parse_header(h) for h in args.header or [])


def _load_specs(args: argparse.Namespace) -> list[Any]:
    from mcp_warden.servers import load_servers, lockfile_for

    specs = load_servers(args.config)
    if args.lockfile:
        for spec in specs:
            spec.policy.lockfile = lockfile_for(args.lockfile, spec.name)
    return specs


def _apply_overrides(args: argparse.Namespace, policies: list[Any]) -> None:
    for p in policies:
        if args.monitor:
            p.mode = "monitor"
        if args.audit:
            p.audit_path = args.audit
        if args.lockfile and not args.config:
            p.lockfile = args.lockfile
        if args.otel:
            p.otel = True


def _sinks(policies: list[Any]) -> list[Any] | None:
    """Audit sinks the policies ask for; None (after printing why) if unavailable."""
    if not any(p.otel for p in policies):
        return []
    from mcp_warden.telemetry import OTelSink, TelemetryUnavailable

    try:
        return [OTelSink(service_name=policies[0].otel_service_name)]
    except TelemetryUnavailable as exc:
        print(f"mcp-warden: {exc}", file=sys.stderr)
        return None


def cmd_run(args: argparse.Namespace) -> int:
    from mcp_warden.proxy import run_stdio_proxy
    from mcp_warden.warden import Warden

    command = _command(args)
    if sum(map(bool, (command, args.url, args.config))) != 1:
        print(
            "mcp-warden run: give one of --config, --url or a server command after --",
            file=sys.stderr,
        )
        return 2
    if args.config and args.policy:
        print("mcp-warden run: --policy is set per server in --config", file=sys.stderr)
        return 2
    specs = _load_specs(args) if args.config else []
    policies = [s.policy for s in specs] or [load_policy(args.policy)]
    _apply_overrides(args, policies)
    policy = policies[0]
    sinks = _sinks(policies)
    if sinks is None:
        return 2
    if args.config:
        from mcp_warden.gateway import run_gateway

        try:
            return asyncio.run(run_gateway(specs, sinks=sinks))
        except KeyboardInterrupt:
            return 130
    if args.url:
        from mcp_warden.http_transport import StreamableHTTP
        from mcp_warden.proxy import run_http_bridge

        transport = StreamableHTTP(args.url, _headers(args))
        try:
            return asyncio.run(run_http_bridge(transport, Warden(policy, sinks=sinks)))
        except KeyboardInterrupt:
            return 130
    try:
        return asyncio.run(run_stdio_proxy(command, Warden(policy, sinks=sinks)))
    except FileNotFoundError as exc:
        print(f"mcp-warden: cannot start server: {exc}", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130


def cmd_serve(args: argparse.Namespace) -> int:
    import os

    from mcp_warden.serve import GatewayServer, run_server

    token = None
    if args.token_env:
        token = os.environ.get(args.token_env)
        if not token:
            print(f"mcp-warden serve: ${args.token_env} is empty or unset", file=sys.stderr)
            return 2
    specs = _load_specs(args)
    _apply_overrides(args, [s.policy for s in specs])
    sinks = _sinks([s.policy for s in specs])
    if sinks is None:
        return 2
    server = GatewayServer(
        specs,
        host=args.host,
        port=args.port,
        path=args.path,
        sinks=sinks,
        token=token,
        allowed_origins=args.allow_origin or [],
    )
    return run_server(server)


def _load_tools(args: argparse.Namespace) -> tuple[str, list[dict[str, Any]]]:
    if args.tools_json:
        data = json.loads(Path(args.tools_json).read_text(encoding="utf-8"))
        tools = data.get("tools", data) if isinstance(data, dict) else data
        return args.tools_json, [t for t in tools if isinstance(t, dict)]
    if args.url:
        from mcp_warden.client import fetch_tools_http

        info, tools = fetch_tools_http(args.url, _headers(args), timeout=args.timeout)
        return f"{info.get('name', args.url)} {info.get('version', '')}".strip(), tools
    command = _command(args)
    if not command:
        raise SystemExit("mcp-warden: give a server command after --, --url URL or --tools-json")
    from mcp_warden.client import fetch_tools

    info, tools = asyncio.run(fetch_tools(command, timeout=args.timeout))
    label = f"{info.get('name', command[0])} {info.get('version', '')}".strip()
    return label, tools


def _print_text(label: str, tools: list[dict[str, Any]], findings: list[Finding]) -> None:
    print(f"mcp-warden {__version__} scanned {len(tools)} tool(s) from {label}\n")
    if not findings:
        print("No findings.")
        return
    order = sorted(findings, key=lambda f: (-f.severity, f.tool or "", f.rule))
    width = max(len(f.tool or "-") for f in order)
    for f in order:
        print(f"  {str(f.severity).upper():<6} {f.rule}  {(f.tool or '-'):<{width}}  {f.message}")
        if f.location or f.evidence:
            where = f"at {f.location}" if f.location else ""
            ev = f"  {f.evidence!r}" if f.evidence else ""
            print(f"  {'':<6} {'':<5}  {'':<{width}}  {where}{ev}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), reverse=True) if n)
    print(f"\n{len(findings)} finding(s): {summary}")


def cmd_scan(args: argparse.Namespace) -> int:
    label, tools = _load_tools(args)
    findings = scan_tools(tools)
    lockfile = args.lockfile
    if lockfile is None and args.policy:
        lockfile = load_policy(args.policy).lockfile
    if lockfile and Path(lockfile).exists():
        findings.extend(Lockfile.load(lockfile).check(tools))

    report: dict[str, Any] | None = None
    if args.format == "json":
        report = {
            "version": __version__,
            "target": label,
            "tools": len(tools),
            "findings": [f.to_dict() for f in findings],
        }
    elif args.format == "sarif":
        from mcp_warden.sarif import to_sarif

        report = to_sarif(findings, args.sarif_uri or args.tools_json or args.policy or label)

    if report is None:
        _print_text(label, tools, findings)
    elif args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        _print_text(label, tools, findings)
    else:
        print(json.dumps(report, indent=2))

    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= threshold for f in findings) else 0


def cmd_pin(args: argparse.Namespace) -> int:
    label, tools = _load_tools(args)
    lock = (
        Lockfile.load(args.lockfile)
        if Path(args.lockfile).exists()
        else Lockfile(Path(args.lockfile))
    )
    before = dict(lock.tools)
    lock.pin(tools)
    lock.save()
    changed = sum(1 for k, v in lock.tools.items() if before.get(k) != v)
    print(f"pinned {len(tools)} tool(s) from {label} to {args.lockfile} ({changed} new or changed)")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    target.write_text(EXAMPLE_POLICY, encoding="utf-8")
    print(f"wrote {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-warden",
        description="Security gateway for MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging to stderr")
    parser.add_argument("-q", "--quiet", action="store_true", help="only log errors")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_remote(p: argparse.ArgumentParser) -> None:
        p.add_argument("--url", help="remote MCP server (Streamable HTTP endpoint)")
        p.add_argument(
            "-H",
            "--header",
            action="append",
            metavar="'NAME: VALUE'",
            help="HTTP header for --url, repeatable (e.g. 'Authorization: Bearer ...')",
        )

    run = sub.add_parser(
        "run", help="proxy an MCP server (stdio or --url) through the policy engine"
    )
    run.add_argument("-p", "--policy", help="policy YAML (default: built-in safe defaults)")
    run.add_argument("--audit", help="audit log path (overrides policy)")
    run.add_argument("--lockfile", help="tool pin lockfile (overrides policy)")
    run.add_argument("--monitor", action="store_true", help="log decisions, block nothing")
    run.add_argument(
        "--otel", action="store_true", help="export spans via OpenTelemetry (OTEL_* env vars)"
    )
    run.add_argument(
        "--config", help="servers YAML: front several servers as one (tools become server__tool)"
    )
    add_remote(run)
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- server command and args")
    run.set_defaults(func=cmd_run)

    serve = sub.add_parser(
        "serve", help="serve the servers in --config to remote clients over Streamable HTTP"
    )
    serve.add_argument("--config", required=True, help="servers YAML (see run --config)")
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8765, help="bind port (default: 8765)")
    serve.add_argument("--path", default="/mcp", help="MCP endpoint path (default: /mcp)")
    serve.add_argument(
        "--token-env",
        metavar="VAR",
        help="require 'Authorization: Bearer <token>' with the token read from $VAR",
    )
    serve.add_argument(
        "--allow-origin",
        action="append",
        metavar="ORIGIN",
        help="browser Origin to accept besides localhost, repeatable ('*' for any)",
    )
    serve.add_argument("--audit", help="audit log path (overrides policy)")
    serve.add_argument("--lockfile", help="tool pin lockfile, split per server")
    serve.add_argument("--monitor", action="store_true", help="log decisions, block nothing")
    serve.add_argument("--otel", action="store_true", help="export spans via OpenTelemetry")
    serve.set_defaults(func=cmd_serve)

    def add_target(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tools-json", help="scan a saved tools/list result instead of a server")
        add_remote(p)
        p.add_argument("--timeout", type=float, default=30.0, help="seconds per request")
        p.add_argument("command", nargs=argparse.REMAINDER, help="-- server command and args")

    scan = sub.add_parser("scan", help="audit a server's tools and exit non-zero on findings")
    scan.add_argument("-p", "--policy", help="policy YAML (used for its lockfile)")
    scan.add_argument("--lockfile", help="compare against this lockfile")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "-o", "--output", help="write the json/sarif report here and print text to stdout"
    )
    scan.add_argument(
        "--sarif-uri",
        help="file SARIF results point at (default: --tools-json, --policy, or the server name)",
    )
    scan.add_argument("--fail-on", default="high", help="low|medium|high (default: high)")
    add_target(scan)
    scan.set_defaults(func=cmd_scan)

    pin = sub.add_parser("pin", help="write tool fingerprints to a lockfile")
    pin.add_argument("--lockfile", default="warden.lock.json")
    add_target(pin)
    pin.set_defaults(func=cmd_pin)

    init = sub.add_parser("init", help="write an example policy file")
    init.add_argument("path", nargs="?", default="warden.yaml")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose, args.quiet)
    try:
        return int(args.func(args))
    except PolicyError as exc:
        print(f"mcp-warden: invalid policy: {exc}", file=sys.stderr)
        return 2
    except (TransportError, MCPError, ValueError) as exc:
        print(f"mcp-warden: {exc}", file=sys.stderr)
        return 2

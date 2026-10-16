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
from mcp_warden.findings import Finding, Severity
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


def cmd_run(args: argparse.Namespace) -> int:
    from mcp_warden.proxy import run_stdio_proxy
    from mcp_warden.warden import Warden

    command = _command(args)
    if not command:
        print("mcp-warden run: missing server command after --", file=sys.stderr)
        return 2
    policy = load_policy(args.policy)
    if args.monitor:
        policy.mode = "monitor"
    if args.audit:
        policy.audit_path = args.audit
    if args.lockfile:
        policy.lockfile = args.lockfile
    try:
        return asyncio.run(run_stdio_proxy(command, Warden(policy)))
    except FileNotFoundError as exc:
        print(f"mcp-warden: cannot start server: {exc}", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130


def _load_tools(args: argparse.Namespace) -> tuple[str, list[dict[str, Any]]]:
    if args.tools_json:
        data = json.loads(Path(args.tools_json).read_text(encoding="utf-8"))
        tools = data.get("tools", data) if isinstance(data, dict) else data
        return args.tools_json, [t for t in tools if isinstance(t, dict)]
    command = _command(args)
    if not command:
        raise SystemExit("mcp-warden: give a server command after -- or --tools-json FILE")
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

    if args.format == "json":
        payload = {
            "version": __version__,
            "target": label,
            "tools": len(tools),
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_text(label, tools, findings)

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

    run = sub.add_parser("run", help="proxy a stdio MCP server through the policy engine")
    run.add_argument("-p", "--policy", help="policy YAML (default: built-in safe defaults)")
    run.add_argument("--audit", help="audit log path (overrides policy)")
    run.add_argument("--lockfile", help="tool pin lockfile (overrides policy)")
    run.add_argument("--monitor", action="store_true", help="log decisions, block nothing")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- server command and args")
    run.set_defaults(func=cmd_run)

    def add_target(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tools-json", help="scan a saved tools/list result instead of a server")
        p.add_argument("--timeout", type=float, default=30.0, help="seconds per request")
        p.add_argument("command", nargs=argparse.REMAINDER, help="-- server command and args")

    scan = sub.add_parser("scan", help="audit a server's tools and exit non-zero on findings")
    scan.add_argument("-p", "--policy", help="policy YAML (used for its lockfile)")
    scan.add_argument("--lockfile", help="compare against this lockfile")
    scan.add_argument("--format", choices=("text", "json"), default="text")
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

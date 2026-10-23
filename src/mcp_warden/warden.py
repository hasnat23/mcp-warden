"""The policy engine that sits between an MCP client and server.

``Warden`` is transport-agnostic and synchronous: it takes one decoded JSON-RPC
message at a time and returns what should be forwarded to each side. The stdio
proxy (and any future HTTP transport) is a thin shell around it, which keeps all
security decisions unit-testable without spawning processes.
"""

from __future__ import annotations

import copy
import json
import logging
import time
from collections.abc import Callable, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from mcp_warden.audit import AuditLog
from mcp_warden.findings import Finding, Severity
from mcp_warden.pinning import Lockfile, tool_fingerprint
from mcp_warden.policy import Policy
from mcp_warden.ratelimit import RateLimiter
from mcp_warden.redact import Redactor
from mcp_warden.scanner import scan_result, scan_tools

log = logging.getLogger("mcp_warden")

Message = dict[str, Any]
Sink = Callable[[dict[str, Any]], None]

# Fields about the calling client (e.g. its HTTP session) added to audit records
# emitted while handling that client's request.
AUDIT_CONTEXT: ContextVar[dict[str, Any] | None] = ContextVar("mcp_warden_audit", default=None)


@dataclass
class Outcome:
    to_server: list[Any] = field(default_factory=list)
    to_client: list[Any] = field(default_factory=list)


@dataclass
class _Pending:
    method: str
    started: float
    tool: str | None = None
    arguments: Any = None


def _id_key(msg_id: Any) -> str:
    return json.dumps(msg_id, sort_keys=True)


def blocked_result(reason: str) -> dict[str, Any]:
    """A tool result the model can read, explaining why the call did not run."""
    return {
        "content": [{"type": "text", "text": f"Blocked by mcp-warden: {reason}"}],
        "isError": True,
    }


class Warden:
    def __init__(
        self,
        policy: Policy,
        *,
        audit: AuditLog | None = None,
        sinks: Sequence[Sink] = (),
        clock: Callable[[], float] = time.monotonic,
        label: str | None = None,
    ):
        self.policy = policy
        # Names the upstream server in audit records when one process fronts several.
        self.label = label
        self.audit = audit if audit is not None else AuditLog(policy.audit_path)
        # Extra consumers of every audit record (e.g. OpenTelemetry). They see the
        # same redacted records as the log and must never break the proxy.
        self.sinks = list(sinks)
        self.redactor = Redactor.build(policy.redact_extra)
        self.limiter = RateLimiter(policy.rate_limits, clock=clock)
        self.lock = Lockfile.load(policy.lockfile) if policy.lockfile else None
        # Trust on first use: with no lockfile yet, the first listing becomes the pin.
        self._tofu = self.lock is not None and not self.lock.exists
        self._clock = clock
        self._pending: dict[str, _Pending] = {}
        self.hidden_tools: dict[str, str] = {}
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------ client -> server

    def from_client(self, msg: Any) -> Outcome:
        if isinstance(msg, dict) and msg.get("method") == "notifications/cancelled":
            self._on_cancelled(msg)
            return Outcome(to_server=[msg])
        if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
            return Outcome(to_server=[msg])
        method = msg["method"]
        if method == "tools/call":
            return self._on_tool_call(msg)
        if method == "tools/list":
            self._pending[_id_key(msg["id"])] = _Pending(method, self._clock())
        return Outcome(to_server=[msg])

    def _on_tool_call(self, msg: Message) -> Outcome:
        params = msg.get("params") or {}
        name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        reason = (
            self.hidden_tools.get(name)
            or self.policy.tool_allowed(name)
            or self.policy.check_arguments(name, arguments if isinstance(arguments, dict) else {})
            or self.limiter.check(name)
        )
        if reason:
            enforce = self.policy.enforcing
            self._audit_call(name, arguments, "deny" if enforce else "would_deny", reason=reason)
            log.warning("%s tools/call %s: %s", "denied" if enforce else "would deny", name, reason)
            if enforce:
                reply = {"jsonrpc": "2.0", "id": msg["id"], "result": blocked_result(reason)}
                return Outcome(to_client=[reply])
        self._pending[_id_key(msg["id"])] = _Pending("tools/call", self._clock(), name, arguments)
        return Outcome(to_server=[msg])

    def _on_cancelled(self, msg: Message) -> None:
        # A cancelled request may never get a response, so its pending entry would
        # otherwise live for the rest of the session and the call would go unaudited.
        params = msg.get("params") or {}
        if "requestId" not in params:
            return
        pending = self._pending.pop(_id_key(params["requestId"]), None)
        if pending is not None and pending.method == "tools/call":
            self._audit_call(
                pending.tool or "",
                pending.arguments,
                "allow",
                cancelled=True,
                reason=params.get("reason"),
                latency_ms=round((self._clock() - pending.started) * 1000, 2),
            )

    # ------------------------------------------------------------------ server -> client

    def from_server(self, msg: Any) -> Outcome:
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            return Outcome(to_client=[msg])
        pending = self._pending.pop(_id_key(msg["id"]), None)
        if pending is None:
            return Outcome(to_client=[self._redact_unmatched(msg)])
        if pending.method == "tools/list" and isinstance(msg.get("result"), dict):
            return Outcome(to_client=[self._on_tools_list(msg)])
        if pending.method == "tools/call":
            return Outcome(to_client=[self._on_tool_result(msg, pending)])
        return Outcome(to_client=[msg])

    def _redact_unmatched(self, msg: Message) -> Message:
        """Responses we are not tracking (e.g. arriving after a cancel) still get redacted."""
        if not self.policy.redact or "result" not in msg:
            return msg
        result, hits = self.redactor.redact(msg["result"])
        if not hits:
            return msg
        log.warning("redacted %d secret(s) from an untracked response", hits)
        return {**msg, "result": result}

    def _on_tools_list(self, msg: Message) -> Message:
        result = msg["result"]
        tools = [t for t in result.get("tools") or [] if isinstance(t, dict)]
        policy = self.policy

        findings: list[Finding] = []
        if policy.scan_descriptions != "off":
            findings.extend(scan_tools(tools))
        if self.lock is not None:
            if self._tofu:
                self.lock.tools.update({str(t.get("name")): tool_fingerprint(t) for t in tools})
                self.lock.save()
                log.info("pinned %d tool(s) to %s", len(tools), self.lock.path)
                # Only the first complete listing is trusted; later drift must be flagged.
                if not result.get("nextCursor"):
                    self._tofu = False
            else:
                # A single page cannot prove a tool was removed, so MW102 is left to `scan`.
                findings.extend(f for f in self.lock.check(tools) if f.rule != "MW102")
        self.findings.extend(findings)

        block_reasons: dict[str, str] = {}
        for f in findings:
            if f.tool is None or f.tool in block_reasons:
                continue
            if (f.rule == "MW100" and policy.on_change == "block") or (
                f.rule not in ("MW100", "MW101", "MW102")
                and policy.scan_descriptions == "block"
                and f.severity >= policy.block_severity
            ):
                block_reasons[f.tool] = f"{f.rule} {f.message}"

        for tool in tools:
            self.hidden_tools.pop(str(tool.get("name")), None)
        if policy.enforcing:
            self.hidden_tools.update(block_reasons)

        for f in findings:
            log.warning("[%s] %s %s: %s", f.severity, f.rule, f.tool or "-", f.message)
        self._emit(
            "tools_list",
            tools=len(tools),
            hidden=sorted(block_reasons) if policy.enforcing else [],
            would_hide=[] if policy.enforcing else sorted(block_reasons),
            findings=[f.to_dict() for f in findings],
        )

        if not policy.enforcing or not block_reasons:
            return msg
        out = copy.deepcopy(msg)
        out["result"]["tools"] = [t for t in tools if str(t.get("name")) not in block_reasons]
        return out

    def _on_tool_result(self, msg: Message, pending: _Pending) -> Message:
        latency_ms = round((self._clock() - pending.started) * 1000, 2)
        name = pending.tool or ""
        if "result" not in msg:
            self._audit_call(
                name, pending.arguments, "allow", latency_ms=latency_ms, error=msg.get("error")
            )
            return msg

        out = copy.deepcopy(msg)
        redactions = 0
        if self.policy.redact:
            out["result"], redactions = self.redactor.redact(out["result"])
            if redactions:
                log.warning("redacted %d secret(s) from %s result", redactions, name)

        findings: list[Finding] = []
        if self.policy.scan_results != "off":
            findings = scan_result(out["result"], tool=name)
            self.findings.extend(findings)
        blocked = (
            self.policy.scan_results == "block"
            and self.policy.enforcing
            and any(f.severity >= self.policy.block_severity for f in findings)
        )
        if blocked:
            worst = max(findings, key=lambda f: f.severity)
            out["result"] = blocked_result(
                f"result withheld, possible prompt injection ({worst.rule} {worst.message})"
            )
        for f in findings:
            log.warning("[%s] %s in result of %s: %s", f.severity, f.rule, name, f.message)

        self._audit_call(
            name,
            pending.arguments,
            "allow",
            latency_ms=latency_ms,
            redactions=redactions,
            result_blocked=blocked,
            findings=[f.to_dict() for f in findings],
            is_error=bool(out["result"].get("isError"))
            if isinstance(out["result"], dict)
            else None,
        )
        return out

    # ------------------------------------------------------------------ helpers

    def _audit_call(self, tool: str, arguments: Any, decision: str, **fields: Any) -> None:
        if self.policy.audit_arguments:
            fields["arguments"] = self.redactor.redact(arguments)[0]
        elif isinstance(arguments, dict):
            fields["argument_keys"] = sorted(arguments)
        self._emit("tool_call", tool=tool, decision=decision, **fields)

    def _emit(self, event: str, **fields: Any) -> None:
        if self.label is not None:
            fields = {"server": self.label, **fields}
        context = AUDIT_CONTEXT.get()
        if context:
            fields = {**context, **fields}
        record = self.audit.write(event, **fields)
        for sink in self.sinks:
            try:
                sink(record)
            except Exception:
                log.exception("audit sink %r failed", sink)

    def close(self) -> None:
        self.audit.close()
        for sink in self.sinks:
            closer = getattr(sink, "close", None)
            if callable(closer):
                closer()

    def worst_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

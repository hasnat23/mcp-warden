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
from mcp_warden.scanner import scan_result, scan_text, scan_tools

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


def blocked_resource(uri: str, reason: str) -> dict[str, Any]:
    """A ``resources/read`` result standing in for content that was withheld."""
    text = f"Blocked by mcp-warden: {reason}"
    return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]}


def blocked_prompt(reason: str) -> dict[str, Any]:
    """A ``prompts/get`` result standing in for a prompt that was withheld."""
    text = f"Blocked by mcp-warden: {reason}"
    return {"messages": [{"role": "user", "content": {"type": "text", "text": text}}]}


def refused(msg_id: Any, reason: str) -> dict[str, Any]:
    """The answer to a server's request (e.g. sampling) that the client never sees.

    Code -1 is what the spec uses for a user declining a sampling request.
    """
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -1, "message": f"Blocked by mcp-warden: {reason}"},
    }


def _request_texts(method: str, params: Any) -> list[tuple[str, str]]:
    """The text a sampling or elicitation request would put in front of the model or user."""
    if not isinstance(params, dict):
        return []
    out = []
    if method == "sampling/createMessage":
        if isinstance(params.get("systemPrompt"), str):
            out.append(("systemPrompt", params["systemPrompt"]))
        for i, m in enumerate(params.get("messages") or []):
            content = m.get("content") if isinstance(m, dict) else None
            blocks = content if isinstance(content, list) else [content]
            for j, block in enumerate(blocks):
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    out.append((f"messages[{i}].content[{j}]", block["text"]))
    elif method == "elicitation/create" and isinstance(params.get("message"), str):
        out.append(("message", params["message"]))
    return out


# Requests whose responses the warden inspects in single-server mode.
_TRACKED = ("tools/list", "resources/list", "prompts/list")


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
        raw = msg.get("params")
        params: dict[str, Any] = raw if isinstance(raw, dict) else {}
        if method in ("resources/read", "prompts/get"):
            if method == "resources/read":
                target = str(params.get("uri", ""))
                blocked = self.admit_resource(target)
            else:
                target = str(params.get("name", ""))
                blocked = self.admit_prompt(target)
            if blocked is not None:
                return Outcome(to_client=[{"jsonrpc": "2.0", "id": msg["id"], "result": blocked}])
            self._pending[_id_key(msg["id"])] = _Pending(method, self._clock(), target)
        elif method == "resources/subscribe":
            uri = str(params.get("uri", ""))
            if self.admit_resource(uri, event="resource_subscribe") is not None:
                # Answer as if the resource did not exist, so a denied URI stays hidden.
                error = {"code": -32002, "message": f"resource not found: {uri}"}
                return Outcome(to_client=[{"jsonrpc": "2.0", "id": msg["id"], "error": error}])
        elif method in _TRACKED:
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
        if isinstance(msg, dict) and "method" in msg and "id" in msg and msg["method"] != "ping":
            forward, refusal = self.screen_server_request(msg)
            if refusal is not None:
                return Outcome(to_server=[refusal])
            return Outcome(to_client=[forward])
        if not isinstance(msg, dict) or "method" in msg or "id" not in msg:
            return Outcome(to_client=[msg])
        pending = self._pending.pop(_id_key(msg["id"]), None)
        if pending is None:
            return Outcome(to_client=[self._redact_unmatched(msg)])
        if pending.method == "tools/list" and isinstance(msg.get("result"), dict):
            return Outcome(to_client=[self._on_tools_list(msg)])
        if pending.method == "tools/call":
            return Outcome(to_client=[self._on_tool_result(msg, pending)])
        result = msg.get("result")
        if not isinstance(result, dict):
            return Outcome(to_client=[msg])
        target = pending.tool or ""
        if pending.method == "resources/read":
            result = self.filter_resource(target, result)
        elif pending.method == "prompts/get":
            result = self.filter_prompt(target, result)
        elif pending.method == "resources/list":
            result = {**result, "resources": self.visible_resources(result.get("resources"))}
        elif pending.method == "prompts/list":
            result = {**result, "prompts": self.visible_prompts(result.get("prompts"))}
        return Outcome(to_client=[{**msg, "result": result}])

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

    # ------------------------------------------------------------------ server requests

    def screen_server_request(self, msg: Message) -> tuple[Message, Message | None]:
        """Check a request the server sends the client, such as sampling or elicitation.

        Sampling puts server-written text in front of the client's model, which makes it
        an injection vector like a tool result. Returns the (redacted) request to pass
        on, and the error to answer the server with instead when it is refused.
        """
        method = str(msg.get("method"))
        reason = self.policy.server_request_allowed(method)
        out, redactions = msg, 0
        findings: list[Finding] = []
        if reason is None:
            if self.policy.redact and method in ("sampling/createMessage", "elicitation/create"):
                params, redactions = self.redactor.redact(msg.get("params"))
                out = {**msg, "params": params}
            if self.policy.scan_results != "off":
                for location, text in _request_texts(method, out.get("params")):
                    findings.extend(scan_text(text, location=location))
                self.findings.extend(findings)
            if self.policy.scan_results == "block" and any(
                f.severity >= self.policy.block_severity for f in findings
            ):
                worst = max(findings, key=lambda f: f.severity)
                reason = f"possible prompt injection ({worst.rule} {worst.message})"
        for f in findings:
            log.warning(
                "[%s] %s in %s at %s: %s", f.severity, f.rule, method, f.location, f.message
            )
        decision = "allow" if reason is None else "deny" if self.policy.enforcing else "would_deny"
        if reason is not None:
            log.warning(
                "%s %s: %s", "refused" if decision == "deny" else "would refuse", method, reason
            )
        self._emit(
            "server_request",
            method=method,
            decision=decision,
            reason=reason,
            redactions=redactions,
            findings=[f.to_dict() for f in findings],
        )
        if decision == "deny":
            assert reason is not None
            return out, refused(msg.get("id"), reason)
        return out, None

    # ------------------------------------------------------------------ resources and prompts

    def admit_resource(self, uri: str, event: str = "resource_read") -> dict[str, Any] | None:
        """Check a ``resources/read`` against the policy before it reaches the server.

        Returns None to forward the read, or the result to answer with instead.
        """
        reason = self.policy.resource_allowed(uri)
        if reason is None:
            return None
        self._deny(event, reason, uri=uri)
        return blocked_resource(uri, reason) if self.policy.enforcing else None

    def admit_prompt(self, name: str) -> dict[str, Any] | None:
        """Check a ``prompts/get`` against the policy, like :meth:`admit_resource`."""
        reason = self.policy.prompt_allowed(name)
        if reason is None:
            return None
        self._deny("prompt_get", reason, prompt=name)
        return blocked_prompt(reason) if self.policy.enforcing else None

    def visible_resources(self, items: Any) -> list[Any]:
        """Drop listed resources the policy denies (only when enforcing)."""
        return self._visible(items, "uri", self.policy.resource_allowed)

    def visible_prompts(self, items: Any) -> list[Any]:
        """Drop listed prompts the policy denies (only when enforcing)."""
        return self._visible(items, "name", self.policy.prompt_allowed)

    def _visible(self, items: Any, key: str, check: Callable[[str], str | None]) -> list[Any]:
        listed: list[Any] = list(items) if isinstance(items, list) else []
        if not self.policy.enforcing:
            return listed
        return [i for i in listed if not (isinstance(i, dict) and check(str(i.get(key, ""))))]

    def _deny(self, event: str, reason: str, **fields: Any) -> None:
        decision = "deny" if self.policy.enforcing else "would_deny"
        log.warning("%s %s: %s", "denied" if self.policy.enforcing else "would deny", event, reason)
        self._emit(event, decision=decision, reason=reason, **fields)

    def filter_resource(self, uri: str, result: Any) -> Any:
        """Redact and scan a ``resources/read`` result, which goes straight to the model."""

        def blocks(r: Any) -> list[tuple[str, Any]]:
            items = r.get("contents") or [] if isinstance(r, dict) else []
            return [(f"contents[{i}]", b) for i, b in enumerate(items) if isinstance(b, dict)]

        out, record = self._screen(result, blocks)
        if record["blocked"]:
            out = blocked_resource(uri, record["reason"])
        self._emit("resource_read", uri=uri, decision="allow", **record)
        return out

    def filter_prompt(self, name: str, result: Any) -> Any:
        """Redact and scan a ``prompts/get`` result before it enters the conversation."""

        def blocks(r: Any) -> list[tuple[str, Any]]:
            items = r.get("messages") or [] if isinstance(r, dict) else []
            return [
                (f"messages[{i}]", m["content"])
                for i, m in enumerate(items)
                if isinstance(m, dict) and isinstance(m.get("content"), dict)
            ]

        out, record = self._screen(result, blocks)
        if record["blocked"]:
            out = blocked_prompt(record["reason"])
        self._emit("prompt_get", prompt=name, decision="allow", **record)
        return out

    def _screen(
        self, result: Any, blocks: Callable[[Any], list[tuple[str, Any]]]
    ) -> tuple[Any, dict[str, Any]]:
        """Redact a result, then scan the text of the blocks it yields for injections."""
        out, redactions = copy.deepcopy(result), 0
        if self.policy.redact:
            out, redactions = self.redactor.redact(out)
            if redactions:
                log.warning("redacted %d secret(s)", redactions)
        findings: list[Finding] = []
        if self.policy.scan_results != "off":
            for location, block in blocks(out):
                if isinstance(block.get("text"), str):
                    findings.extend(scan_text(block["text"], location=location))
            self.findings.extend(findings)
        blocked = (
            self.policy.scan_results == "block"
            and self.policy.enforcing
            and any(f.severity >= self.policy.block_severity for f in findings)
        )
        reason = None
        if blocked:
            worst = max(findings, key=lambda f: f.severity)
            reason = f"content withheld, possible prompt injection ({worst.rule} {worst.message})"
        for f in findings:
            log.warning("[%s] %s at %s: %s", f.severity, f.rule, f.location, f.message)
        record = {
            "redactions": redactions,
            "findings": [f.to_dict() for f in findings],
            "blocked": blocked,
            "reason": reason,
        }
        return out, record

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

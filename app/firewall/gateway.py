"""The firewall core: one request lifecycle, no HTTP knowledge.

    session -> authenticate -> rate limit -> validate -> risk -> authorize -> integrity
            -> scan input -> circuit breaker -> upstream call -> scan output -> audit -> return

Design rules:
  * Fail closed: any unexpected error becomes a DENY.
  * Every decision (allow or deny) is audited, including denials that happen very early.
  * The firewall is deterministic. No LLM is consulted for any security decision.
"""
from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from app.firewall.audit import AuditLog
from app.firewall.authentication import AuthError, Authenticator
from app.firewall.authorization import Authorizer, PermissionDenied
from app.firewall.circuit_breaker import CircuitBreakerRegistry
from app.firewall.integrity import IntegrityChecker
from app.firewall.rate_limiter import RateLimitExceeded, SlidingWindowRateLimiter
from app.firewall.risk import RiskClassifier
from app.firewall.scanner import DESCRIPTION, INPUT, OUTPUT, Scanner
from app.mcp.client import Upstream
from app.models.events import Decision, Stage
from app.models.policies import Policy, RiskLevel
from app.models.requests import (
    ApprovalOutcome,
    GatewayResult,
    ToolDefinition,
    ToolInfo,
    ToolRequest,
    UserSession,
)
from app.storage.database import Database

logger = logging.getLogger("agentic_firewall")

TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.\-]{1,128}")


@dataclass
class _Ctx:
    """What we know about the caller so far; used to build the audit record."""

    user_id: str | None = None
    role: str | None = None
    session_ref: str | None = None
    risk: RiskLevel | None = None


class UpstreamUnavailable(Exception):
    pass


class Firewall:
    def __init__(
        self,
        policy: Policy,
        db: Database,
        upstream: Upstream,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.db = db
        self.upstream = upstream
        self.auth = Authenticator(db, clock=clock, session_ttl_seconds=policy.session_ttl_seconds)
        self.authz = Authorizer(policy)
        self.risk = RiskClassifier(policy.tool_risk)
        self.integrity = IntegrityChecker(db, clock=clock)
        self.scanner = Scanner(max_chars=policy.scanner.max_scan_chars)
        self.limiter = SlidingWindowRateLimiter(
            policy.rate_limit.max_requests, policy.rate_limit.window_seconds, clock=monotonic
        )
        self.login_limiter = SlidingWindowRateLimiter(
            policy.login_rate_limit.max_requests, policy.login_rate_limit.window_seconds, clock=monotonic
        )
        self.breakers = CircuitBreakerRegistry(
            policy.circuit_breaker.failure_threshold,
            policy.circuit_breaker.cooldown_seconds,
            clock=monotonic,
        )
        self.audit = AuditLog(db, clock=clock)

    # ==========================================================================================
    # Login
    # ==========================================================================================
    def login(self, user_id: str, api_key: str, client_key: str = "unknown") -> tuple[str, UserSession]:
        rl = self.login_limiter.check(client_key)
        if not rl.allowed:
            self._audit_simple(user_id, Stage.LOGIN, Decision.DENY, "too many login attempts")
            raise RateLimitExceeded(rl.retry_after)
        try:
            session_id, session = self.auth.login(user_id, api_key)
        except AuthError:
            self._audit_simple(user_id, Stage.LOGIN, Decision.DENY, "invalid credentials")
            raise
        self._audit_simple(
            session.user_id, Stage.LOGIN, Decision.ALLOW, "login ok",
            role=session.role, session_ref=session.session_ref,
        )
        return session_id, session

    # ==========================================================================================
    # The main request lifecycle
    # ==========================================================================================
    async def handle(self, req: ToolRequest) -> GatewayResult:
        start = time.perf_counter()
        ctx = _Ctx()
        try:
            result = await self._pipeline(req, ctx)
        except Exception:
            logger.exception("internal firewall error; failing closed")
            result = self._deny(req, ctx, Stage.INTERNAL, "internal error; request denied (fail closed)")
        result.latency_ms = round((time.perf_counter() - start) * 1000, 3)
        self._audit_result(req, ctx, result)
        return result

    async def _pipeline(self, req: ToolRequest, ctx: _Ctx) -> GatewayResult:
        # 1. Authentication: who is this?
        try:
            session = self.auth.validate(req.session_id)
        except AuthError as exc:
            return self._deny(req, ctx, Stage.AUTHENTICATION, str(exc))
        ctx.user_id, ctx.role, ctx.session_ref = session.user_id, session.role, session.session_ref

        # 2. Rate limit (per user, counts every authenticated request, allowed or not)
        rl = self.limiter.check(session.user_id)
        if not rl.allowed:
            return self._deny(
                req, ctx, Stage.RATE_LIMIT,
                f"rate limit exceeded ({self.limiter.max_requests} requests per "
                f"{self.limiter.window_seconds:g}s); retry in {math.ceil(rl.retry_after)}s",
                retry_after=rl.retry_after,
            )

        # 3. Basic validation
        if not TOOL_NAME_RE.fullmatch(req.tool):
            return self._deny(req, ctx, Stage.VALIDATION, "invalid tool name")

        # 4. Risk classification
        ctx.risk = self.risk.classify(req.tool)

        # 5. Authorization: can this role use this tool at this risk level?
        decision = self.authz.check(session.role, req.tool, ctx.risk)
        if not decision.allowed:
            return self._deny(req, ctx, Stage.AUTHORIZATION, decision.reason)

        # 6. Integrity: is the live tool definition exactly what was approved?
        try:
            tools = await self._fetch_tools()
        except Exception:
            logger.exception("could not list upstream tools")
            return self._deny(req, ctx, Stage.UPSTREAM, "could not verify tool definition with upstream")
        matches = [t for t in tools if t.name == req.tool]
        if not matches:
            return self._deny(req, ctx, Stage.INTEGRITY, "tool is not exposed by the upstream server")
        if len(matches) > 1:
            return self._deny(req, ctx, Stage.INTEGRITY, "upstream exposes duplicate definitions for this tool")
        integrity = self.integrity.verify(matches[0])
        if not integrity.ok:
            return self._deny(req, ctx, Stage.INTEGRITY, integrity.reason)

        # 7. Input inspection
        scan_in = self.scanner.scan_value(req.arguments, INPUT, "arguments")
        if scan_in.blocked:
            return self._deny(req, ctx, Stage.INPUT_SCAN, f"blocked by input scanner: {scan_in.summary()}")

        # 8. Circuit breaker. After allow() returns True, the try/except below ALWAYS records
        #    a success or failure so a half-open probe can never be lost.
        breaker = self.breakers.get(req.tool)
        if not breaker.allow():
            return self._deny(
                req, ctx, Stage.CIRCUIT_BREAKER,
                f"circuit open for tool '{req.tool}'; retry in {math.ceil(breaker.retry_after())}s",
                retry_after=breaker.retry_after(),
            )

        # 9. Forward to the MCP server
        try:
            response = await asyncio.wait_for(
                self.upstream.call_tool(req.tool, req.arguments),
                timeout=self.policy.upstream_timeout_seconds,
            )
        except asyncio.CancelledError:
            breaker.record_failure()
            raise
        except Exception:
            breaker.record_failure()
            logger.exception("upstream call failed for tool %r", req.tool)
            return self._deny(req, ctx, Stage.UPSTREAM, "upstream call failed")
        if response.is_error:
            breaker.record_failure()
        else:
            breaker.record_success()

        # 10. Output inspection: never hand an unscanned response to the agent
        scan_out = self.scanner.scan_value(response.text, OUTPUT, "response")
        if scan_out.blocked:
            return self._deny(req, ctx, Stage.OUTPUT_SCAN, f"blocked by output scanner: {scan_out.summary()}")

        # 11. Return
        reason = "allowed (tool reported an error)" if response.is_error else "allowed"
        return GatewayResult(
            decision=Decision.ALLOW,
            stage=Stage.ALLOWED,
            reason=reason,
            tool=req.tool,
            user_id=ctx.user_id,
            role=ctx.role,
            risk=ctx.risk.name if ctx.risk else None,
            response=response,
        )

    # ==========================================================================================
    # Tool approval (fingerprint pinning) and discovery
    # ==========================================================================================
    async def approve_tools(
        self, approver: UserSession, names: Sequence[str] | None = None
    ) -> list[ApprovalOutcome]:
        """Pin the *current* upstream definition of each tool. Managers only.

        A definition whose text trips the scanner (hidden instructions, secret paths, ...) is
        refused, so a poisoned tool is never pinned as "trusted".
        """
        if not self.authz.can_manage(approver.role):
            raise PermissionDenied("role may not approve tools")
        tools = await self._fetch_tools()
        counts: dict[str, int] = {}
        for t in tools:
            counts[t.name] = counts.get(t.name, 0) + 1
        by_name = {t.name: t for t in tools}
        wanted = list(dict.fromkeys(names)) if names is not None else list(by_name)

        outcomes: list[ApprovalOutcome] = []
        for name in wanted:
            defn = by_name.get(name)
            if defn is None:
                outcome = ApprovalOutcome(tool=name, status="not_found", reason="tool not exposed by upstream")
            elif counts[name] > 1:
                outcome = ApprovalOutcome(tool=name, status="rejected", reason="duplicate definitions from upstream")
            else:
                outcome = self._approve_one(defn, approver)
            outcomes.append(outcome)
            self.audit.record(
                user_id=approver.user_id,
                session_ref=approver.session_ref,
                role=approver.role,
                tool=name,
                risk=self.risk.classify(name).name if TOOL_NAME_RE.fullmatch(name) else None,
                decision=Decision.ALLOW if outcome.status in ("approved", "updated", "unchanged") else Decision.DENY,
                stage=Stage.APPROVAL,
                reason=f"{outcome.status}: {outcome.reason}".rstrip(": "),
            )
        return outcomes

    def _approve_one(self, defn: ToolDefinition, approver: UserSession) -> ApprovalOutcome:
        scan = self.scanner.scan_value(defn.model_dump(), DESCRIPTION, "definition")
        if scan.blocked:
            return ApprovalOutcome(
                tool=defn.name, status="rejected", reason=f"suspicious tool definition: {scan.summary()}"
            )
        previous = self.integrity.approved_fingerprint(defn.name)
        fp = self.integrity.approve(defn, approved_by=approver.user_id)
        status = "approved" if previous is None else ("unchanged" if previous == fp else "updated")
        return ApprovalOutcome(tool=defn.name, status=status, fingerprint=fp)

    async def list_tools(self, session_id: str) -> list[ToolInfo]:
        """Tools this caller may see. Non-managers only see approved, unchanged, permitted tools,
        so a poisoned description is never relayed to an agent."""
        session = self.authenticate(session_id)
        manager = self.authz.can_manage(session.role)
        infos: list[ToolInfo] = []
        for defn in await self._fetch_tools():
            risk = self.risk.classify(defn.name)
            integrity = self.integrity.verify(defn)
            if not manager:
                if not integrity.ok or not self.authz.check(session.role, defn.name, risk).allowed:
                    continue
            infos.append(
                ToolInfo(
                    name=defn.name,
                    description=defn.description,
                    input_schema=defn.input_schema,
                    risk=risk.name,
                    integrity=integrity.status,
                )
            )
        return infos

    # ==========================================================================================
    # Helpers for the API layer
    # ==========================================================================================
    def authenticate(self, session_id: str) -> UserSession:
        """Validate a session and count the call against the caller's rate limit."""
        session = self.auth.validate(session_id)
        rl = self.limiter.check(session.user_id)
        if not rl.allowed:
            raise RateLimitExceeded(rl.retry_after)
        return session

    def require_manager(self, session_id: str) -> UserSession:
        session = self.authenticate(session_id)
        if not self.authz.can_manage(session.role):
            raise PermissionDenied("this action requires a manager role")
        return session

    # ==========================================================================================
    # Internals
    # ==========================================================================================
    async def _fetch_tools(self) -> list[ToolDefinition]:
        return await asyncio.wait_for(
            self.upstream.list_tools(), timeout=self.policy.upstream_timeout_seconds
        )

    def _deny(
        self, req: ToolRequest, ctx: _Ctx, stage: str, reason: str, retry_after: float | None = None
    ) -> GatewayResult:
        return GatewayResult(
            decision=Decision.DENY,
            stage=stage,
            reason=reason,
            tool=req.tool,
            user_id=ctx.user_id,
            role=ctx.role,
            risk=ctx.risk.name if ctx.risk else None,
            retry_after=retry_after,
        )

    def _audit_result(self, req: ToolRequest, ctx: _Ctx, result: GatewayResult) -> None:
        try:
            self.audit.record(
                user_id=ctx.user_id,
                session_ref=ctx.session_ref,
                role=ctx.role,
                tool=req.tool,
                risk=result.risk,
                decision=result.decision,
                stage=result.stage,
                reason=result.reason,
                latency_ms=result.latency_ms,
            )
        except Exception:
            # The decision stands; losing an audit row must not turn into an outage or an allow.
            logger.exception("failed to write audit record")

    def _audit_simple(
        self,
        user_id: str | None,
        stage: str,
        decision: Decision,
        reason: str,
        *,
        role: str | None = None,
        session_ref: str | None = None,
    ) -> None:
        try:
            self.audit.record(
                user_id=user_id, session_ref=session_ref, role=role, tool=None, risk=None,
                decision=decision, stage=stage, reason=reason,
            )
        except Exception:
            logger.exception("failed to write audit record")

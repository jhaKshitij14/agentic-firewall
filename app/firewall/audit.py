"""Audit logging: every decision is written to SQLite and to the `agentic_firewall.audit` logger."""
from __future__ import annotations

import logging
import time
from typing import Callable

from app.models.events import Decision, SecurityEvent
from app.storage.database import Database

logger = logging.getLogger("agentic_firewall.audit")


class AuditLog:
    def __init__(self, db: Database, *, clock: Callable[[], float] = time.time) -> None:
        self._db = db
        self._clock = clock

    def record(
        self,
        *,
        user_id: str | None,
        session_ref: str | None,
        role: str | None,
        tool: str | None,
        risk: str | None,
        decision: Decision,
        stage: str,
        reason: str,
        latency_ms: float = 0.0,
    ) -> SecurityEvent:
        # SecurityEvent sanitises attacker-controlled strings (control chars, bidi, length).
        event = SecurityEvent(
            ts=self._clock(),
            user_id=user_id,
            session_ref=session_ref,
            role=role,
            tool=tool,
            risk=risk,
            decision=decision,
            stage=stage,
            reason=reason,
            latency_ms=latency_ms,
        )
        event.id = self._db.add_audit(
            ts=event.ts,
            user_id=event.user_id,
            session_ref=event.session_ref,
            role=event.role,
            tool=event.tool,
            risk=event.risk,
            decision=event.decision.value,
            stage=event.stage,
            reason=event.reason,
            latency_ms=event.latency_ms,
        )
        logger.info(event.to_log_line())
        return event

    def recent(self, limit: int = 50) -> list[SecurityEvent]:
        return [SecurityEvent(**row) for row in self._db.recent_audit(limit)]

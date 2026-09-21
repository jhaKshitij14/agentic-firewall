"""Decisions, pipeline stage names, and the audit event model."""
from __future__ import annotations

import enum
import re
from datetime import datetime, timezone

from pydantic import BaseModel, field_validator


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Stage:
    """Where in the pipeline a decision was made."""

    LOGIN = "login"
    AUTHENTICATION = "authentication"
    RATE_LIMIT = "rate_limit"
    VALIDATION = "validation"
    AUTHORIZATION = "authorization"
    INTEGRITY = "integrity"
    INPUT_SCAN = "input_scan"
    CIRCUIT_BREAKER = "circuit_breaker"
    UPSTREAM = "upstream"
    OUTPUT_SCAN = "output_scan"
    APPROVAL = "approval"
    INTERNAL = "internal_error"
    ALLOWED = "allowed"


# Control characters, line/paragraph separators, bidi controls, zero-width chars.
# Anything attacker-controlled (tool names, argument keys) is stripped of these before
# it is stored or logged, so it cannot forge log lines or spoof what an operator sees.
_UNSAFE_LOG_CHARS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)


def sanitize(text: object, max_len: int = 300) -> str:
    s = _UNSAFE_LOG_CHARS.sub(" ", str(text))
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


class SecurityEvent(BaseModel):
    ts: float
    user_id: str | None = None
    session_ref: str | None = None  # non-reversible reference; never the raw session id
    role: str | None = None
    tool: str | None = None
    risk: str | None = None
    decision: Decision
    stage: str
    reason: str
    latency_ms: float = 0.0
    id: int | None = None

    @field_validator("user_id", "session_ref", "role", "tool", "risk", "stage", "reason")
    @classmethod
    def _clean(cls, v: str | None) -> str | None:
        return sanitize(v) if v is not None else v

    def to_log_line(self) -> str:
        when = datetime.fromtimestamp(self.ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"{when} user={self.user_id or '-'} role={self.role or '-'} tool={self.tool or '-'} "
            f"risk={self.risk or '-'} decision={self.decision.value} stage={self.stage} "
            f'reason="{self.reason}" latency_ms={self.latency_ms:.2f}'
        )

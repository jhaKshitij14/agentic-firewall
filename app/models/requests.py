"""Request/response models that cross the firewall boundary."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.models.events import Decision


class ToolRequest(BaseModel):
    session_id: str = ""
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    """What an MCP server declares about a tool. Everything here is fingerprinted."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    extras: dict[str, Any] = Field(default_factory=dict)  # any other server-declared fields


class ToolResponse(BaseModel):
    text: str = ""
    is_error: bool = False


class UserSession(BaseModel):
    user_id: str
    role: str
    session_ref: str
    created_at: float
    expires_at: float


class GatewayResult(BaseModel):
    decision: Decision
    stage: str
    reason: str
    tool: str
    user_id: str | None = None
    role: str | None = None
    risk: str | None = None
    latency_ms: float = 0.0
    retry_after: float | None = None
    response: ToolResponse | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


class ToolInfo(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any]
    risk: str
    integrity: str  # ok | changed | unapproved


class ApprovalOutcome(BaseModel):
    tool: str
    status: str  # approved | updated | unchanged | rejected | not_found
    fingerprint: str | None = None
    reason: str = ""

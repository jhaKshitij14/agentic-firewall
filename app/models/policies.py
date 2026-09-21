"""Policy models. Loaded from YAML and validated strictly (unknown keys are errors)."""
from __future__ import annotations

import enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


class RiskLevel(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any) -> "RiskLevel":
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                pass
        raise ValueError(f"invalid risk level {value!r}; expected LOW, MEDIUM, HIGH or CRITICAL")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RolePolicy(_Strict):
    # Exact tool names only. No wildcards: deny by default, allow explicitly.
    allowed_tools: list[str] = Field(default_factory=list)
    # Highest tool risk this role may invoke, even if the tool is on the allowlist.
    max_risk: RiskLevel = RiskLevel.LOW
    # May approve tool fingerprints and read logs/policies.
    can_manage: bool = False

    @field_validator("max_risk", mode="before")
    @classmethod
    def _parse_risk(cls, v: Any) -> RiskLevel:
        return RiskLevel.parse(v)

    @field_validator("allowed_tools")
    @classmethod
    def _no_wildcards(cls, v: list[str]) -> list[str]:
        for name in v:
            if not name or "*" in name or "?" in name:
                raise ValueError(f"invalid tool name {name!r}: wildcards are not supported")
        return v

    @field_serializer("max_risk")
    def _ser_risk(self, v: RiskLevel) -> str:
        return v.name


class RateLimitPolicy(_Strict):
    max_requests: int = Field(100, ge=1)
    window_seconds: float = Field(60.0, gt=0)


class CircuitBreakerPolicy(_Strict):
    failure_threshold: int = Field(5, ge=1)
    cooldown_seconds: float = Field(30.0, gt=0)


class ScannerPolicy(_Strict):
    max_scan_chars: int = Field(1_000_000, ge=1_000)


class Policy(_Strict):
    version: int = 1
    session_ttl_seconds: int = Field(3600, ge=60, le=86_400)
    upstream_timeout_seconds: float = Field(30.0, gt=0)
    roles: dict[str, RolePolicy]
    tool_risk: dict[str, RiskLevel] = Field(default_factory=dict)
    rate_limit: RateLimitPolicy = Field(default_factory=RateLimitPolicy)
    login_rate_limit: RateLimitPolicy = Field(
        default_factory=lambda: RateLimitPolicy(max_requests=10, window_seconds=60.0)
    )
    circuit_breaker: CircuitBreakerPolicy = Field(default_factory=CircuitBreakerPolicy)
    scanner: ScannerPolicy = Field(default_factory=ScannerPolicy)

    @field_validator("roles")
    @classmethod
    def _need_roles(cls, v: dict[str, RolePolicy]) -> dict[str, RolePolicy]:
        if not v:
            raise ValueError("policy must define at least one role")
        return v

    @field_validator("tool_risk", mode="before")
    @classmethod
    def _parse_tool_risk(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return {k: RiskLevel.parse(level) for k, level in v.items()}
        return v

    @field_serializer("tool_risk")
    def _ser_tool_risk(self, v: dict[str, RiskLevel]) -> dict[str, str]:
        return {k: level.name for k, level in v.items()}


def load_policy(path: str | Path) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"policy file {path} must contain a YAML mapping")
    return Policy.model_validate(raw)

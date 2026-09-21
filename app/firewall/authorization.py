"""RBAC: does this role get this tool? Deny by default."""
from __future__ import annotations

from dataclasses import dataclass

from app.models.policies import Policy, RiskLevel


class PermissionDenied(Exception):
    """Caller is authenticated but not allowed to do this."""


@dataclass(frozen=True)
class AuthzDecision:
    allowed: bool
    reason: str


class Authorizer:
    def __init__(self, policy: Policy) -> None:
        self._roles = policy.roles

    def check(self, role: str, tool: str, risk: RiskLevel) -> AuthzDecision:
        role_policy = self._roles.get(role)
        if role_policy is None:
            return AuthzDecision(False, f"unknown role '{role}'")
        if tool not in role_policy.allowed_tools:
            return AuthzDecision(False, f"role '{role}' is not permitted to use tool '{tool}'")
        if risk > role_policy.max_risk:
            return AuthzDecision(
                False,
                f"tool risk {risk.name} exceeds role '{role}' limit {role_policy.max_risk.name}",
            )
        return AuthzDecision(True, "permitted")

    def can_manage(self, role: str) -> bool:
        role_policy = self._roles.get(role)
        return bool(role_policy and role_policy.can_manage)

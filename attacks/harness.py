"""Shared test environment for attacks, the benchmark and tests.

make_env() builds a fresh firewall around a fresh in-process MCP server, with two users
(alice=analyst, bob=admin) and every demo tool approved by bob. Time is a manual clock, so
results are deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from app.firewall.gateway import Firewall
from app.mcp.client import InProcessUpstream
from app.mcp.server import DemoToolServer, build_demo_server
from app.models.events import Decision
from app.models.policies import Policy, load_policy
from app.models.requests import GatewayResult, ToolRequest, UserSession
from app.storage.database import Database

POLICY_PATH = Path(__file__).resolve().parent.parent / "app" / "config" / "policies.yaml"
KEYS = {"alice": "alice-api-key-0123456789", "bob": "bob-api-key-0123456789ab"}
ROLES = {"alice": "analyst", "bob": "admin"}


class ManualClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class AttackEnv:
    firewall: Firewall
    server: DemoToolServer
    clock: ManualClock
    db: Database
    session_ids: dict[str, str] = field(default_factory=dict)
    sessions: dict[str, UserSession] = field(default_factory=dict)

    def login(self, who: str) -> str:
        sid, session = self.firewall.login(who, KEYS[who], client_key=f"test-{who}")
        self.session_ids[who] = sid
        self.sessions[who] = session
        return sid

    async def call(
        self, who: str, tool: str, arguments: dict[str, Any] | None = None, *, session_id: str | None = None
    ) -> GatewayResult:
        sid = session_id if session_id is not None else self.session_ids[who]
        return await self.firewall.handle(ToolRequest(session_id=sid, tool=tool, arguments=arguments or {}))


async def make_env(policy: Policy | None = None, *, approve: bool = True) -> AttackEnv:
    policy = policy or load_policy(POLICY_PATH)
    clock = ManualClock()
    db = Database(":memory:")
    server = build_demo_server()
    fw = Firewall(policy, db, InProcessUpstream(server), clock=clock, monotonic=clock)
    for user, role in ROLES.items():
        if role in policy.roles:
            fw.auth.register_user(user, role, KEYS[user])
    env = AttackEnv(firewall=fw, server=server, clock=clock, db=db)
    for user, role in ROLES.items():
        if role in policy.roles:
            env.login(user)
    if approve:
        await fw.approve_tools(env.sessions["bob"])
    return env


# --------------------------------------------------------------------------------------------
@dataclass
class AttackResult:
    blocked: bool
    detail: str


@dataclass(frozen=True)
class Attack:
    name: str
    description: str
    run: Callable[[AttackEnv], Awaitable[AttackResult]]


def denied(result: GatewayResult) -> bool:
    return result.decision is Decision.DENY

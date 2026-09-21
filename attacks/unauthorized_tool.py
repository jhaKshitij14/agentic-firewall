"""Attack: a low-privilege agent calls a tool its role does not have."""
from attacks.harness import Attack, AttackEnv, AttackResult, denied


async def run(env: AttackEnv) -> AttackResult:
    r = await env.call("alice", "execute_trade", {"symbol": "RELIANCE", "quantity": 10})
    reached = env.server.calls_to("execute_trade")
    ok = denied(r) and reached == 0
    return AttackResult(ok, f"analyst -> execute_trade: {r.decision.value} at {r.stage}; upstream calls={reached}")


ATTACKS = [Attack("Unauthorized tool call", "analyst calls admin-only execute_trade", run)]

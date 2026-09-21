"""Attack: hammer the gateway with valid calls to exhaust the upstream."""
from attacks.harness import Attack, AttackEnv, AttackResult


async def run(env: AttackEnv) -> AttackResult:
    limit = env.firewall.policy.rate_limit.max_requests
    total = limit + 50
    allowed = 0
    for _ in range(total):
        r = await env.call("alice", "get_stock_price", {"symbol": "TCS"})
        allowed += r.allowed
    reached = env.server.calls_to("get_stock_price")
    ok = allowed <= limit and reached <= limit
    return AttackResult(ok, f"{allowed}/{total} requests allowed (limit {limit}); upstream calls={reached}")


ATTACKS = [Attack("Rate-limit abuse", "burst of valid requests above the per-minute limit", run)]

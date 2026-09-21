"""Attack: an authenticated analyst tries to become someone more powerful."""
from attacks.harness import Attack, AttackEnv, AttackResult, denied


async def run(env: AttackEnv) -> AttackResult:
    attempts: list[tuple[str, bool]] = []

    # 1. Forged / guessed session ids
    for forged in ("admin", "bob", "' OR '1'='1", "A" * 43, ""):
        r = await env.call("alice", "delete_file", {"path": "x"}, session_id=forged)
        attempts.append((f"forged session {forged[:12]!r}", denied(r)))

    # 2. Smuggle a role / stolen session id inside the arguments of an admin-only tool
    r = await env.call("alice", "delete_file", {"path": "x", "role": "admin", "session_id": env.session_ids["bob"]})
    attempts.append(("role smuggled in arguments", denied(r)))

    # 3. Tool-name tricks: case change, trailing space, path-like name, null byte
    for name in ("Execute_Trade", "execute_trade ", "../execute_trade", "execute_trade\x00"):
        r = await env.call("alice", name, {"symbol": "TCS", "quantity": 1})
        attempts.append((f"tool name {name!r}", denied(r)))

    # 4. A CRITICAL tool that nobody's role includes, even the admin's
    r = await env.call("bob", "execute_command", {"command": "id"})
    attempts.append(("admin -> execute_command (CRITICAL)", denied(r)))

    # 5. Expired session
    env.clock.advance(env.firewall.policy.session_ttl_seconds + 1)
    r = await env.call("bob", "get_stock_price", {"symbol": "TCS"})
    attempts.append(("expired session", denied(r)))

    reached = env.server.calls_to("delete_file") + env.server.calls_to("execute_trade") + env.server.calls_to("execute_command")
    passed = [n for n, ok in attempts if not ok]
    ok = not passed and reached == 0
    return AttackResult(ok, f"{len(attempts) - len(passed)}/{len(attempts)} attempts denied; sensitive upstream calls={reached}")


ATTACKS = [Attack("Privilege escalation", "forged/expired sessions, smuggled roles, tool-name tricks", run)]

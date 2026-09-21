import asyncio

import pytest

from attacks import ALL_ATTACKS
from attacks.benign import run_controls
from attacks.harness import make_env


@pytest.mark.parametrize("attack", ALL_ATTACKS, ids=lambda a: a.name)
def test_attack_is_blocked(attack):
    async def go():
        return await attack.run(await make_env())

    result = asyncio.run(go())
    assert result.blocked, result.detail


def test_benign_controls_are_allowed():
    async def go():
        return await run_controls(await make_env())

    for benign, ok, detail in asyncio.run(go()):
        assert ok, f"false positive on {benign.label}: {detail}"


def test_harness_detects_a_broken_firewall():
    """Sanity check on the benchmark itself: with authorization gutted, attacks must NOT all pass."""
    from app.firewall.authorization import AuthzDecision
    from attacks.unauthorized_tool import ATTACKS

    async def go():
        env = await make_env()
        env.firewall.authz.check = lambda *a, **k: AuthzDecision(True, "oops")
        return await ATTACKS[0].run(env)

    assert asyncio.run(go()).blocked is False

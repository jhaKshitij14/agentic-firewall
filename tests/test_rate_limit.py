import pytest

from app.firewall.circuit_breaker import BreakerState, CircuitBreaker
from app.firewall.rate_limiter import SlidingWindowRateLimiter
from app.models.requests import ToolResponse
from attacks.harness import ManualClock


# ---- rate limiter unit ---------------------------------------------------------------------
def test_limiter_blocks_over_limit_and_recovers():
    clock = ManualClock()
    rl = SlidingWindowRateLimiter(3, 60, clock=clock)
    assert all(rl.check("u").allowed for _ in range(3))
    r = rl.check("u")
    assert not r.allowed and 0 < r.retry_after <= 60
    clock.advance(30)
    assert not rl.check("u").allowed
    clock.advance(30.1)
    assert rl.check("u").allowed


def test_limiter_is_per_key():
    rl = SlidingWindowRateLimiter(1, 60, clock=ManualClock())
    assert rl.check("a").allowed and rl.check("b").allowed
    assert not rl.check("a").allowed


def test_rejected_requests_do_not_extend_lockout():
    clock = ManualClock()
    rl = SlidingWindowRateLimiter(2, 60, clock=clock)
    rl.check("u"); rl.check("u")
    for _ in range(100):
        assert not rl.check("u").allowed
        clock.advance(0.5)  # hammering for 50s
    clock.advance(10.1)
    assert rl.check("u").allowed  # first two hits expired at t=60 regardless of hammering


def test_limiter_rejects_bad_config():
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(0, 60)
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(1, 0)


def test_limiter_sweeps_stale_keys():
    clock = ManualClock()
    rl = SlidingWindowRateLimiter(1, 1, clock=clock)
    rl._SWEEP_THRESHOLD = 10
    for i in range(20):
        rl.check(f"k{i}")
    clock.advance(5)
    rl.check("fresh")
    assert len(rl._hits) < 20


# ---- rate limit through the gateway --------------------------------------------------------
def test_gateway_rate_limit_end_to_end(env, run):
    limit = env.firewall.policy.rate_limit.max_requests
    results = [run(env.call("alice", "get_stock_price", {"symbol": "TCS"})) for _ in range(limit + 1)]
    assert all(r.allowed for r in results[:limit])
    last = results[-1]
    assert not last.allowed and last.stage == "rate_limit" and last.retry_after > 0
    assert env.server.calls_to("get_stock_price") == limit
    env.clock.advance(env.firewall.policy.rate_limit.window_seconds + 1)
    assert run(env.call("alice", "get_stock_price", {"symbol": "TCS"})).allowed


def test_rate_limit_is_per_user_and_counts_denied_requests(env, run):
    limit = env.firewall.policy.rate_limit.max_requests
    for _ in range(limit):
        run(env.call("alice", "execute_trade", {}))  # all denied by authorization, still counted
    assert run(env.call("alice", "search_news", {"query": "x"})).stage == "rate_limit"
    assert run(env.call("bob", "search_news", {"query": "x"})).allowed  # bob unaffected


def test_login_rate_limit(env):
    from app.firewall.authentication import AuthError
    from app.firewall.rate_limiter import RateLimitExceeded

    limit = env.firewall.policy.login_rate_limit.max_requests
    for _ in range(limit):
        with pytest.raises(AuthError):
            env.firewall.login("alice", "wrong-key-0123456789", client_key="1.2.3.4")
    with pytest.raises(RateLimitExceeded):
        env.firewall.login("alice", "alice-api-key-0123456789", client_key="1.2.3.4")  # even the right key
    env.firewall.login("alice", "alice-api-key-0123456789", client_key="5.6.7.8")  # other client fine


# ---- circuit breaker unit ------------------------------------------------------------------
def test_breaker_state_machine():
    clock = ManualClock()
    cb = CircuitBreaker(3, 30, clock=clock)
    assert cb.state is BreakerState.CLOSED
    for _ in range(3):
        assert cb.allow()
        cb.record_failure()
    assert cb.state is BreakerState.OPEN and not cb.allow()
    assert 0 < cb.retry_after() <= 30
    clock.advance(30)
    assert cb.allow() and cb.state is BreakerState.HALF_OPEN
    assert not cb.allow()  # only one probe at a time
    cb.record_failure()  # failed probe re-opens
    assert cb.state is BreakerState.OPEN and not cb.allow()
    clock.advance(30)
    assert cb.allow()
    cb.record_success()
    assert cb.state is BreakerState.CLOSED and cb.allow()


def test_breaker_counts_only_consecutive_failures():
    cb = CircuitBreaker(3, 30, clock=ManualClock())
    for _ in range(10):
        cb.record_failure(); cb.record_failure(); cb.record_success()
    assert cb.state is BreakerState.CLOSED


# ---- circuit breaker through the gateway ---------------------------------------------------
def _flaky(env, fail):
    def handler(symbol=""):
        if fail["on"]:
            raise RuntimeError("boom")
        return "fine"
    env.server.set_handler("get_stock_price", handler)


def test_gateway_circuit_opens_probes_and_closes(env, run):
    fail = {"on": True}
    _flaky(env, fail)
    threshold = env.firewall.policy.circuit_breaker.failure_threshold
    for _ in range(threshold):
        r = run(env.call("alice", "get_stock_price", {"symbol": "TCS"}))
        assert r.allowed and r.response.is_error  # tool error passes through, but counts as a failure
    calls = env.server.calls_to("get_stock_price")
    r = run(env.call("alice", "get_stock_price", {"symbol": "TCS"}))
    assert not r.allowed and r.stage == "circuit_breaker" and r.retry_after > 0
    assert env.server.calls_to("get_stock_price") == calls  # upstream not touched while open
    assert run(env.call("alice", "search_news", {"query": "x"})).allowed  # other tools unaffected
    env.clock.advance(env.firewall.policy.circuit_breaker.cooldown_seconds + 1)
    fail["on"] = False
    r = run(env.call("alice", "get_stock_price", {"symbol": "TCS"}))
    assert r.allowed and not r.response.is_error
    assert run(env.call("alice", "get_stock_price", {"symbol": "TCS"})).allowed  # closed again


def test_upstream_exception_counts_as_failure_and_is_denied(env, run):
    class Broken:
        async def start(self): ...
        async def stop(self): ...
        async def list_tools(self):
            return await env.server.list_tools()
        async def call_tool(self, name, arguments):
            raise ConnectionError("upstream down: secret internal detail")

    env.firewall.upstream = Broken()
    r = run(env.call("alice", "get_stock_price", {"symbol": "TCS"}))
    assert not r.allowed and r.stage == "upstream"
    assert "secret internal detail" not in r.reason  # no internals leaked to the caller


def test_upstream_timeout_is_denied_and_recorded(env, run):
    import asyncio

    class Slow:
        async def start(self): ...
        async def stop(self): ...
        async def list_tools(self):
            return await env.server.list_tools()
        async def call_tool(self, name, arguments):
            await asyncio.sleep(5)
            return ToolResponse(text="late")

    env.firewall.policy.upstream_timeout_seconds = 0.05
    env.firewall.upstream = Slow()
    r = run(env.call("alice", "get_stock_price", {"symbol": "TCS"}))
    assert not r.allowed and r.stage == "upstream"

"""Per-tool circuit breaker: stop hammering a tool that keeps failing.

CLOSED --(N consecutive failures)--> OPEN --(cooldown elapsed)--> HALF_OPEN
HALF_OPEN lets exactly one probe through: success -> CLOSED, failure -> OPEN again.

Contract: every allow() that returns True MUST be followed by record_success() or
record_failure(), otherwise a HALF_OPEN breaker waits forever for its probe result.
"""
from __future__ import annotations

import enum
import threading
import time
from typing import Callable


class BreakerState(str, enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1 or cooldown_seconds <= 0:
            raise ValueError("failure_threshold must be >= 1 and cooldown_seconds > 0")
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._state

    def allow(self) -> bool:
        with self._lock:
            if self._state is BreakerState.CLOSED:
                return True
            if self._state is BreakerState.OPEN:
                if self._clock() - self._opened_at >= self._cooldown:
                    self._state = BreakerState.HALF_OPEN
                    self._probe_in_flight = True
                    return True
                return False
            # HALF_OPEN: one probe at a time
            if not self._probe_in_flight:
                self._probe_in_flight = True
                return True
            return False

    def retry_after(self) -> float:
        with self._lock:
            if self._state is BreakerState.OPEN:
                return max(self._opened_at + self._cooldown - self._clock(), 0.0)
            return 0.0

    def record_success(self) -> None:
        with self._lock:
            self._state = BreakerState.CLOSED
            self._failures = 0
            self._probe_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            if self._state is BreakerState.HALF_OPEN:
                self._trip()
                return
            self._failures += 1
            if self._failures >= self._threshold:
                self._trip()

    def _trip(self) -> None:
        self._state = BreakerState.OPEN
        self._opened_at = self._clock()
        self._probe_in_flight = False
        self._failures = 0


class CircuitBreakerRegistry:
    def __init__(
        self,
        failure_threshold: int,
        cooldown_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> CircuitBreaker:
        with self._lock:
            breaker = self._breakers.get(key)
            if breaker is None:
                breaker = CircuitBreaker(self._threshold, self._cooldown, clock=self._clock)
                self._breakers[key] = breaker
            return breaker

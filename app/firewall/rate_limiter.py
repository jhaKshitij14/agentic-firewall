"""Sliding-window rate limiter (in-memory, single process). No Redis."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: float) -> None:
        super().__init__(f"rate limit exceeded; retry in {retry_after:.0f}s")
        self.retry_after = retry_after


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: float = 0.0


class SlidingWindowRateLimiter:
    """At most `max_requests` per `window_seconds` per key.

    Rejected requests are not recorded, so an attacker who keeps hammering does not extend
    their own lockout beyond the window, and legit traffic recovers as soon as old hits expire.
    """

    _SWEEP_THRESHOLD = 10_000

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_requests < 1 or window_seconds <= 0:
            raise ValueError("max_requests must be >= 1 and window_seconds > 0")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._hits: dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> RateLimitResult:
        with self._lock:
            now = self._clock()
            cutoff = now - self.window_seconds
            if len(self._hits) > self._SWEEP_THRESHOLD:
                self._sweep(cutoff)
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.max_requests:
                return RateLimitResult(False, max(hits[0] + self.window_seconds - now, 0.0))
            hits.append(now)
            return RateLimitResult(True)

    def _sweep(self, cutoff: float) -> None:
        stale = [k for k, d in self._hits.items() if not d or d[-1] <= cutoff]
        for k in stale:
            del self._hits[k]

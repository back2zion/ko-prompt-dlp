"""Thread-safe, in-memory rate limiting and per-day quota.

Pure standard-library: no FastAPI import, so the core class is directly
unit-testable. Keyed by an opaque client id (API principal name or client IP).
Two independent limits are enforced per key:

- rate (burst): a token bucket holding at most ``per_sec`` tokens that refills at
  ``per_sec`` tokens/second. This absorbs short bursts while holding the steady
  state to ``per_sec`` requests per second.
- quota: a fixed 24h window of at most ``per_day`` requests per key.

Either limit set to ``0`` (or less) means *unlimited* for that dimension. A
request is allowed only when both limits permit it; a denied request is NOT
counted against the daily quota. The limiter reports a ``Retry-After`` hint in
seconds for the limit that tripped.

The clock is injectable (``clock``) so tests can advance time deterministically;
it defaults to ``time.monotonic``.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

DAY_SECONDS = 86400.0


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: float = 0.0   # seconds until the request would be allowed
    reason: str = ""           # "rate" | "quota" | ""


class _Bucket:
    __slots__ = ("tokens", "updated", "day_count", "day_start")

    def __init__(self, tokens: float, now: float) -> None:
        self.tokens = tokens
        self.updated = now
        self.day_count = 0
        self.day_start = now


class RateLimiter:
    """Token-bucket rate limiter with a fixed-window daily quota, per key."""

    def __init__(self, per_sec: float = 0.0, per_day: int = 0,
                 clock: Callable[[], float] | None = None) -> None:
        self.per_sec = float(per_sec)
        self.per_day = int(per_day)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    @property
    def enabled(self) -> bool:
        return self.per_sec > 0 or self.per_day > 0

    def check(self, key: str) -> Decision:
        """Account for one request from ``key`` and decide whether it is allowed.

        Atomic per call: the burst token and the quota slot are consumed together,
        and only when both limits pass.
        """
        if self.per_sec <= 0 and self.per_day <= 0:
            return Decision(True)
        now = self._clock()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(self.per_sec if self.per_sec > 0 else 0.0, now)
                self._buckets[key] = b

            # --- per-day quota (fixed window), checked before consuming a token ---
            if self.per_day > 0:
                if now - b.day_start >= DAY_SECONDS:
                    b.day_start = now
                    b.day_count = 0
                if b.day_count >= self.per_day:
                    return Decision(False, max(0.0, DAY_SECONDS - (now - b.day_start)), "quota")

            # --- per-second token bucket ---
            if self.per_sec > 0:
                elapsed = now - b.updated
                if elapsed > 0:
                    b.tokens = min(self.per_sec, b.tokens + elapsed * self.per_sec)
                    b.updated = now
                if b.tokens < 1.0:
                    need = (1.0 - b.tokens) / self.per_sec
                    return Decision(False, need, "rate")
                b.tokens -= 1.0

            # both limits passed -> count the request against the daily quota
            if self.per_day > 0:
                b.day_count += 1
            return Decision(True)

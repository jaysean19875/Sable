"""Async token-bucket rate limiting, one bucket per host.

Every outbound request passes through here.  This is the mechanism behind the
"per-host rate limits" claim in the scope notice: no adapter can bypass it
because adapters never touch httpx directly.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from .config import RateLimitConfig


class TokenBucket:
    """Classic token bucket; ``capacity`` is the burst size."""

    def __init__(self, rate: float, capacity: int) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = float(max(1, capacity))
        self._tokens = float(self.capacity)
        self._stamp = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._stamp
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._stamp = now

    async def acquire(self, tokens: float = 1.0) -> None:
        if tokens > self.capacity:
            raise ValueError(f"requested {tokens} tokens from a bucket of {self.capacity}")
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                needed = (tokens - self._tokens) / self.rate
            await asyncio.sleep(min(needed, 5.0))


class RateLimiter:
    """Per-host buckets with a conservative default."""

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        self._config = config or RateLimitConfig()
        self._buckets: dict[str, TokenBucket] = {}

    def bucket_for(self, host: str) -> TokenBucket:
        host = host.lower()
        bucket = self._buckets.get(host)
        if bucket is None:
            rate = self._config.per_host.get(host, self._config.default_rps)
            bucket = TokenBucket(rate=rate, capacity=self._config.burst)
            self._buckets[host] = bucket
        return bucket

    @staticmethod
    def host_of(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()

    async def acquire(self, url: str) -> None:
        host = self.host_of(url)
        if host:
            await self.bucket_for(host).acquire()

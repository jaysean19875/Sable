"""Rate limiting: bursts, sustained rate, per-host isolation."""

from __future__ import annotations

import asyncio
import time

import pytest

from projectosint.config import RateLimitConfig
from projectosint.ratelimit import RateLimiter, TokenBucket


async def test_burst_then_throttle() -> None:
    bucket = TokenBucket(rate=100.0, capacity=1)
    started = time.perf_counter()
    await bucket.acquire()  # capacity 1: immediate
    first = time.perf_counter() - started
    await bucket.acquire()  # must wait for ~10ms of refill
    second = time.perf_counter() - started
    assert first < 0.01
    assert second >= 0.005


async def test_invalid_bucket() -> None:
    with pytest.raises(ValueError):
        TokenBucket(rate=0, capacity=1)
    bucket = TokenBucket(rate=10, capacity=1)
    with pytest.raises(ValueError):
        await bucket.acquire(tokens=2)


async def test_per_host_override() -> None:
    limiter = RateLimiter(RateLimitConfig(default_rps=1.0, burst=2, per_host={"example.com": 50.0}))
    fast = limiter.bucket_for("example.com")
    slow = limiter.bucket_for("other.example")
    assert fast.rate == 50.0
    assert slow.rate == 1.0
    assert limiter.bucket_for("EXAMPLE.com") is fast


async def test_acquire_by_url() -> None:
    limiter = RateLimiter(RateLimitConfig(default_rps=50.0, burst=10))
    started = time.perf_counter()
    await asyncio.gather(*(limiter.acquire("https://a.example/x") for _ in range(5)))
    assert time.perf_counter() - started < 0.5

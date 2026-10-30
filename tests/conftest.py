"""Shared pytest fixtures.  Every test is offline: no real network calls."""

from __future__ import annotations

from pathlib import Path

import pytest

import projectosint.collectors  # noqa: F401  (populates the registry)
from projectosint.base import BaseCollector, CollectorContext
from projectosint.config import RateLimitConfig, Settings
from projectosint.http import OsintClient
from projectosint.models import Target
from projectosint.targets import parse_target


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database=str(tmp_path / "data" / "osint.db"),
        cache_ttl_s=0,
        deadline_s=5.0,
        source_timeout_s=2.0,
        rate_limit=RateLimitConfig(default_rps=50.0, burst=50),
        retries=0,
        log_json=False,
    )


@pytest.fixture
def domain_target() -> Target:
    return parse_target("example.com")


@pytest.fixture
async def context(settings: Settings, domain_target: Target):
    async with OsintClient(settings) as client:
        yield CollectorContext(settings=settings, client=client, target=domain_target, scan_id="testscan")


def collect(collector: BaseCollector):
    return collector.collect()

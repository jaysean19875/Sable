"""Engine behaviour: isolation, timeouts, deadlines, caching, dedupe.

The collectors here are synthetic, so these tests prove the orchestration
semantics without touching the network.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from projectosint import scheduler as scheduler_mod
from projectosint.base import BaseCollector
from projectosint.cache import ResultCache
from projectosint.config import Settings
from projectosint.models import Category, Status, TargetKind
from projectosint.registry import CollectorSpec
from projectosint.scheduler import ScanEngine


def make_collector(
    name: str,
    *,
    delay: float = 0.0,
    fail: bool = False,
    count: int = 1,
    duplicate: bool = False,
):
    collector_spec = CollectorSpec(
        name=name,
        category=Category.DNS,
        description="synthetic collector",
        target_kinds=frozenset({TargetKind.DOMAIN}),
    )

    class _Fake(BaseCollector):
        spec = collector_spec

        async def collect(self):
            if delay:
                await asyncio.sleep(delay)
            if fail:
                raise RuntimeError("synthetic failure")
            modulus = 1 if duplicate else count
            return [
                self.finding("test.kind", f"{name}-{index % modulus}") for index in range(count)
            ]

    _Fake.__name__ = f"Fake_{name}"
    return _Fake


@pytest.fixture
def patch_select(monkeypatch: pytest.MonkeyPatch):
    def _patch(*classes):
        monkeypatch.setattr(scheduler_mod.registry, "select", lambda **_: list(classes))

    return _patch


async def test_scan_happy_path(patch_select, settings: Settings) -> None:
    patch_select(make_collector("fast_a", count=2), make_collector("fast_b"))
    report = await ScanEngine(settings).scan("example.com")
    assert report.stats.by_status == {"ok": 2}
    assert report.stats.total_findings == 3
    assert {r.source for r in report.results} == {"fast_a", "fast_b"}
    assert report.duration_ms >= 0
    assert report.finished_at is not None


async def test_failing_source_is_isolated(patch_select, settings: Settings) -> None:
    patch_select(make_collector("good"), make_collector("bad", fail=True))
    report = await ScanEngine(settings).scan("example.com")
    statuses = {r.source: r.status for r in report.results}
    assert statuses == {"good": Status.OK, "bad": Status.ERROR}
    bad = next(r for r in report.results if r.source == "bad")
    assert "synthetic failure" in (bad.error or "")


async def test_per_source_timeout_degrades(patch_select, settings: Settings) -> None:
    patch_select(make_collector("slow", delay=0.5), make_collector("quick"))
    settings.source_timeout_s = 0.05
    report = await ScanEngine(settings).scan("example.com", deadline_s=2.0)
    statuses = {r.source: r.status for r in report.results}
    assert statuses["quick"] is Status.OK
    assert statuses["slow"] is Status.TIMEOUT


async def test_global_deadline_keeps_partial_results(patch_select, settings: Settings) -> None:
    patch_select(make_collector("fast"), make_collector("slow", delay=5.0))
    report = await ScanEngine(settings).scan("example.com", deadline_s=0.15)
    statuses = {r.source: r.status for r in report.results}
    assert statuses["fast"] is Status.OK
    assert statuses["slow"] is Status.TIMEOUT
    assert any("deadline" in note for note in report.notes)
    assert report.stats.total_findings == 1


async def test_cache_roundtrip_preserves_findings(patch_select, settings: Settings, tmp_path: Path) -> None:
    patch_select(make_collector("cached_source", count=2))
    async with ResultCache(tmp_path / "cache.db", ttl_s=3600) as cache:
        engine = ScanEngine(settings, cache=cache)
        first = await engine.scan("example.com")
        second = await engine.scan("example.com")
    assert first.results[0].status is Status.OK
    assert second.results[0].status is Status.CACHED
    assert second.results[0].from_cache is True
    assert [f.value for f in second.findings] == [f.value for f in first.findings]


async def test_cache_bypassed_when_disabled(patch_select, settings: Settings, tmp_path: Path) -> None:
    patch_select(make_collector("cached_source"))
    async with ResultCache(tmp_path / "cache.db", ttl_s=3600) as cache:
        engine = ScanEngine(settings, cache=cache)
        await engine.scan("example.com")
        second = await engine.scan("example.com", use_cache=False)
    assert second.results[0].status is Status.OK


async def test_duplicate_findings_collapse(patch_select, settings: Settings) -> None:
    patch_select(make_collector("dupes", count=3, duplicate=True))
    report = await ScanEngine(settings).scan("example.com")
    assert report.stats.total_findings == 1


async def test_unknown_source_is_rejected(settings: Settings) -> None:
    with pytest.raises(KeyError, match="unknown collector"):
        await ScanEngine(settings).scan("example.com", sources=["does_not_exist"])


async def test_events_are_emitted(patch_select, settings: Settings) -> None:
    patch_select(make_collector("evented"))
    seen: list[str] = []
    engine = ScanEngine(settings, on_event=lambda event, _payload: seen.append(event))
    await engine.scan("example.com")
    assert seen[0] == "scan_start"
    assert "source_done" in seen
    assert seen[-1] == "scan_done"


async def test_broken_callback_does_not_kill_scan(patch_select, settings: Settings) -> None:
    patch_select(make_collector("evented"))

    def boom(_event: str, _payload: dict) -> None:
        raise RuntimeError("ui broke")

    report = await ScanEngine(settings, on_event=boom).scan("example.com")
    assert report.stats.by_status == {"ok": 1}

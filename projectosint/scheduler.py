"""Scan orchestration.

Design constraints taken literally from the spec:

* collectors run concurrently under an ``asyncio.TaskGroup``;
* each source has its own timeout, and the *scan* has a global deadline;
* a slow or failing source degrades to ``partial``/``timeout`` instead of
  blocking the run or discarding completed work;
* successful results are cached by target so repeat scans are instant.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable, Iterable
from typing import Any

from . import registry
from .base import BaseCollector, CollectorContext
from .cache import ResultCache
from .config import Settings
from .http import OsintClient
from .logging_setup import get_logger
from .models import (
    Category,
    CollectorResult,
    ScanReport,
    ScanRequest,
    Status,
    Target,
    utcnow,
)
from .pipeline import normalise
from .ratelimit import RateLimiter
from .targets import parse_target

EventCallback = Callable[[str, dict[str, Any]], None]
_CACHEABLE = frozenset({Status.OK, Status.PARTIAL})


class ScanEngine:
    def __init__(
        self,
        settings: Settings,
        *,
        cache: ResultCache | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        self.settings = settings
        self.cache = cache
        self.on_event = on_event
        self.log = get_logger("engine")

    # ------------------------------------------------------------------
    async def scan(
        self,
        subject: str | Target | ScanRequest,
        *,
        deadline_s: float | None = None,
        sources: Iterable[str] | None = None,
        categories: Iterable[Category] | None = None,
        use_cache: bool | None = None,
        scan_id: str | None = None,
    ) -> ScanReport:
        request = self._build_request(subject, deadline_s, sources, categories, use_cache)
        target = request.target
        classes = registry.select(
            kinds={target.kind},
            categories=request.categories,
            sources=list(request.sources) if request.sources else None,
            disabled=self.settings.disabled_sources,
        )

        report = ScanReport(
            scan_id=scan_id or uuid.uuid4().hex[:12],
            target=target,
            deadline_s=request.deadline_s,
            started_at=utcnow(),
            notes=[],
        )
        if not classes:
            report.notes.append("no collectors matched the target kind and filters")
            return report.finalise()

        self._emit(
            "scan_start",
            {
                "scan_id": report.scan_id,
                "target": target.label,
                "sources": [cls.spec.name for cls in classes],
                "deadline_s": request.deadline_s,
            },
        )

        collected: dict[str, CollectorResult] = {}
        per_source_timeout = min(self.settings.source_timeout_s, request.deadline_s)
        limiter = RateLimiter(self.settings.rate_limit)

        async with OsintClient(self.settings, limiter) as client:

            async def run(cls: type[Any]) -> None:
                collected[cls.spec.name] = await self._run_one(
                    cls, client, target, report.scan_id, request, per_source_timeout
                )

            timed_out = False
            try:
                async with asyncio.timeout(request.deadline_s):
                    async with asyncio.TaskGroup() as group:
                        for cls in classes:
                            group.create_task(run(cls), name=cls.spec.name)
            except TimeoutError:
                timed_out = True
                report.notes.append(
                    f"global deadline of {request.deadline_s:g}s reached; "
                    "unfinished sources were cancelled and are reported as timeout"
                )

        for cls in classes:
            spec = cls.spec
            result = collected.get(spec.name)
            if result is None:
                result = CollectorResult(
                    source=spec.name,
                    category=spec.category,
                    status=Status.TIMEOUT,
                    error="global deadline exceeded" if timed_out else "not run",
                    note="cancelled at deadline",
                )
            report.results.append(result)

        normalise(report, per_source_limit=self.settings.max_findings_per_source)
        report.finalise()
        self._emit(
            "scan_done",
            {
                "scan_id": report.scan_id,
                "target": target.label,
                "duration_ms": report.duration_ms,
                "findings": report.stats.total_findings,
                "sources": report.stats.by_status,
            },
        )
        self.log.info(
            "scan {id} {target}: {n} findings in {ms}ms",
            id=report.scan_id,
            target=target.label,
            n=report.stats.total_findings,
            ms=report.duration_ms,
        )
        return report

    # ------------------------------------------------------------------
    async def _run_one(
        self,
        cls: type[Any],
        client: OsintClient,
        target: Target,
        scan_id: str,
        request: ScanRequest,
        timeout: float,
    ) -> CollectorResult:
        spec = cls.spec
        self._emit("source_start", {"source": spec.name, "category": spec.category.value})

        missing = registry.requirements_missing(spec, self.settings.api_keys)
        if missing:
            result = CollectorResult(
                source=spec.name,
                category=spec.category,
                status=Status.SKIPPED,
                note=f"missing API key '{missing}' (set OSINT_API_KEYS__{missing.upper()})",
            )
            self._emit(
                "source_done",
                result.model_dump(mode="json", exclude={"findings"}) | {"count": 0},
            )
            return result

        cache_key = ResultCache.make_key(target.label, spec.name)
        if self.cache is not None and request.use_cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                result = cached.model_copy(update={"status": Status.CACHED, "from_cache": True})
                self._emit(
                    "source_done",
                    result.model_dump(mode="json", exclude={"findings"}) | {"count": result.count},
                )
                return result

        ctx = CollectorContext(settings=self.settings, client=client, target=target, scan_id=scan_id)
        collector: BaseCollector = cls(ctx)
        started = time.perf_counter()
        try:
            async with asyncio.timeout(timeout):
                findings = await collector.collect()
            status = Status.OK
            error = None
            note = None
        except TimeoutError:
            findings, status, error, note = [], Status.TIMEOUT, f"source timeout after {timeout:g}s", None
        except Exception as exc:  # adapter failed; siblings must survive
            findings, status = [], Status.ERROR
            error = f"{type(exc).__name__}: {exc}"
            note = None
            self.log.warning("source {s} failed: {e}", s=spec.name, e=error)

        result = CollectorResult(
            source=spec.name,
            category=spec.category,
            status=status,
            findings=findings,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
            http_calls=ctx.calls,
            error=error,
            note=note,
        )
        if self.cache is not None and request.use_cache and status in _CACHEABLE:
            await self.cache.put(cache_key, result)
        self._emit(
            "source_done",
            result.model_dump(mode="json", exclude={"findings"})
            | {"count": result.count},
        )
        return result

    # ------------------------------------------------------------------
    def _build_request(
        self,
        subject: str | Target | ScanRequest,
        deadline_s: float | None,
        sources: Iterable[str] | None,
        categories: Iterable[Category] | None,
        use_cache: bool | None,
    ) -> ScanRequest:
        if isinstance(subject, ScanRequest):
            request = subject
            if deadline_s is not None:
                request = request.model_copy(update={"deadline_s": deadline_s})
            return request
        target = subject if isinstance(subject, Target) else parse_target(subject)
        unknown = [name for name in (sources or []) if name not in registry.names()]
        if unknown:
            raise KeyError(f"unknown collector(s): {', '.join(unknown)}")
        return ScanRequest(
            target=target,
            deadline_s=deadline_s if deadline_s is not None else self.settings.deadline_s,
            sources=list(sources) if sources is not None else None,
            categories=list(categories) if categories is not None else None,
            use_cache=True if use_cache is None else use_cache,
        )

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(event, payload)
        except Exception:  # a broken UI callback must never kill a scan
            self.log.debug("event callback failed for {e}", e=event)

"""FastAPI application: JSON API + SSE progress + the dashboard shell.

Scan execution is asynchronous by design: ``POST /api/scans`` returns an id
immediately, the browser follows ``/api/jobs/{id}/stream`` for live per-source
progress, then fetches the finished report.  This keeps a 10-second scan from
blocking a request and mirrors how the CLI drives the same engine.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__, registry
from ..cache import ResultCache
from ..config import Settings
from ..export import to_csv, to_json, write_pdf
from ..logging_setup import get_logger, setup_logging
from ..models import Category, ScanReport
from ..scheduler import ScanEngine
from ..store import Store
from ..targets import parse_target

MAX_CONCURRENT_SCANS = 3
STATIC_DIR = Path(__file__).parent / "static"


class ScanPayload(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    sources: list[str] | None = None
    categories: list[str] | None = None
    deadline_s: float | None = Field(default=None, gt=0, le=120)
    use_cache: bool = True


@dataclass
class Job:
    """A running or finished scan, with a replayable event log for SSE."""

    job_id: str
    target: str
    status: str = "running"
    report: ScanReport | None = None
    error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    subscribers: set[asyncio.Queue[dict[str, Any]]] = field(default_factory=set)

    def publish(self, event: str, data: dict[str, Any]) -> None:
        payload = {"event": event, "data": data}
        self.events.append(payload)
        for queue in list(self.subscribers):
            with suppress(asyncio.QueueFull):
                queue.put_nowait(payload)

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=512)
        for payload in self.events:
            with suppress(asyncio.QueueFull):
                queue.put_nowait(payload)
        self.subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self.subscribers.discard(queue)


class JobRegistry:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    def create(self, target: str) -> Job:
        job = Job(job_id=uuid.uuid4().hex[:12], target=target)
        self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def attach(self, job: Job, task: asyncio.Task[None]) -> None:
        self._tasks[job.job_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(job.job_id, None))

    async def shutdown(self) -> None:
        for task in list(self._tasks.values()):
            task.cancel()
        for task in list(self._tasks.values()):
            with suppress(asyncio.CancelledError, Exception):
                await task

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.events[0]["data"].get("started", 0)
                      if j.events else 0, reverse=True)
        return [
            {"scan_id": j.job_id, "target": j.target, "status": j.status,
             "findings": j.report.stats.total_findings if j.report else 0}
            for j in jobs[:limit]
        ]


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    setup_logging(cfg.log_level, json_logs=cfg.log_json, log_dir=cfg.data_dir / "logs")
    cfg.ensure_dirs()
    log = get_logger("web")
    registry_jobs = JobRegistry()
    state: dict[str, Any] = {"store": None, "cache": None}

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        store = await Store(cfg.db_path).open()
        cache = await ResultCache(cfg.data_dir / "cache.db", cfg.cache_ttl_s).open()
        state["store"] = store
        state["cache"] = cache
        log.info("dashboard ready on the configured host")
        try:
            yield
        finally:
            await registry_jobs.shutdown()
            await cache.close()
            await store.close()

    app = FastAPI(title="ProjectOSINT", version=__version__, lifespan=lifespan)

    # -- pages ---------------------------------------------------------
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "sources": len(registry.all_specs())}

    @app.get("/api/sources")
    async def sources() -> dict[str, Any]:
        specs = sorted(registry.all_specs(), key=lambda s: (s.category.value, s.name))
        return {"count": len(specs), "sources": [spec.to_public_dict() for spec in specs]}

    # -- scans ---------------------------------------------------------
    @app.post("/api/scans", status_code=202)
    async def start_scan(payload: ScanPayload) -> JSONResponse:
        try:
            target = parse_target(payload.target)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        unknown = [name for name in (payload.sources or []) if name not in registry.names()]
        if unknown:
            raise HTTPException(status_code=422, detail=f"unknown sources: {', '.join(unknown)}")
        valid_categories = {category.value for category in Category}
        bad_categories = [c for c in (payload.categories or []) if c not in valid_categories]
        if bad_categories:
            raise HTTPException(
                status_code=422, detail=f"unknown categories: {', '.join(bad_categories)}"
            )
        selected_categories = [Category(c) for c in payload.categories] if payload.categories else None
        store: Store = state["store"]
        cache: ResultCache = state["cache"]

        job = registry_jobs.create(target.label)

        async def run() -> None:
            async with registry_jobs._semaphore:
                try:
                    job.publish("job_started", {"scan_id": job.job_id, "target": target.label})
                    engine = ScanEngine(
                        cfg,
                        cache=cache,
                        on_event=lambda event, data: job.publish(event, data),
                    )
                    report = await engine.scan(
                        target,
                        scan_id=job.job_id,
                        deadline_s=payload.deadline_s,
                        sources=payload.sources,
                        categories=selected_categories,
                        use_cache=payload.use_cache,
                    )
                    job.report = report
                    job.status = "done"
                    await store.save(report)
                except asyncio.CancelledError:
                    job.status = "cancelled"
                    job.publish("job_error", {"error": "cancelled"})
                    raise
                except Exception as exc:  # surfaced to the UI, never swallowed
                    job.status = "error"
                    job.error = f"{type(exc).__name__}: {exc}"
                    job.publish("job_error", {"error": job.error})
                    log.exception("scan {id} failed", id=job.job_id)

        registry_jobs.attach(job, asyncio.create_task(run()))
        return JSONResponse(
            {"scan_id": job.job_id, "target": target.label, "stream": f"/api/jobs/{job.job_id}/stream"},
            status_code=202,
        )

    @app.get("/api/jobs/{job_id}/stream")
    async def stream(job_id: str) -> StreamingResponse:
        job = registry_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")

        async def generator() -> AsyncIterator[bytes]:
            queue = job.subscribe()
            try:
                while True:
                    try:
                        payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except TimeoutError:
                        yield b": keepalive\n\n"
                        continue
                    body = json.dumps(payload["data"], separators=(",", ":"))
                    yield f"event: {payload['event']}\ndata: {body}\n\n".encode()
                    if payload["event"] in {"scan_done", "job_error"}:
                        break
            finally:
                job.unsubscribe(queue)

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                     "Connection": "keep-alive"},
        )

    @app.get("/api/scans")
    async def list_scans(limit: int = Query(25, ge=1, le=200)) -> dict[str, Any]:
        store: Store = state["store"]
        stored = await store.list_scans(limit=limit)
        return {"scans": stored, "live": registry_jobs.recent(limit)}

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        job = registry_jobs.get(scan_id)
        if job is not None and job.report is not None:
            return job.report.model_dump(mode="json")
        store: Store = state["store"]
        report = await store.get(scan_id)
        if report is None:
            if job is not None:
                raise HTTPException(status_code=409, detail=f"scan still {job.status}")
            raise HTTPException(status_code=404, detail="unknown scan")
        return report.model_dump(mode="json")

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(
        scan_id: str,
        severity: str | None = None,
        source: str | None = None,
        category: str | None = None,
        q: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
    ) -> dict[str, Any]:
        store: Store = state["store"]
        rows = await store.findings(
            scan_id, severity=severity, source=source, category=category, query=q, limit=limit
        )
        return {"count": len(rows), "findings": rows}

    @app.get("/api/scans/{scan_id}/export/{fmt}")
    async def export(scan_id: str, fmt: str) -> Any:
        job = registry_jobs.get(scan_id)
        report = job.report if job is not None else None
        if report is None:
            store: Store = state["store"]
            report = await store.get(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="unknown scan")
        fmt = fmt.lower()
        if fmt == "json":
            return Response(
                content=to_json(report),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.json"'},
            )
        if fmt == "csv":
            return StreamingResponse(
                iter([to_csv(report)]),
                media_type="text/csv",
                headers={"Content-Disposition": f'attachment; filename="{scan_id}.csv"'},
            )
        if fmt == "pdf":
            path = cfg.data_dir / "exports" / f"{scan_id}.pdf"
            write_pdf(report, path)
            return FileResponse(path, media_type="application/pdf", filename=f"{scan_id}.pdf")
        raise HTTPException(status_code=400, detail="fmt must be json, csv or pdf")

    @app.get("/api/stats")
    async def stats() -> dict[str, Any]:
        store: Store = state["store"]
        return await store.stats()

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app


app = create_app()

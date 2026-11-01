"""Personal Data checks: breach exposure and account presence for one user.

Privacy rules this module lives by, enforced by tests:

* the password is hashed locally and only a 5-hex-character SHA-1 prefix is
  ever transmitted (HIBP k-anonymity);
* the password never appears in logs, findings, the report or any file;
* nothing is written to the shared scan store or result cache: personal
  checks are invisible from the History tab and to other users;
* the only output is a report folder next to the app (``RESULTS``), plus the
  UI display - nothing is uploaded anywhere.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from . import registry
from .base import CollectorContext
from .collectors.pwned import password_breach_count
from .config import Settings
from .http import OsintClient
from .logging_setup import get_logger
from .models import Category, Finding, Status, Target, TargetKind
from .ratelimit import RateLimiter

_PASSWORD_SOURCE = "hibp_password"

EventCallback = Callable[[str, dict[str, Any]], None]


class PersonalSourceResult(BaseModel):
    source: str
    category: str
    status: str
    detail: str = ""
    count: int = 0
    error: str | None = None
    findings: list[str] = Field(default_factory=list)


class PersonalReport(BaseModel):
    scan_id: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    emails: list[str] = Field(default_factory=list)
    username: str | None = None
    password_checked: bool = False
    password_seen_in_breaches: int | None = None
    results: list[PersonalSourceResult] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    note: str = (
        "Local only: this report was written to the RESULTS folder beside the "
        "application and was never uploaded anywhere."
    )

    @property
    def summary(self) -> dict[str, int]:
        by_status: dict[str, int] = {}
        for result in self.results:
            by_status[result.status] = by_status.get(result.status, 0) + 1
        return dict(sorted(by_status.items()))


def default_results_dir() -> Path:
    """RESULTS lives next to the app: the exe folder when frozen, else the
    project root the launcher anchored to."""
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "RESULTS"
    return Path.cwd() / "RESULTS"


def parse_emails(raw: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for part in raw.replace(";", ",").split(","):
        value = part.strip().lower()
        if value and "@" in value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


async def run_checks(
    settings: Settings,
    *,
    emails: list[str],
    username: str | None,
    password: str | None,
    deadline_s: float,
    results_dir: Path | None = None,
    on_event: EventCallback | None = None,
) -> PersonalReport:
    """Run the whole personal sweep under one deadline, then write reports."""
    log = get_logger("personal")
    report = PersonalReport(
        scan_id=uuid.uuid4().hex[:12],
        emails=emails,
        username=username or None,
        password_checked=password is not None,
    )
    directory = results_dir or default_results_dir()
    directory.mkdir(parents=True, exist_ok=True)

    targets: list[Target] = []
    for email in emails:
        try:
            targets.append(Target(kind=TargetKind.EMAIL, value=email, host=email.split("@")[-1]))
        except ValueError:
            continue
    if username:
        targets.append(Target(kind=TargetKind.USERNAME, value=username.strip().lower()))

    jobs: list[tuple[type[Any], Target, str]] = []
    for target in targets:
        classes = registry.select(kinds={target.kind}, disabled=settings.disabled_sources)
        for cls in classes:
            jobs.append((cls, target, f"{cls.spec.name} · {target.label}"))
    password_name = f"{_PASSWORD_SOURCE} · password"

    collected: dict[str, PersonalSourceResult] = {}
    per_source_timeout = min(settings.source_timeout_s, deadline_s)

    def emit(event: str, payload: dict[str, Any]) -> None:
        if on_event is not None:
            with contextlib.suppress(Exception):  # a broken UI callback must not kill the run
                on_event(event, payload)

    async with OsintClient(settings, RateLimiter(settings.rate_limit)) as client:
        async def run_source(cls: type[Any], target: Target, name: str) -> None:
            spec = cls.spec
            emit("source_start", {"source": name})
            missing = registry.requirements_missing(spec, settings.api_keys)
            if missing:
                collected[name] = PersonalSourceResult(
                    source=spec.name,
                    category=spec.category.value,
                    status=Status.SKIPPED.value,
                    detail=f"needs API key '{missing}' in .env",
                )
                emit("source_done", {"source": name, "status": "skipped", "count": 0})
                return
            context = CollectorContext(
                settings=settings, client=client, target=target, scan_id=report.scan_id
            )
            try:
                async with asyncio.timeout(per_source_timeout):
                    findings: list[Finding] = await cls(context).collect()
                result = PersonalSourceResult(
                    source=spec.name,
                    category=spec.category.value,
                    status=Status.OK.value,
                    count=len(findings),
                    findings=[
                        f"{f.kind}: {f.value}" + (f" ({f.detail})" if f.detail else "")
                        for f in findings[:25]
                    ],
                )
            except TimeoutError:
                result = PersonalSourceResult(
                    source=spec.name, category=spec.category.value,
                    status=Status.TIMEOUT.value,
                    detail=f"source timed out after {per_source_timeout:g}s",
                )
            except Exception as exc:  # a dead endpoint must not sink the sweep
                result = PersonalSourceResult(
                    source=spec.name, category=spec.category.value,
                    status=Status.ERROR.value, error=f"{type(exc).__name__}: {exc}",
                )
            collected[name] = result
            emit("source_done", {"source": name, "status": result.status,
                                 "count": result.count})

        async def run_password() -> None:
            if password is None:
                return
            emit("source_start", {"source": password_name})
            try:
                async with asyncio.timeout(per_source_timeout):
                    count = await password_breach_count(client, password)
                report.password_seen_in_breaches = count
                result = PersonalSourceResult(
                    source=_PASSWORD_SOURCE,
                    category=Category.EXPOSURE.value,
                    status=Status.OK.value,
                    count=0,
                    detail=(
                        f"password seen {count} time(s) in known breaches"
                        if count else "password not seen in known breaches"
                    ),
                )
            except TimeoutError:
                result = PersonalSourceResult(
                    source=_PASSWORD_SOURCE, category=Category.EXPOSURE.value,
                    status=Status.TIMEOUT.value, detail="password check timed out",
                )
            except Exception as exc:
                result = PersonalSourceResult(
                    source=_PASSWORD_SOURCE, category=Category.EXPOSURE.value,
                    status=Status.ERROR.value, error=f"{type(exc).__name__}: {exc}",
                )
            collected[password_name] = result
            emit("source_done", {"source": password_name, "status": result.status,
                                 "count": result.count})

        sources = [name for _, _, name in jobs] + (
            [password_name] if password is not None else []
        )
        emit("personal_start", {
            "scan_id": report.scan_id, "total": len(sources), "sources": sources,
        })
        try:
            async with asyncio.timeout(deadline_s):
                async with asyncio.TaskGroup() as group:
                    for cls, target, name in jobs:
                        group.create_task(run_source(cls, target, name), name=name)
                    if password is not None:
                        group.create_task(run_password(), name=password_name)
        except TimeoutError:
            log.info("personal check {id}: global deadline reached", id=report.scan_id)

    report.results = [
        collected.get(name) or PersonalSourceResult(
            source=cls.spec.name,
            category=cls.spec.category.value,
            status=Status.TIMEOUT.value,
            detail="global deadline reached",
        )
        for cls, _target, name in jobs
    ]
    if password is not None:
        report.results.append(
            collected.get(password_name) or PersonalSourceResult(
                source=_PASSWORD_SOURCE,
                category=Category.EXPOSURE.value,
                status=Status.TIMEOUT.value,
                detail="global deadline reached",
            )
        )
    report.results.sort(key=lambda r: (r.category, r.source))

    report.files = _write_reports(report, directory)
    emit("personal_done", {"scan_id": report.scan_id, "files": report.files,
                           "summary": report.summary})
    return report


def _write_reports(report: PersonalReport, directory: Path) -> list[str]:
    base = f"{report.scan_id}_personal"
    files: list[str] = []

    json_path = directory / f"{base}.json"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    files.append(json_path.name)

    csv_path = directory / f"{base}.csv"
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=("source", "category", "status", "count", "detail", "findings")
    )
    writer.writeheader()
    for result in report.results:
        writer.writerow(
            {
                "source": result.source,
                "category": result.category,
                "status": result.status,
                "count": result.count,
                "detail": result.detail,
                "findings": " | ".join(result.findings),
            }
        )
    csv_path.write_text(buffer.getvalue(), encoding="utf-8")
    files.append(csv_path.name)

    txt_path = directory / f"{base}.txt"
    lines = [
        f"ProjectOSINT personal data check {report.scan_id}",
        f"Checked at: {report.checked_at.isoformat()}",
        f"Emails: {', '.join(report.emails) or 'none'}",
        f"Username: {report.username or 'none'}",
        f"Password checked: {report.password_checked}",
    ]
    if report.password_seen_in_breaches is not None:
        lines.append(
            f"Password seen in breaches: {report.password_seen_in_breaches} time(s)"
        )
    lines.append("")
    for result in report.results:
        lines.append(
            f"[{result.status.upper():<8}] {result.source:<22} {result.detail or result.error or ''}"
        )
        for finding in result.findings:
            lines.append(f"         - {finding}")
    lines += ["", report.note]
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    files.append(txt_path.name)
    return files

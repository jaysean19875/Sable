"""The Personal Data orchestrator: output files, redaction, isolation."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from projectosint import personal
from projectosint.base import BaseCollector
from projectosint.models import Category, TargetKind
from projectosint.registry import CollectorSpec


def make_collector(
    name: str,
    kind: TargetKind,
    *,
    requires_key: str | None = None,
    count: int = 1,
    delay: float = 0.0,
    fail: bool = False,
):
    collector_spec = CollectorSpec(
        name=name,
        category=Category.IDENTITY,
        description="synthetic personal source",
        target_kinds=frozenset({kind}),
        requires_key=requires_key,
    )

    class _Fake(BaseCollector):
        spec = collector_spec

        async def collect(self):
            if delay:
                await asyncio.sleep(delay)
            if fail:
                raise RuntimeError("synthetic failure")
            return [self.finding("test.kind", f"{name}-{i}") for i in range(count)]

    _Fake.__name__ = f"Fake_{name}"
    return _Fake


def test_parse_emails() -> None:
    assert personal.parse_emails("a@x.com, B@X.com; a@x.com") == ["a@x.com", "b@x.com"]
    assert personal.parse_emails("not-an-email, c@x.com") == ["c@x.com"]
    assert personal.parse_emails("") == []


def test_default_results_dir_name() -> None:
    directory = personal.default_results_dir()
    assert directory.name == "RESULTS"
    assert directory.is_absolute()


async def test_run_checks_writes_reports_and_never_stores_password(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    email_source = make_collector("email_check", TargetKind.EMAIL, count=2)
    gated_source = make_collector("gated_check", TargetKind.EMAIL, requires_key="hibp")
    user_source = make_collector("user_check", TargetKind.USERNAME)

    def fake_select(*, kinds, disabled=()):
        kinds = set(kinds)
        return [cls for cls in (email_source, gated_source, user_source)
                if cls.spec.target_kinds & kinds]

    monkeypatch.setattr(personal.registry, "select", fake_select)
    monkeypatch.setattr(personal, "password_breach_count", _fake_password_count)

    events: list[tuple[str, dict]] = []
    report = await personal.run_checks(
        settings,
        emails=["analyst@example.com"],
        username="analyst",
        password="Sup3rSecret!!",
        deadline_s=5.0,
        results_dir=tmp_path,
        on_event=lambda event, payload: events.append((event, payload)),
    )

    assert report.password_checked is True
    assert report.password_seen_in_breaches == 42
    statuses = {result.source: result.status for result in report.results}
    assert statuses == {
        "email_check": "ok",
        "gated_check": "skipped",
        "user_check": "ok",
        "hibp_password": "ok",
    }
    assert len(report.files) == 3

    # the password must not exist in ANY written artefact
    for filename in report.files:
        content = (tmp_path / filename).read_text(encoding="utf-8")
        assert "Sup3rSecret" not in content
        assert "password seen 42 time(s)" in content

    assert "Sup3rSecret" not in report.model_dump_json()
    assert "Sup3rSecret" not in json.dumps(events)

    event_names = [event for event, _payload in events]
    assert event_names[0] == "personal_start"
    assert "source_done" in event_names
    assert event_names[-1] == "personal_done"


async def test_global_deadline_degrades(settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    slow = make_collector("slow_check", TargetKind.EMAIL, delay=0.6)
    monkeypatch.setattr(personal.registry, "select", lambda **_: [slow])

    report = await personal.run_checks(
        settings,
        emails=["analyst@example.com"],
        username=None,
        password=None,
        deadline_s=0.05,
        results_dir=tmp_path,
    )
    assert report.results[0].status == "timeout"
    assert "global deadline" in report.results[0].detail
    assert (tmp_path / report.files[0]).is_file()


async def test_no_password_means_no_password_row(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_collector("user_check", TargetKind.USERNAME)
    monkeypatch.setattr(personal.registry, "select", lambda **_: [source])
    report = await personal.run_checks(
        settings,
        emails=[],
        username="analyst",
        password=None,
        deadline_s=5.0,
        results_dir=tmp_path,
    )
    assert report.password_checked is False
    assert report.password_seen_in_breaches is None
    assert all(result.source != "hibp_password" for result in report.results)


async def test_sweep_cap(settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sources = [
        make_collector(f"check_{n}", TargetKind.EMAIL) for n in range(3)
    ]
    monkeypatch.setattr(personal.registry, "select", lambda **_: list(sources))
    settings.personal_max_sources = 1
    report = await personal.run_checks(
        settings,
        emails=["analyst@example.com"],
        username=None,
        password=None,
        deadline_s=5.0,
        results_dir=tmp_path,
    )
    assert report.sources_capped is True
    assert len(report.results) == 1


async def _fake_password_count(_client, _password: str) -> int:
    return 42

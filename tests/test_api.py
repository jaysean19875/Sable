"""HTTP API: validation, async scan lifecycle, filters, exports."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from projectosint.config import Settings
from projectosint.models import (
    Category,
    CollectorResult,
    Confidence,
    Finding,
    Provenance,
    ScanReport,
    Severity,
    Status,
)
from projectosint.targets import parse_target
from projectosint.web import app as app_module


class FakeEngine:
    """Same constructor surface as ScanEngine, zero network."""

    def __init__(self, settings: Settings, *, cache=None, on_event=None) -> None:
        self.on_event = on_event

    async def scan(self, subject, *, deadline_s=None, sources=None, categories=None,
                   use_cache=True, scan_id=None) -> ScanReport:
        target = subject if hasattr(subject, "kind") else parse_target(str(subject))
        report = ScanReport(target=target, scan_id=scan_id or "fakefakefake")
        finding = Finding.build(
            source="fake_source",
            category=Category.WEB,
            kind="web.title",
            value="Example Domain",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            provenance=Provenance(
                source="fake_source", category=Category.WEB, endpoint="https://example.com/"
            ),
        )
        report.results = [
            CollectorResult(
                source="fake_source", category=Category.WEB, status=Status.OK,
                findings=[finding], duration_ms=5.0,
            )
        ]
        report.findings = [finding]
        if self.on_event:
            self.on_event("scan_start", {"scan_id": report.scan_id, "target": target.label,
                                         "sources": ["fake_source"], "deadline_s": 5})
            self.on_event("source_done", {"source": "fake_source", "status": "ok", "count": 1,
                                          "duration_ms": 5.0})
        report.finalise()
        if self.on_event:
            self.on_event("scan_done", {"scan_id": report.scan_id, "target": target.label,
                                        "duration_ms": report.duration_ms, "findings": 1})
        return report


@pytest.fixture
def client(settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app_module, "ScanEngine", FakeEngine)
    app = app_module.create_app(settings.model_copy(update={"data_dir": tmp_path / "data",
                                                           "database": str(tmp_path / "data" / "osint.db")}))
    with TestClient(app) as test_client:
        yield test_client


def _wait_for_scan(client: TestClient, scan_id: str, attempts: int = 100) -> dict:
    for _ in range(attempts):
        response = client.get(f"/api/scans/{scan_id}")
        if response.status_code == 200:
            return response.json()
        time.sleep(0.02)
    raise AssertionError("scan did not finish")


def test_health_and_sources(client: TestClient) -> None:
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["sources"] >= 25
    catalog = client.get("/api/sources").json()
    assert catalog["count"] >= 25
    assert all("lawful_note" in source for source in catalog["sources"])


def test_scan_rejects_bad_target(client: TestClient) -> None:
    assert client.post("/api/scans", json={"target": "not a target!"}).status_code == 422
    assert client.post("/api/scans", json={"target": "example.com", "sources": ["nope"]}).status_code == 422


def test_scan_lifecycle(client: TestClient) -> None:
    started = client.post("/api/scans", json={"target": "example.com", "deadline_s": 5})
    assert started.status_code == 202
    body = started.json()
    scan_id = body["scan_id"]
    assert body["stream"].endswith(f"/api/jobs/{scan_id}/stream")

    report = _wait_for_scan(client, scan_id)
    assert report["scan_id"] == scan_id
    assert report["stats"]["total_findings"] == 1
    assert report["findings"][0]["source"] == "fake_source"

    findings = client.get(f"/api/scans/{scan_id}/findings", params={"severity": "low"}).json()
    assert findings["count"] == 1
    assert client.get(f"/api/scans/{scan_id}/findings", params={"severity": "critical"}).json()["count"] == 0

    history = client.get("/api/scans").json()
    assert any(scan["scan_id"] == scan_id for scan in history["scans"])

    stats = client.get("/api/stats").json()
    assert stats["scans"] >= 1


def test_exports(client: TestClient) -> None:
    scan_id = client.post("/api/scans", json={"target": "example.com"}).json()["scan_id"]
    _wait_for_scan(client, scan_id)

    as_json = client.get(f"/api/scans/{scan_id}/export/json")
    assert as_json.status_code == 200
    assert as_json.json()["scan_id"] == scan_id

    as_csv = client.get(f"/api/scans/{scan_id}/export/csv")
    assert as_csv.status_code == 200
    assert "fake_source" in as_csv.text

    as_pdf = client.get(f"/api/scans/{scan_id}/export/pdf")
    assert as_pdf.status_code == 200
    assert as_pdf.content.startswith(b"%PDF")

    assert client.get(f"/api/scans/{scan_id}/export/xml").status_code == 400


def test_unknown_scan(client: TestClient) -> None:
    assert client.get("/api/scans/nope").status_code == 404
    assert client.get("/api/jobs/nope/stream").status_code == 404

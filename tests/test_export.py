"""Export formats: lossless JSON, analysis CSV, a real PDF."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from projectosint.export import write_csv, write_json, write_pdf, write_report
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


def _report() -> ScanReport:
    target = parse_target("example.com")
    finding = Finding.build(
        source="dns_a",
        category=Category.DNS,
        kind="dns.a",
        value="93.184.216.34",
        detail="A record",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        tags=("dns",),
        provenance=Provenance(
            source="dns_a",
            category=Category.DNS,
            endpoint="DNS A example.com",
            query="example.com",
            terms="Public DNS resolution.",
        ),
    )
    report = ScanReport(target=target, scan_id="exportscan01")
    report.results = [
        CollectorResult(
            source="dns_a", category=Category.DNS, status=Status.OK, findings=[finding], duration_ms=3
        )
    ]
    report.findings = [finding]
    report.notes.append("synthetic export test")
    return report.finalise()


def test_json_contains_provenance(tmp_path: Path) -> None:
    report = _report()
    path = write_json(report, tmp_path / "out" / "report.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["target"]["value"] == "example.com"
    assert payload["findings"][0]["provenance"]["endpoint"] == "DNS A example.com"
    assert payload["schema_version"] == 1


def test_csv_has_stable_columns(tmp_path: Path) -> None:
    report = _report()
    path = write_csv(report, tmp_path / "findings.csv")
    rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"))))
    assert rows[0]["source"] == "dns_a"
    assert rows[0]["severity"] == "info"
    assert rows[0]["lawful_note"] == "Public DNS resolution."


def test_pdf_is_generated(tmp_path: Path) -> None:
    report = _report()
    path = write_pdf(report, tmp_path / "report.pdf")
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 1500


def test_write_report_multiple(tmp_path: Path) -> None:
    report = _report()
    written = write_report(
        report,
        json_path=str(tmp_path / "a.json"),
        csv_path=str(tmp_path / "a.csv"),
        pdf_path=str(tmp_path / "a.pdf"),
    )
    assert len(written) == 3
    assert all(path.is_file() for path in written)

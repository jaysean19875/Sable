"""Schema invariants: ids, ordering, stats, provenance."""

from __future__ import annotations

from projectosint.models import (
    Category,
    CollectorResult,
    Confidence,
    Finding,
    Provenance,
    ScanReport,
    Severity,
    Status,
    TargetKind,
)
from projectosint.targets import parse_target


def _finding(source: str = "dns_a", value: str = "1.2.3.4", **kwargs) -> Finding:
    return Finding.build(
        source=source,
        category=Category.DNS,
        kind="dns.a",
        value=value,
        provenance=Provenance(source=source, category=Category.DNS),
        **kwargs,
    )


def test_finding_id_is_stable_and_source_scoped() -> None:
    first = _finding()
    second = _finding()
    other_source = _finding(source="dns_aaaa")
    assert first.id == second.id
    assert first.id != other_source.id
    assert len(first.id) == 16


def test_severity_rank_orders() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank
    assert Severity.LOW.rank > Severity.INFO.rank


def test_scan_report_finalise_aggregates() -> None:
    report = ScanReport(target=parse_target("example.com"))
    report.results = [
        CollectorResult(
            source="dns_a",
            category=Category.DNS,
            status=Status.OK,
            findings=[_finding(severity=Severity.HIGH), _finding(value="5.6.7.8")],
            http_calls=1,
        ),
        CollectorResult(
            source="crtsh",
            category=Category.CERTIFICATES,
            status=Status.ERROR,
            error="boom",
        ),
    ]
    report.findings = [_finding(severity=Severity.HIGH), _finding(value="5.6.7.8")]
    report.finalise()
    assert report.finished_at is not None
    assert report.stats.total_findings == 2
    assert report.stats.by_status == {"error": 1, "ok": 1}
    assert report.stats.by_severity == {"high": 1, "info": 1}
    assert report.stats.http_calls == 1
    assert [r.source for r in report.results] == ["crtsh", "dns_a"]  # sorted category, source


def test_result_requires_valid_status() -> None:
    result = CollectorResult(source="x", category=Category.WEB, status=Status.OK, findings=[_finding()])
    assert result.count == 1
    assert result.from_cache is False


def test_provenance_is_frozen() -> None:
    provenance = Provenance(source="dns_a", category=Category.DNS)
    try:
        provenance.source = "other"  # type: ignore[misc]
    except Exception as exc:  # pydantic raises ValidationError
        assert "frozen" in str(exc).lower() or "immutable" in str(exc).lower()
    else:  # pragma: no cover - defensive
        raise AssertionError("Provenance should be immutable")


def test_confidence_and_target_kind_values() -> None:
    assert Confidence.LOW.value == "low"
    assert TargetKind.EMAIL.value == "email"

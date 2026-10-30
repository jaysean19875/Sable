"""Cache and store: the two persistence paths, exercised for truthfulness."""

from __future__ import annotations

import asyncio
from pathlib import Path

from projectosint.cache import ResultCache
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
from projectosint.store import Store
from projectosint.targets import parse_target


def make_finding(source: str, kind: str, value: str, severity: Severity = Severity.INFO) -> Finding:
    return Finding.build(
        source=source,
        category=Category.DNS if source.startswith("dns") else Category.CERTIFICATES,
        kind=kind,
        value=value,
        severity=severity,
        confidence=Confidence.HIGH,
        provenance=Provenance(source=source, category=Category.DNS, endpoint="https://example.test/x"),
    )


def make_report() -> ScanReport:
    target = parse_target("example.com")
    findings = [
        make_finding("dns_a", "dns.a", "93.184.216.34"),
        make_finding("crtsh", "host.subdomain", "www.example.com", Severity.LOW),
        make_finding("crtsh", "host.subdomain", "api.example.com", Severity.HIGH),
    ]
    report = ScanReport(target=target, scan_id="scan00000001")
    report.results = [
        CollectorResult(
            source="dns_a", category=Category.DNS, status=Status.OK,
            findings=[findings[0]], duration_ms=12.5, http_calls=0,
        ),
        CollectorResult(
            source="crtsh", category=Category.CERTIFICATES, status=Status.OK,
            findings=findings[1:], duration_ms=88.0, http_calls=1,
        ),
    ]
    report.findings = findings
    return report.finalise()


async def test_cache_roundtrip_and_ttl(tmp_path: Path) -> None:
    async with ResultCache(tmp_path / "cache.db", ttl_s=0.05) as cache:
        key = ResultCache.make_key("domain:example.com", "dns_a")
        result = CollectorResult(
            source="dns_a", category=Category.DNS, status=Status.OK,
            findings=[make_finding("dns_a", "dns.a", "1.1.1.1")],
        )
        await cache.put(key, result)
        hit = await cache.get(key)
        assert hit is not None
        assert hit.from_cache is True
        assert hit.findings[0].value == "1.1.1.1"
        await asyncio.sleep(0.07)
        assert await cache.get(key) is None


async def test_cache_disabled_when_ttl_zero(tmp_path: Path) -> None:
    async with ResultCache(tmp_path / "cache.db", ttl_s=0) as cache:
        key = ResultCache.make_key("domain:example.com", "dns_a")
        result = CollectorResult(source="dns_a", category=Category.DNS, status=Status.OK)
        await cache.put(key, result)
        assert await cache.get(key) is None
        assert await cache.purge_expired() == 0


async def test_store_roundtrip(tmp_path: Path) -> None:
    report = make_report()
    async with Store(tmp_path / "osint.db") as store:
        await store.save(report)
        restored = await store.get(report.scan_id)
        assert restored is not None
        assert restored.target.value == "example.com"
        assert restored.stats.total_findings == 3
        assert {f.value for f in restored.findings} == {
            "93.184.216.34", "www.example.com", "api.example.com"
        }

        listed = await store.list_scans()
        assert listed[0]["scan_id"] == report.scan_id
        assert listed[0]["findings_total"] == 3

        severe = await store.findings(report.scan_id, severity="high")
        assert [row["value"] for row in severe] == ["api.example.com"]

        by_source = await store.findings(report.scan_id, source="dns_a")
        assert len(by_source) == 1

        searched = await store.findings(report.scan_id, query="api")
        assert len(searched) == 1

        stats = await store.stats()
        assert stats["scans"] == 1
        assert stats["findings"] == 3
        assert stats["by_severity"]["high"] == 1

        assert await store.delete(report.scan_id) is True
        assert await store.get(report.scan_id) is None
        assert await store.findings(report.scan_id) == []

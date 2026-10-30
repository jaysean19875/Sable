"""Typed data model for the whole platform.

Every collector emits :class:`Finding` objects.  Nothing reaches storage,
export or the UI without passing through these models, which is what keeps
provenance and severity semantics consistent across 25+ heterogeneous
sources.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

SCHEMA_VERSION = 1


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp (never use naive datetimes here)."""
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Status(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    CACHED = "cached"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ERROR = "error"


class Category(StrEnum):
    DNS = "dns"
    CERTIFICATES = "certificates"
    REGISTRATION = "registration"
    INFRASTRUCTURE = "infrastructure"
    WEB = "web"
    EXPOSURE = "exposure"
    IDENTITY = "identity"
    THREAT = "threat"
    SEARCH = "search"


class TargetKind(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"
    HASH = "hash"


class Provenance(BaseModel):
    """Where a finding came from, when, and under which terms."""

    model_config = ConfigDict(frozen=True)

    source: str
    category: Category
    endpoint: str | None = None
    query: str | None = None
    retrieved_at: datetime = Field(default_factory=utcnow)
    terms: str | None = None
    from_cache: bool = False


class Target(BaseModel):
    """A normalised scan subject."""

    model_config = ConfigDict(frozen=True)

    kind: TargetKind
    value: str
    host: str | None = None

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target value must not be empty")
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def label(self) -> str:
        return f"{self.kind.value}:{self.value}"


class Finding(BaseModel):
    """A single atomic observation with its provenance.

    ``id`` is derived from (source, kind, value) so the same fact observed by
    the same adapter twice collapses during de-duplication, while the same
    fact from two different adapters stays visible (provenance is the point).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    category: Category
    kind: str
    value: str
    detail: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    tags: tuple[str, ...] = ()
    evidence: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance

    @classmethod
    def build(
        cls,
        *,
        source: str,
        category: Category,
        kind: str,
        value: str,
        detail: str = "",
        severity: Severity = Severity.INFO,
        confidence: Confidence = Confidence.MEDIUM,
        tags: tuple[str, ...] | list[str] = (),
        evidence: dict[str, Any] | None = None,
        provenance: Provenance,
    ) -> Self:
        value = str(value).strip()
        digest = hashlib.sha1(f"{source}\x00{kind}\x00{value}".encode()).hexdigest()[:16]
        return cls(
            id=digest,
            source=source,
            category=category,
            kind=kind,
            value=value,
            detail=detail,
            severity=severity,
            confidence=confidence,
            tags=tuple(tags),
            evidence=evidence or {},
            provenance=provenance,
        )


class CollectorResult(BaseModel):
    """Outcome of one adapter against one target."""

    model_config = ConfigDict(validate_assignment=True)

    source: str
    category: Category
    status: Status
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: float = 0.0
    http_calls: int = 0
    error: str | None = None
    note: str | None = None
    from_cache: bool = False

    @property
    def count(self) -> int:
        return len(self.findings)


class ScanStats(BaseModel):
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    sources_total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    http_calls: int = 0

    @classmethod
    def from_results(cls, results: list[CollectorResult]) -> Self:
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        by_status: dict[str, int] = {}
        total = 0
        calls = 0
        for res in results:
            by_status[res.status.value] = by_status.get(res.status.value, 0) + 1
            calls += res.http_calls
            for finding in res.findings:
                total += 1
                by_sev[finding.severity.value] = by_sev.get(finding.severity.value, 0) + 1
                by_cat[finding.category.value] = by_cat.get(finding.category.value, 0) + 1
        return cls(
            total_findings=total,
            by_severity=dict(sorted(by_sev.items())),
            by_category=dict(sorted(by_cat.items())),
            sources_total=len(results),
            by_status=dict(sorted(by_status.items())),
            http_calls=calls,
        )


class ScanRequest(BaseModel):
    """User intent, validated before any network traffic happens."""

    target: Target
    deadline_s: float = 10.0
    sources: list[str] | None = None
    categories: list[Category] | None = None
    use_cache: bool = True


class ScanReport(BaseModel):
    """The artefact a scan produces: one target, many sources, one timeline."""

    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    schema_version: int = SCHEMA_VERSION
    target: Target
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    deadline_s: float = 10.0
    results: list[CollectorResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    notes: list[str] = Field(default_factory=list)

    def finalise(self, *, started_at: datetime | None = None) -> Self:
        """Freeze timings and aggregate stats. Idempotent."""
        self.finished_at = utcnow()
        begin = started_at or self.started_at
        self.duration_ms = round((self.finished_at - begin).total_seconds() * 1000, 1)
        self.results.sort(key=lambda r: (r.category.value, r.source))
        self.findings = sorted(self.findings, key=lambda f: f.id)
        self.stats = ScanStats.from_results(self.results)
        return self

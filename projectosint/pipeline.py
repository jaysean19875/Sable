"""Post-collection normalisation and de-duplication.

Two different things are called "dedup" in OSINT tools and conflating them
loses provenance:

* within a source, identical (kind, value) rows are merged;
* across sources, identical values are kept separately but cross-linked, so
  the report can say "crt.sh, dns_txt and wayback all mention this host".

This module only does the first, plus stable ordering and caps.
"""

from __future__ import annotations

from .models import Confidence, Finding, ScanReport


def _merge(left: Finding, right: Finding) -> Finding:
    """Merge two findings from the same source, keeping the strongest signals."""
    sev = left.severity if left.severity.rank >= right.severity.rank else right.severity
    conf_rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
    conf = left.confidence if conf_rank[left.confidence] >= conf_rank[right.confidence] else right.confidence
    detail = left.detail or right.detail
    if right.detail and right.detail != detail:
        detail = f"{detail}" if detail.endswith(right.detail) else f"{detail}; {right.detail}".strip("; ")
    tags = tuple(sorted(set(left.tags) | set(right.tags)))
    evidence = {**right.evidence, **left.evidence}
    return left.model_copy(
        update={"severity": sev, "confidence": conf, "detail": detail, "tags": tags, "evidence": evidence}
    )


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate (source, kind, value) triples, order deterministically."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.id)
        merged[finding.id] = finding if existing is None else _merge(existing, finding)
    return sorted(
        merged.values(),
        key=lambda f: (-f.severity.rank, f.source, f.kind, f.value.lower()),
    )


def cap(findings: list[Finding], limit: int) -> tuple[list[Finding], bool]:
    """Deterministically truncate a source's output; returns (kept, truncated)."""
    if limit <= 0 or len(findings) <= limit:
        return findings, False
    return findings[:limit], True


def normalise(report: ScanReport, *, per_source_limit: int) -> ScanReport:
    """Apply per-source caps then global dedupe, updating report stats."""
    kept: list[Finding] = []
    for result in report.results:
        ordered = dedupe(result.findings)
        capped, truncated = cap(ordered, per_source_limit)
        if truncated:
            note = f"{result.source}: truncated at {per_source_limit} findings"
            if note not in report.notes:
                report.notes.append(note)
        result.findings = capped
        kept.extend(capped)
    report.findings = dedupe(kept)
    return report

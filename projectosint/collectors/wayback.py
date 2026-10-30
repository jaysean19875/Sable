"""Wayback Machine CDX: the historical URL inventory.

The CDX API is public and keyless.  It is also the single best source of
"dead" endpoints - admin panels, staging hosts and API paths that no longer
appear on the live site but are still archived.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

CDX = "https://web.archive.org/cdx/search/cdx"
_SENSITIVE = ("admin", "backup", "config", "private", "api", "internal", "staging", "test", "debug")
_MAX_ROWS = 1000


@register(
    CollectorSpec(
        name="wayback_cdx",
        category=Category.WEB,
        description="Historical URLs and subdomains from the Wayback Machine CDX index",
        target_kinds=frozenset({TargetKind.DOMAIN}),
        weight="heavy",
        lawful_note="Internet Archive public CDX API.",
        tags=("history", "subdomains"),
    )
)
class WaybackCdx(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = (self.ctx.target.host or self.ctx.target.value).lower()
        response = await self.ctx.get(
            CDX,
            params={
                "url": f"{host}/*",
                "output": "json",
                "fl": "timestamp,original",
                "collapse": "urlkey",
                "limit": _MAX_ROWS,
                "filter": "statuscode:200",
            },
            headers={"Accept": "application/json"},
        )
        if response.status == 404:
            return []
        if not response.ok:
            raise CollectorHttpError(f"CDX returned HTTP {response.status}", status=response.status)
        try:
            rows = response.json()
        except ValueError as exc:
            raise CollectorHttpError("CDX returned non-JSON") from exc
        if not isinstance(rows, list):
            return []

        findings: list[Finding] = []
        hosts: dict[str, str] = {}
        first_ts: str | None = None
        last_ts: str | None = None
        sensitive: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, list) or len(row) < 2:
                continue
            timestamp, original = str(row[0]), str(row[1])
            first_ts = timestamp if first_ts is None or timestamp < first_ts else first_ts
            last_ts = timestamp if last_ts is None or timestamp > last_ts else last_ts
            parts = urlsplit(original)
            sub = (parts.hostname or "").lower()
            if sub and sub.endswith(host) and sub != host:
                hosts.setdefault(sub, original)
            path = (parts.path or "").lower()
            if any(token in path for token in _SENSITIVE):
                sensitive.setdefault(original, timestamp)

        for sub in sorted(hosts)[:100]:
            findings.append(
                self.finding(
                    "host.subdomain",
                    sub,
                    detail="hostname present in archived URLs",
                    confidence=Confidence.MEDIUM,
                    tags=("subdomain", "history"),
                    evidence={"sample_url": hosts[sub]},
                    endpoint=CDX,
                    query=f"{host}/*",
                )
            )
        if first_ts:
            findings.append(
                self.finding(
                    "web.archive.first",
                    _iso(first_ts),
                    detail="earliest archived capture in the sampled window",
                    confidence=Confidence.HIGH,
                    tags=("history",),
                    endpoint=CDX,
                    query=f"{host}/*",
                )
            )
        if last_ts:
            findings.append(
                self.finding(
                    "web.archive.last",
                    _iso(last_ts),
                    detail="most recent archived capture in the sampled window",
                    confidence=Confidence.HIGH,
                    tags=("history",),
                    endpoint=CDX,
                    query=f"{host}/*",
                )
            )
        for url, timestamp in list(sensitive.items())[:25]:
            findings.append(
                self.finding(
                    "web.archive.sensitive",
                    url,
                    detail="archived URL with a sensitive-looking path",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    tags=("history", "exposure"),
                    evidence={"first_seen": _iso(timestamp)},
                    endpoint=CDX,
                    query=f"{host}/*",
                )
            )
        return findings


def _iso(timestamp: str) -> str:
    """CDX timestamps are YYYYMMDDhhmmss."""
    if len(timestamp) >= 8 and timestamp[:8].isdigit():
        return f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
    return timestamp

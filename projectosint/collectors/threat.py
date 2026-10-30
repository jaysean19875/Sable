"""Key-gated sources: registered, documented, and honestly skipped when no key.

Each adapter declares ``requires_key`` in its spec; the scheduler turns a
missing key into ``status=skipped`` with an actionable note instead of a
failure, so a scan never lies about coverage or silently drops a source.
"""

from __future__ import annotations

from typing import Any

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

_EMAIL = frozenset({TargetKind.EMAIL})
_IP = frozenset({TargetKind.IP})
_DOMAIN = frozenset({TargetKind.DOMAIN})


@register(
    CollectorSpec(
        name="hibp_breaches",
        category=Category.EXPOSURE,
        description="Breach exposure for an email address (Have I Been Pwned)",
        target_kinds=_EMAIL,
        requires_key="hibp",
        weight="normal",
        lawful_note="HIBP API with a paid key; no enumeration of breach contents.",
    )
)
class HibpBreaches(BaseCollector):
    async def collect(self) -> list[Finding]:
        email = self.ctx.target.value
        key = self.ctx.settings.api_keys.hibp
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        response = await self.ctx.get(
            url,
            headers={"hibp-api-key": key or "", "User-Agent": self.ctx.settings.user_agent},
        )
        if response.status == 404:
            return [
                self.finding(
                    "breach.none",
                    "no breaches",
                    detail="address not present in the HIBP corpus",
                    confidence=Confidence.MEDIUM,
                    tags=("breach",),
                    endpoint=url,
                    query=email,
                )
            ]
        if not response.ok:
            raise CollectorHttpError(f"HIBP returned HTTP {response.status}", status=response.status)
        breaches = response.json() or []
        findings: list[Finding] = []
        for breach in breaches:
            if not isinstance(breach, dict):
                continue
            findings.append(
                self.finding(
                    "breach.exposure",
                    str(breach.get("Name") or "unknown"),
                    detail=f"account exposed in '{breach.get('Title')}' ({breach.get('BreachDate')})",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    tags=("breach", "exposure"),
                    evidence={
                        "data_classes": breach.get("DataClasses"),
                        "pwn_count": breach.get("PwnCount"),
                        "domain": breach.get("Domain"),
                    },
                    endpoint=url,
                    query=email,
                )
            )
        return findings


@register(
    CollectorSpec(
        name="shodan_host",
        category=Category.EXPOSURE,
        description="Exposed services and banners for an IP (Shodan)",
        target_kinds=_IP,
        requires_key="shodan",
        weight="normal",
        lawful_note="Shodan API with a user key; passive index lookups only.",
    )
)
class ShodanHost(BaseCollector):
    async def collect(self) -> list[Finding]:
        ip = self.ctx.target.value
        key = self.ctx.settings.api_keys.shodan
        url = f"https://api.shodan.io/shodan/host/{ip}"
        response = await self.ctx.get(url, params={"key": key or ""})
        if response.status == 404:
            return []
        if not response.ok:
            raise CollectorHttpError(f"Shodan returned HTTP {response.status}", status=response.status)
        data = response.json() or {}
        findings: list[Finding] = []
        for service in data.get("data", []) or []:
            port = service.get("port")
            banner = str(service.get("product") or service.get("_shodan", {}).get("module") or "")
            findings.append(
                self.finding(
                    "exposure.port",
                    f"{port}/{service.get('transport', 'tcp')}",
                    detail=f"open service {banner}".strip(),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    tags=("exposure", "port"),
                    evidence={"product": service.get("product"), "version": service.get("version")},
                    endpoint=url,
                    query=ip,
                )
            )
        for cve in data.get("vulns", []) or []:
            findings.append(
                self.finding(
                    "exposure.cve",
                    str(cve),
                    detail="vulnerability reported by Shodan's index",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    tags=("exposure", "cve"),
                    endpoint=url,
                    query=ip,
                )
            )
        return findings


@register(
    CollectorSpec(
        name="urlscan_search",
        category=Category.EXPOSURE,
        description="Recent public scans referencing the domain (urlscan.io)",
        target_kinds=_DOMAIN,
        requires_key="urlscan",
        weight="normal",
        lawful_note="urlscan.io public scan index with a user key.",
    )
)
class UrlscanSearch(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = self.ctx.target.host or self.ctx.target.value
        key = self.ctx.settings.api_keys.urlscan
        url = "https://urlscan.io/api/v1/search/"
        response = await self.ctx.get(
            url, params={"q": f"domain:{host}", "size": 20}, headers={"API-Key": key or ""}
        )
        if not response.ok:
            raise CollectorHttpError(f"urlscan returned HTTP {response.status}", status=response.status)
        payload = response.json() or {}
        findings: list[Finding] = []
        for result in payload.get("results", []) or []:
            page = result.get("page") or {}
            task = result.get("task") or {}
            url_value = str(page.get("url") or task.get("url") or "")
            if not url_value:
                continue
            findings.append(
                self.finding(
                    "exposure.urlscan",
                    url_value,
                    detail=f"scanned {task.get('time', '?')}",
                    confidence=Confidence.MEDIUM,
                    tags=("urlscan",),
                    evidence={"result": result.get("result"), "server": page.get("server")},
                    endpoint=url,
                    query=host,
                )
            )
        return findings


@register(
    CollectorSpec(
        name="virustotal_domain",
        category=Category.THREAT,
        description="Reputation and resolutions for a domain (VirusTotal)",
        target_kinds=_DOMAIN,
        requires_key="virustotal",
        weight="normal",
        lawful_note="VirusTotal API with a user key; no file uploads.",
    )
)
class VirusTotalDomain(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = self.ctx.target.host or self.ctx.target.value
        key = self.ctx.settings.api_keys.virustotal
        url = f"https://www.virustotal.com/api/v3/domains/{host}"
        response = await self.ctx.get(url, headers={"x-apikey": key or ""})
        if response.status == 404:
            return []
        if not response.ok:
            raise CollectorHttpError(f"VirusTotal returned HTTP {response.status}", status=response.status)
        payload = response.json() or {}
        attributes: dict[str, Any] = (payload.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        findings = [
            self.finding(
                "threat.reputation",
                f"malicious={malicious} suspicious={suspicious}",
                detail="aggregated engine verdicts",
                severity=Severity.HIGH if malicious else Severity.INFO,
                confidence=Confidence.MEDIUM,
                tags=("reputation",),
                evidence=stats,
                endpoint=url,
                query=host,
            )
        ]
        for record in (attributes.get("last_dns_records") or [])[:50]:
            if not isinstance(record, dict):
                continue
            findings.append(
                self.finding(
                    f"threat.dns.{record.get('type', 'record')}",
                    str(record.get("value") or ""),
                    detail="historic DNS resolution observed by VirusTotal",
                    confidence=Confidence.LOW,
                    tags=("dns", "history"),
                    endpoint=url,
                    query=host,
                )
            )
        return findings

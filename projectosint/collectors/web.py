"""Web surface adapters: fingerprint, robots, sitemap, security.txt.

These are plain GETs of documents that exist to be read publicly.  We never
crawl beyond what robots.txt permits, and we do not fuzz paths - the whole
class of "did you find /admin" guessing is deliberately out of scope.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ..base import BaseCollector
from ..http import HttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

_DOMAIN = frozenset({TargetKind.DOMAIN})
_SENSITIVE = re.compile(
    r"(admin|backup|\.git|config|private|secret|token|internal|debug|staging|phpmyadmin)", re.I
)
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


async def _fetch_root(self: BaseCollector) -> tuple[object, str]:
    """GET the site root, falling back to http:// when https is unavailable."""
    host = self.ctx.target.host or self.ctx.target.value
    try:
        result = await self.ctx.get(f"https://{host}/", headers={"Accept": "text/html"})
        return result, f"https://{host}/"
    except HttpError:
        result = await self.ctx.get(f"http://{host}/", headers={"Accept": "text/html"})
        return result, f"http://{host}/"


@register(
    CollectorSpec(
        name="http_fingerprint",
        category=Category.WEB,
        description="Response fingerprint: status, server, title, generator, security headers",
        target_kinds=_DOMAIN,
        weight="normal",
        lawful_note="Single GET of the public homepage; robots.txt is respected for further fetches.",
    )
)
class HttpFingerprint(BaseCollector):
    async def collect(self) -> list[Finding]:
        response, requested = await _fetch_root(self)
        findings: list[Finding] = []
        status = getattr(response, "status", 0)
        final_url = getattr(response, "url", requested)
        findings.append(
            self.finding(
                "web.status",
                str(status),
                detail=f"homepage responded at {final_url}",
                severity=Severity.LOW if status >= 400 else Severity.INFO,
                confidence=Confidence.HIGH,
                tags=("web",),
                endpoint=requested,
            )
        )
        if str(final_url).rstrip("/") != requested.rstrip("/") and status < 400:
            findings.append(
                self.finding(
                    "web.redirect",
                    str(final_url),
                    detail="homepage redirects",
                    confidence=Confidence.HIGH,
                    tags=("web",),
                    endpoint=requested,
                )
            )
        headers = {k.lower(): v for k, v in getattr(response, "headers", {}).items()}
        for header, label in (("server", "web.server"), ("x-powered-by", "web.powered_by"),
                              ("via", "web.proxy"), ("cf-ray", "web.cdn")):
            value = headers.get(header)
            if value:
                findings.append(
                    self.finding(
                        label,
                        value,
                        detail=f"{header} header",
                        confidence=Confidence.HIGH,
                        tags=("web", "fingerprint"),
                        endpoint=str(final_url),
                    )
                )
        missing = [label for header, label in _SECURITY_HEADERS.items() if header not in headers]
        if missing:
            findings.append(
                self.finding(
                    "web.security_headers",
                    "missing:" + ",".join(sorted(missing)),
                    detail="security headers not present on the homepage response",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    tags=("web", "hardening"),
                    evidence={"present": sorted(set(_SECURITY_HEADERS.values()) - set(missing))},
                    endpoint=str(final_url),
                )
            )
        text = getattr(response, "text", "") or ""
        soup = BeautifulSoup(text[:500_000], "html.parser")
        if soup.title and soup.title.string:
            findings.append(
                self.finding(
                    "web.title",
                    soup.title.string.strip()[:200],
                    detail="page title",
                    confidence=Confidence.HIGH,
                    tags=("web", "fingerprint"),
                    endpoint=str(final_url),
                )
            )
        generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if generator and generator.get("content"):
            findings.append(
                self.finding(
                    "web.generator",
                    str(generator["content"])[:200],
                    detail="CMS/framework generator meta tag",
                    confidence=Confidence.HIGH,
                    tags=("web", "cms"),
                    endpoint=str(final_url),
                )
            )
        description = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        if description and description.get("content"):
            findings.append(
                self.finding(
                    "web.description",
                    str(description["content"])[:300],
                    detail="meta description",
                    confidence=Confidence.MEDIUM,
                    tags=("web",),
                    endpoint=str(final_url),
                )
            )
        return findings


@register(
    CollectorSpec(
        name="http_security_txt",
        category=Category.WEB,
        description="security.txt disclosure contacts and policy",
        target_kinds=_DOMAIN,
        weight="light",
        lawful_note="Public well-known document.",
    )
)
class HttpSecurityTxt(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = self.ctx.target.host or self.ctx.target.value
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = f"https://{host}{path}"
            try:
                response = await self.ctx.get(url)
            except HttpError:
                continue
            if response.status == 200 and "contact" in response.text.lower():
                fields: dict[str, list[str]] = {}
                for line in response.text.splitlines():
                    if ":" in line and not line.strip().startswith("#"):
                        key, value = line.split(":", 1)
                        fields.setdefault(key.strip().lower(), []).append(value.strip())
                findings = [
                    self.finding(
                        "web.security_txt.contact",
                        contact,
                        detail="security contact published in security.txt",
                        confidence=Confidence.HIGH,
                        tags=("web", "disclosure"),
                        endpoint=url,
                    )
                    for contact in fields.get("contact", [])
                ]
                if "expires" in fields:
                    findings.append(
                        self.finding(
                            "web.security_txt.expires",
                            fields["expires"][0],
                            detail="security.txt expiry",
                            confidence=Confidence.HIGH,
                            tags=("web", "disclosure"),
                            endpoint=url,
                        )
                    )
                return findings
        return [
            self.finding(
                "web.security_txt.absent",
                "absent",
                detail="no security.txt published at either well-known location",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                tags=("web", "disclosure"),
                endpoint=f"https://{host}/.well-known/security.txt",
            )
        ]


@register(
    CollectorSpec(
        name="http_robots",
        category=Category.WEB,
        description="robots.txt directives and sitemap references",
        target_kinds=_DOMAIN,
        weight="light",
        lawful_note="Public document; its own rules are honoured by this scanner.",
    )
)
class HttpRobots(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = self.ctx.target.host or self.ctx.target.value
        url = f"https://{host}/robots.txt"
        try:
            response = await self.ctx.get(url)
        except HttpError:
            return []
        if response.status != 200 or "<html" in response.text[:500].lower():
            return []
        disallow = [
            line.split(":", 1)[1].strip()
            for line in response.text.splitlines()
            if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
        ]
        findings = [
            self.finding(
                "web.robots",
                line.strip(),
                detail="robots.txt directive",
                confidence=Confidence.HIGH,
                tags=("web", "robots"),
                evidence={"disallow_count": len(disallow)},
                endpoint=url,
            )
            for line in response.text.splitlines()
            if line.lower().startswith(("disallow:", "sitemap:"))
        ]
        for path in disallow:
            if _SENSITIVE.search(path):
                findings.append(
                    self.finding(
                        "web.robots.sensitive",
                        path,
                        detail="robots.txt advertises a path that looks sensitive",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        tags=("web", "robots", "exposure"),
                        endpoint=url,
                    )
                )
        return findings


@register(
    CollectorSpec(
        name="http_sitemap",
        category=Category.WEB,
        description="sitemap.xml URL inventory and notable paths",
        target_kinds=_DOMAIN,
        weight="light",
        lawful_note="Public document.",
    )
)
class HttpSitemap(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = self.ctx.target.host or self.ctx.target.value
        url = f"https://{host}/sitemap.xml"
        try:
            response = await self.ctx.get(url)
        except HttpError:
            return []
        if response.status != 200:
            return []
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", response.text, flags=re.I)
        if not locs:
            return []
        findings = [
            self.finding(
                "web.sitemap",
                f"{len(locs)} urls",
                detail="sitemap.xml inventory",
                confidence=Confidence.HIGH,
                tags=("web", "sitemap"),
                evidence={"sample": locs[:10]},
                endpoint=url,
            )
        ]
        for loc in locs:
            if _SENSITIVE.search(urlsplit(loc).path):
                findings.append(
                    self.finding(
                        "web.sitemap.sensitive",
                        loc,
                        detail="sitemap references a sensitive-looking path",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        tags=("web", "sitemap", "exposure"),
                        endpoint=url,
                    )
                )
        return findings


def _absolute(base: str, href: str) -> str:
    return urljoin(base, href)

"""Certificate Transparency via crt.sh.

CT logs are public, append-only and deliberately searchable; this is one of
the few sources that legitimately reveals subdomains without touching the
target.  crt.sh is best-effort infrastructure, so failures are expected and
are reported as source errors rather than retried forever.
"""

from __future__ import annotations

import json
from collections import Counter

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

CRT_SH = "https://crt.sh/"
MAX_ROWS = 2000


@register(
    CollectorSpec(
        name="crtsh",
        category=Category.CERTIFICATES,
        description="Subdomains and issuing CAs from certificate transparency logs",
        target_kinds=frozenset({TargetKind.DOMAIN}),
        weight="heavy",
        lawful_note="Public CT logs queried via crt.sh; no authentication, no bypass.",
        tags=("subdomains", "ct"),
    )
)
class CrtShCollector(BaseCollector):
    async def collect(self) -> list[Finding]:
        domain = (self.ctx.target.host or self.ctx.target.value).lower()
        response = await self.ctx.get(
            CRT_SH,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"Accept": "application/json"},
        )
        if response.status == 404:
            return []
        if not response.ok:
            raise CollectorHttpError(f"crt.sh returned HTTP {response.status}", status=response.status)
        try:
            rows = json.loads(response.text or "[]")
        except json.JSONDecodeError as exc:
            raise CollectorHttpError("crt.sh returned non-JSON (usually an outage page)") from exc
        if not isinstance(rows, list):
            return []

        names: dict[str, dict[str, str]] = {}
        issuers: Counter[str] = Counter()
        for row in rows[:MAX_ROWS]:
            if not isinstance(row, dict):
                continue
            issuer = str(row.get("issuer_name") or "").strip()
            if issuer:
                org = _issuer_org(issuer)
                if org:
                    issuers[org] += 1
            for candidate in str(row.get("name_value") or "").splitlines():
                name = candidate.strip().lower().lstrip("*.").rstrip(".")
                if not name or name == domain or "." not in name:
                    continue
                if not name.endswith("." + domain) and name != domain:
                    continue
                entry = names.setdefault(
                    name,
                    {"first": str(row.get("not_before") or ""), "last": str(row.get("not_after") or "")},
                )
                first = str(row.get("not_before") or "")
                if first and (not entry["first"] or first < entry["first"]):
                    entry["first"] = first

        findings: list[Finding] = []
        for name in sorted(names):
            meta = names[name]
            findings.append(
                self.finding(
                    "host.subdomain",
                    name,
                    detail="hostname disclosed in certificate transparency",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    tags=("subdomain", "ct"),
                    evidence={"first_cert": meta["first"], "last_cert": meta["last"]},
                    endpoint=CRT_SH,
                    query=f"%.{domain}",
                )
            )
        for issuer, count in issuers.most_common(10):
            findings.append(
                self.finding(
                    "cert.issuer",
                    issuer,
                    detail=f"certificate authority observed {count} time(s)",
                    confidence=Confidence.HIGH,
                    tags=("pki",),
                    evidence={"certificates": count},
                    endpoint=CRT_SH,
                    query=f"%.{domain}",
                )
            )
        return findings


_PLACEHOLDERS = {"issuer not found", "none", "unknown"}


def _split_dn(dn: str) -> list[str]:
    """Split a distinguished name on unquoted commas (RFC 4514 values may be quoted)."""
    parts: list[str] = []
    buffer: list[str] = []
    in_quotes = False
    escaped = False
    for char in dn:
        if escaped:
            buffer.append(char)
            escaped = False
        elif char == "\\":
            buffer.append(char)
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
            buffer.append(char)
        elif char == "," and not in_quotes:
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
    parts.append("".join(buffer))
    return [part.strip() for part in parts if part.strip()]


def _issuer_org(issuer: str) -> str | None:
    """``C=US, O="thawte, Inc.", CN=thawte TLS RSA CA G1`` -> ``thawte, Inc.``

    crt.sh passes the issuer DN through verbatim, so quoted values containing
    commas must not be split naively - doing so produced the classic
    ``"thawte`` truncated issuer.
    """
    fallback: str | None = None
    for part in _split_dn(issuer):
        key, _, value = part.partition("=")
        cleaned = value.strip().strip('"').replace("\\,", ",").strip()
        if not cleaned or cleaned.lower() in _PLACEHOLDERS:
            continue
        if key.strip().upper() == "O":
            return cleaned
        if key.strip().upper() == "CN" and fallback is None:
            fallback = cleaned
    return fallback


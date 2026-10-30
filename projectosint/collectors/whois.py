"""Legacy WHOIS over TCP/43, with referral following.

RDAP is the future but plenty of registries still only serve port 43, and the
thin registries (``.com``, ``.net``) require following a referral to the
registrar to see registrant data.  Nothing here authenticates, scrapes a web
form, or circumvents redaction: what the registry returns is what we report.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime

from ..base import BaseCollector
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

IANA_WHOIS = "whois.iana.org"
WHOIS_PORT = 43
MAX_REFERRALS = 2
MAX_BYTES = 1_000_000


async def whois_query(server: str, query: str, timeout: float = 6.0) -> str:
    """Single WHOIS request. Raises OSError/timeout on transport failure."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(server, WHOIS_PORT), timeout)
    try:
        writer.write((query + "\r\n").encode("ascii", "ignore"))
        await writer.drain()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_BYTES:
                break
        return b"".join(chunks).decode("utf-8", "replace")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _fields(text: str) -> dict[str, list[str]]:
    """Split ``Key: value`` lines, case-insensitively, preserving order."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("%", "#", ">>>")):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key or not value:
            continue
        out.setdefault(key, []).append(value)
    return out


def _first(fields: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        values = fields.get(key.lower())
        if values:
            return values[0]
    return None


def _parse_date(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            parsed = datetime.strptime(value.strip(), fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None

@register(
    CollectorSpec(
        name="whois",
        category=Category.REGISTRATION,
        description="Registry WHOIS (port 43) with registrar referral following",
        target_kinds=frozenset({TargetKind.DOMAIN}),
        weight="normal",
        lawful_note="Public registry WHOIS; redacted fields are reported as redacted.",
    )
)
class WhoisCollector(BaseCollector):
    async def collect(self) -> list[Finding]:
        domain = (self.ctx.target.host or self.ctx.target.value).lower()
        timeout = min(6.0, self.ctx.settings.http_timeout_s)
        text = await whois_query(IANA_WHOIS, domain, timeout)
        fields = _fields(text)
        server = _first(fields, "refer", "whois")
        for _ in range(MAX_REFERRALS):
            if not server:
                break
            try:
                referred = await whois_query(server, domain, timeout)
            except (TimeoutError, OSError):
                break
            referred_fields = _fields(referred)
            for key, values in referred_fields.items():
                fields.setdefault(key, values)
            server = _first(referred_fields, "registrar whois server", "refer")

        return self._findings(fields, domain)

    def _findings(self, fields: dict[str, list[str]], domain: str) -> list[Finding]:
        endpoint = f"whois://{IANA_WHOIS}/{domain}"
        findings: list[Finding] = []

        registrar = _first(fields, "registrar", "registrar name", "sponsoring registrar")
        if registrar:
            findings.append(
                self.finding(
                    "whois.registrar",
                    registrar,
                    detail="sponsoring registrar",
                    confidence=Confidence.HIGH,
                    tags=("registration",),
                    endpoint=endpoint,
                    query=domain,
                )
            )

        created = _parse_date(_first(fields, "creation date", "created", "domain registration date") or "")
        if created:
            findings.append(
                self.finding(
                    "whois.created",
                    created.date().isoformat(),
                    detail="domain creation date",
                    confidence=Confidence.HIGH,
                    tags=("registration", "age"),
                    endpoint=endpoint,
                    query=domain,
                )
            )

        expires_raw = _first(
            fields, "registry expiry date", "registrar registration expiration date", "expiry date", "expires"
        )
        expires = _parse_date(expires_raw or "")
        if expires:
            days = (expires - datetime.now(UTC)).days
            severity = Severity.MEDIUM if days < 30 else Severity.INFO
            findings.append(
                self.finding(
                    "whois.expires",
                    expires.date().isoformat(),
                    detail=f"registration expiry in {days} days",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    tags=("registration", "expiry"),
                    evidence={"days_remaining": days},
                    endpoint=endpoint,
                    query=domain,
                )
            )

        org = _first(fields, "registrant organization", "registrant organisation", "registrant name", "org")
        if org:
            redacted = "redacted" in org.lower() or "not disclosed" in org.lower()
            findings.append(
                self.finding(
                    "whois.registrant",
                    org,
                    detail="registrant organisation" + (" (redacted by registry)" if redacted else ""),
                    confidence=Confidence.LOW if redacted else Confidence.MEDIUM,
                    tags=("registration", "registrant"),
                    endpoint=endpoint,
                    query=domain,
                )
            )

        for status in fields.get("domain status", []) + fields.get("status", []):
            findings.append(
                self.finding(
                    "whois.status",
                    status,
                    detail="domain status flag",
                    severity=Severity.MEDIUM if "hold" in status.lower() else Severity.INFO,
                    confidence=Confidence.HIGH,
                    tags=("registration", "status"),
                    endpoint=endpoint,
                    query=domain,
                )
            )

        for nameserver in fields.get("name server", []) + fields.get("nserver", []):
            findings.append(
                self.finding(
                    "whois.nameserver",
                    nameserver.lower().rstrip("."),
                    detail="nameserver per WHOIS",
                    confidence=Confidence.MEDIUM,
                    tags=("dns",),
                    endpoint=endpoint,
                    query=domain,
                )
            )
        return findings

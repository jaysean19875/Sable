"""TLS certificate inspection.

Connecting to port 443 and reading the certificate the server presents is
passive, ordinary client behaviour - and it leaks SANs, issuer, validity and
the negotiated protocol version, all of which matter during reconnaissance.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

import certifi

from ..base import BaseCollector
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

_CERT_TIME = "%b %d %H:%M:%S %Y %Z"


@lru_cache(maxsize=1)
def ssl_context() -> ssl.SSLContext:
    """Verified context using certifi's bundle, not the OS store.

    The Windows certificate store is frequently stale or incomplete (and in
    Python 3.11 on Windows, loaded lazily), which produced *false* "invalid
    certificate" findings against perfectly valid chains.  certifi is the same
    trust store httpx already uses, so HTTP and TLS agree on what is valid.
    """
    return ssl.create_default_context(cafile=certifi.where())


async def fetch_peer_certificate(
    host: str, *, port: int = 443, timeout: float = 6.0
) -> tuple[dict[str, Any], str | None, str | None]:
    """Return (cert dict, TLS version, cipher name). Raises on handshake failure."""
    context = ssl_context()
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() if ssl_object is not None else {}
        version = ssl_object.version() if ssl_object is not None else None
        cipher = ssl_object.cipher()[0] if ssl_object is not None and ssl_object.cipher() else None
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    return dict(cert or {}), version, cipher


def _name_part(cert: dict[str, Any], key: str) -> str | None:
    for rdn in cert.get(key, ()):  # subject/issuer are ((('commonName','x'),),)
        for item in rdn:
            if len(item) == 2 and item[0] == "commonName":
                return str(item[1])
    return None


def _org_part(cert: dict[str, Any], key: str) -> str | None:
    for rdn in cert.get(key, ()):
        for item in rdn:
            if len(item) == 2 and item[0] == "organizationName":
                return str(item[1])
    return None


@register(
    CollectorSpec(
        name="tls_cert",
        category=Category.CERTIFICATES,
        description="Served certificate: SANs, issuer, validity window, protocol version",
        target_kinds=frozenset({TargetKind.DOMAIN}),
        weight="normal",
        lawful_note="Ordinary TLS handshake to a public endpoint; no vulnerability probing.",
    )
)
class TlsCertificate(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = (self.ctx.target.host or self.ctx.target.value).lower()
        endpoint = f"tls://{host}:443"
        try:
            cert, version, cipher = await fetch_peer_certificate(
                host, timeout=min(6.0, self.ctx.settings.http_timeout_s)
            )
        except ssl.SSLCertVerificationError as exc:
            return [
                self.finding(
                    "tls.invalid",
                    str(exc.reason or "certificate verification failed"),
                    detail="certificate chain failed validation",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    tags=("tls", "certificate"),
                    evidence={"verify_message": str(exc.verify_message)},
                    endpoint=endpoint,
                    query=host,
                )
            ]

        findings: list[Finding] = []
        subject = _name_part(cert, "subject")
        if subject:
            findings.append(
                self.finding(
                    "tls.subject",
                    subject,
                    detail="certificate common name",
                    confidence=Confidence.HIGH,
                    tags=("tls",),
                    endpoint=endpoint,
                    query=host,
                )
            )
        issuer_org = _org_part(cert, "issuer") or _name_part(cert, "issuer")
        if issuer_org:
            self_signed = subject == _name_part(cert, "issuer")
            findings.append(
                self.finding(
                    "tls.issuer",
                    issuer_org,
                    detail="self-signed certificate" if self_signed else "issuing certificate authority",
                    severity=Severity.MEDIUM if self_signed else Severity.INFO,
                    confidence=Confidence.HIGH,
                    tags=("tls", "pki"),
                    endpoint=endpoint,
                    query=host,
                )
            )
        for kind, hostname in cert.get("subjectAltName", ()):
            if kind != "DNS":
                continue
            findings.append(
                self.finding(
                    "tls.san",
                    str(hostname).lower(),
                    detail="DNS subject alternative name",
                    confidence=Confidence.HIGH,
                    tags=("tls", "san"),
                    endpoint=endpoint,
                    query=host,
                )
            )
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expires = datetime.strptime(str(not_after), _CERT_TIME).replace(tzinfo=UTC)
            except ValueError:
                expires = None
            if expires is not None:
                days = (expires - datetime.now(UTC)).days
                severity = Severity.INFO
                if days < 0 or days < 14:
                    severity = Severity.HIGH
                elif days < 30:
                    severity = Severity.MEDIUM
                findings.append(
                    self.finding(
                        "tls.expires",
                        expires.date().isoformat(),
                        detail=f"certificate expires in {days} days",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        tags=("tls", "expiry"),
                        evidence={"days_remaining": days},
                        endpoint=endpoint,
                        query=host,
                    )
                )
        if version:
            findings.append(
                self.finding(
                    "tls.protocol",
                    version,
                    detail="negotiated TLS version",
                    severity=Severity.MEDIUM if version in {"TLSv1", "TLSv1.1", "SSLv3"} else Severity.INFO,
                    confidence=Confidence.HIGH,
                    tags=("tls",),
                    endpoint=endpoint,
                    query=host,
                )
            )
        if cipher:
            findings.append(
                self.finding(
                    "tls.cipher",
                    cipher,
                    detail="negotiated cipher suite",
                    confidence=Confidence.HIGH,
                    tags=("tls",),
                    endpoint=endpoint,
                    query=host,
                )
            )
        return findings

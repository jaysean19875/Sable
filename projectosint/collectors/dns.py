"""DNS adapters: the cheapest, most reliable intelligence available.

All lookups go through :func:`query_dns` so the whole module can be tested
offline by monkeypatching one function, and so no adapter can accidentally
open its own resolver with different timeout semantics.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..base import BaseCollector
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

_MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "messagelabs.com": "Broadcom Email Security",
    "barracudanetworks.com": "Barracuda",
    "zoho.com": "Zoho Mail",
    "yandex.net": "Yandex Mail",
    "qq.com": "Tencent Exmail",
    "secureserver.net": "GoDaddy Mail",
}

_DNS_KINDS = frozenset({TargetKind.DOMAIN})


async def query_dns(name: str, rrtype: str, timeout: float = 5.0) -> list[str]:
    """Resolve ``name``/``rrtype`` returning textual RDATA ([] on no answer)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = await resolver.resolve(name, rrtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        return []
    if answer.rrset is None:
        return []
    return [rdata.to_text() for rdata in answer.rrset]


def _unquote(raw: str) -> str:
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1]
    return text.replace('\\"', '"').replace("\\\\", "\\")


def _host(ctx_target_host: str | None, value: str) -> str:
    return ctx_target_host or value


class _RecordCollector(BaseCollector):
    """Shared implementation for single-RRType lookups."""

    record_type: ClassVar[str] = "A"
    finding_kind: ClassVar[str] = "dns.record"
    confidence: ClassVar[Confidence] = Confidence.HIGH
    tags: ClassVar[tuple[str, ...]] = ()

    async def collect(self) -> list[Finding]:
        host = _host(self.ctx.target.host, self.ctx.target.value)
        records = await query_dns(host, self.record_type, self.ctx.settings.http_timeout_s)
        findings = []
        for raw in records:
            value, detail, tags, severity = self.describe(raw)
            findings.append(
                self.finding(
                    self.finding_kind,
                    value,
                    detail=detail,
                    severity=severity,
                    confidence=self.confidence,
                    tags=tuple(self.tags) + tuple(tags),
                    evidence={"rrtype": self.record_type, "raw": raw, "host": host},
                    endpoint=f"DNS {self.record_type} {host}",
                    query=host,
                )
            )
        return findings

    def describe(self, raw: str) -> tuple[str, str, tuple[str, ...], Severity]:
        return _unquote(raw), f"{self.record_type} record for this host", (), Severity.INFO


@register(
    CollectorSpec(
        name="dns_a",
        category=Category.DNS,
        description="IPv4 addresses (A records) for the apex and resolved host",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsA(_RecordCollector):
    record_type = "A"
    finding_kind = "dns.a"


@register(
    CollectorSpec(
        name="dns_aaaa",
        category=Category.DNS,
        description="IPv6 addresses (AAAA records)",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsAaaa(_RecordCollector):
    record_type = "AAAA"
    finding_kind = "dns.aaaa"


@register(
    CollectorSpec(
        name="dns_ns",
        category=Category.DNS,
        description="Authoritative nameservers and the DNS operator they imply",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsNs(_RecordCollector):
    record_type = "NS"
    finding_kind = "dns.ns"

    def describe(self, raw: str) -> tuple[str, str, tuple[str, ...], Severity]:
        value = _unquote(raw).rstrip(".").lower()
        provider = _operator_for(value)
        return value, f"nameserver ({provider})" if provider else "nameserver", (), Severity.INFO


@register(
    CollectorSpec(
        name="dns_mx",
        category=Category.DNS,
        description="Mail exchangers, priorities and the mail provider in use",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsMx(_RecordCollector):
    record_type = "MX"
    finding_kind = "dns.mx"

    def describe(self, raw: str) -> tuple[str, str, tuple[str, ...], Severity]:
        parts = raw.split()
        if len(parts) == 2:
            priority, exchange = parts[0], _unquote(parts[1])
        else:  # malformed / empty MX
            priority, exchange = "?", _unquote(raw).strip()
        exchange = exchange.rstrip(".")
        if exchange in {"", "."}:
            return (
                ".",
                "null MX (RFC 7505): the domain explicitly does not accept mail",
                ("email-security", "null-mx"),
                Severity.LOW,
            )
        provider = _operator_for(exchange)
        tags = (f"mail-provider:{provider}",) if provider else ()
        provider_note = f" via {provider}" if provider else ""
        return exchange, f"MX priority {priority}{provider_note}", tags, Severity.INFO


@register(
    CollectorSpec(
        name="dns_txt",
        category=Category.DNS,
        description="TXT records: verification tokens, SPF/DMARC context, policy hints",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsTxt(_RecordCollector):
    record_type = "TXT"
    finding_kind = "dns.txt"
    confidence = Confidence.MEDIUM

    def describe(self, raw: str) -> tuple[str, str, tuple[str, ...], Severity]:
        value = _unquote(raw)
        low = value.lower()
        tags: tuple[str, ...] = ()
        if low.startswith("v=spf1"):
            tags = ("spf",)
        elif low.startswith("v=dmarc1"):
            tags = ("dmarc",)
        elif "verification" in low or low.startswith("ms="):
            tags = ("verification-token",)
        elif low.startswith("v=dkim1"):
            tags = ("dkim",)
        return value, "TXT record", tags, Severity.INFO


@register(
    CollectorSpec(
        name="dns_caa",
        category=Category.DNS,
        description="CAA records: which CAs may issue certificates for the domain",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsCaa(_RecordCollector):
    record_type = "CAA"
    finding_kind = "dns.caa"

    def describe(self, raw: str) -> tuple[str, str, tuple[str, ...], Severity]:
        value = _unquote(raw)
        return value, "certificate authority authorisation", ("caa",), Severity.INFO


@register(
    CollectorSpec(
        name="dns_soa",
        category=Category.DNS,
        description="SOA: primary nameserver, responsible mailbox, serial",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsSoa(_RecordCollector):
    record_type = "SOA"
    finding_kind = "dns.soa"

    def describe(self, raw: str) -> tuple[str, str, tuple[str, ...], Severity]:
        parts = _unquote(raw).split()
        primary = parts[0].rstrip(".") if parts else raw
        rname = parts[1].replace(".", "@", 1).rstrip(".") if len(parts) > 1 else ""
        serial = parts[2] if len(parts) > 2 else ""
        detail = f"primary={primary} serial={serial}"
        if rname:
            detail += f" contact={rname}"
        return primary, detail, (), Severity.INFO


@register(
    CollectorSpec(
        name="dns_spf",
        category=Category.DNS,
        description="SPF policy analysis, including the all-qualifier risk",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsSpf(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = _host(self.ctx.target.host, self.ctx.target.value)
        records = await query_dns(host, "TXT", self.ctx.settings.http_timeout_s)
        spf = [r for r in records if "v=spf1" in r.lower()]
        if not spf:
            return [
                self.finding(
                    "dns.spf",
                    "missing",
                    detail="No SPF record: the domain does not publish sender policy",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    tags=("email-security",),
                    endpoint=f"DNS TXT {host}",
                    query=host,
                )
            ]
        findings = []
        for raw in spf:
            record = _unquote(raw)
            qualifier = _spf_all_qualifier(record)
            severity = Severity.INFO
            note = ""
            if qualifier == "+":
                severity = Severity.MEDIUM
                note = " '+all' authorises every sender - effectively no policy"
            elif qualifier in {"?", "~"}:
                severity = Severity.LOW
                note = f" '{qualifier}all' is permissive (softfail/neutral)"
            findings.append(
                self.finding(
                    "dns.spf",
                    record,
                    detail=f"SPF policy, {len(record.split()) - 1} mechanisms{note}",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    tags=("email-security",),
                    evidence={"all_qualifier": qualifier, "host": host},
                    endpoint=f"DNS TXT {host}",
                    query=host,
                )
            )
        return findings


@register(
    CollectorSpec(
        name="dns_dmarc",
        category=Category.DNS,
        description="DMARC policy strength for the domain",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsDmarc(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = _host(self.ctx.target.host, self.ctx.target.value)
        name = f"_dmarc.{host}"
        records = await query_dns(name, "TXT", self.ctx.settings.http_timeout_s)
        dmarc = [r for r in records if "v=dmarc1" in r.lower()]
        if not dmarc:
            return [
                self.finding(
                    "dns.dmarc",
                    "missing",
                    detail="No DMARC record: no published policy for failing mail",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    tags=("email-security",),
                    endpoint=f"DNS TXT {name}",
                    query=name,
                )
            ]
        findings = []
        for raw in dmarc:
            record = _unquote(raw)
            tags = dict(
                item.split("=", 1) for item in record.replace(" ", "").split(";") if "=" in item
            )
            policy = tags.get("p", "").lower()
            severity = Severity.MEDIUM if policy in {"none", ""} else Severity.INFO
            detail = f"DMARC p={policy or 'none'}"
            if tags.get("rua"):
                detail += " with aggregate reporting"
            findings.append(
                self.finding(
                    "dns.dmarc",
                    record,
                    detail=detail,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    tags=("email-security",),
                    evidence=tags,
                    endpoint=f"DNS TXT {name}",
                    query=name,
                )
            )
        return findings


@register(
    CollectorSpec(
        name="dns_dnssec",
        category=Category.DNS,
        description="DNSSEC signing state (DNSKEY present, DS delegated)",
        target_kinds=_DNS_KINDS,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class DnsDnssec(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = _host(self.ctx.target.host, self.ctx.target.value)
        timeout = self.ctx.settings.http_timeout_s
        keys, ds = await asyncio.gather(
            query_dns(host, "DNSKEY", timeout),
            query_dns(host, "DS", timeout),
        )
        if not keys and not ds:
            return [
                self.finding(
                    "dns.dnssec",
                    "unsigned",
                    detail="No DNSKEY or DS records: the zone is not DNSSEC signed",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    tags=("dnssec",),
                    endpoint=f"DNS DNSKEY {host}",
                    query=host,
                )
            ]
        return [
            self.finding(
                "dns.dnssec",
                "signed",
                detail=f"DNSKEY records={len(keys)}, DS records={len(ds)}",
                confidence=Confidence.HIGH,
                tags=("dnssec",),
                evidence={"dnskey_count": len(keys), "ds_count": len(ds)},
                endpoint=f"DNS DNSKEY {host}",
                query=host,
            )
        ]


def _spf_all_qualifier(record: str) -> str:
    for token in record.split():
        low = token.lower()
        if low.endswith("all") and len(low) == 4:
            return low[0]
        if low == "all":
            return "+"
    return ""


def _operator_for(hostname: str) -> str | None:
    hostname = hostname.lower().rstrip(".")
    for suffix, provider in _MAIL_PROVIDERS.items():
        if hostname == suffix or hostname.endswith("." + suffix):
            return provider
    return None

"""IP and ASN intelligence.

Team Cymru's DNS interface is the keyless, low-latency way to map an address
to an ASN and prefix; ip-api.com fills in geography and hosting/proxy flags.
Both are public services with documented rate expectations, which is why the
token bucket exists.
"""

from __future__ import annotations

import ipaddress

import dns.reversename

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register
from .dns import _unquote, query_dns

_IP = frozenset({TargetKind.IP})
_CYMRU_V4 = "origin.asn.cymru.com"
_CYMRU_V6 = "origin6.asn.cymru.com"
_GEO = "http://ip-api.com/json/"


def _reverse_name(ip: str) -> tuple[str, str]:
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        octets = ip.split(".")
        return ".".join(reversed(octets)) + "." + _CYMRU_V4, _CYMRU_V4
    exploded = address.exploded.replace(":", "")
    return ".".join(reversed(exploded)) + "." + _CYMRU_V6, _CYMRU_V6


@register(
    CollectorSpec(
        name="ip_asn_cymru",
        category=Category.INFRASTRUCTURE,
        description="ASN, announced prefix and registry via Team Cymru DNS (keyless)",
        target_kinds=_IP,
        weight="light",
        lawful_note="Team Cymru public DNS whois service.",
    )
)
class IpAsnCymru(BaseCollector):
    async def collect(self) -> list[Finding]:
        ip = self.ctx.target.value
        timeout = self.ctx.settings.http_timeout_s
        query_name, zone = _reverse_name(ip)
        rows = [r for r in await query_dns(query_name, "TXT", timeout) if "|" in r]
        findings: list[Finding] = []
        for raw in rows[:3]:
            parts = [_unquote(p).strip() for p in _unquote(raw).split("|")]
            if len(parts) < 3:
                continue
            asn, prefix, country = parts[0], parts[1], parts[2]
            registry = parts[3] if len(parts) > 3 else ""
            findings.append(
                self.finding(
                    "ip.asn",
                    f"AS{asn}",
                    detail=f"announced by {prefix} ({country})" + (f" via {registry}" if registry else ""),
                    confidence=Confidence.HIGH,
                    tags=("asn", "network"),
                    evidence={"asn": asn, "prefix": prefix, "country": country, "registry": registry},
                    endpoint=f"DNS TXT {zone}",
                    query=query_name,
                )
            )
            org = await self._asn_org(asn, timeout)
            if org:
                findings.append(
                    self.finding(
                        "ip.asn_org",
                        org,
                        detail=f"AS{asn} holder",
                        confidence=Confidence.HIGH,
                        tags=("asn", "org"),
                        evidence={"asn": asn},
                        endpoint="DNS TXT asn.cymru.com",
                        query=asn,
                    )
                )
        return findings

    async def _asn_org(self, asn: str, timeout: float) -> str | None:
        rows = [r for r in await query_dns(f"AS{asn}.asn.cymru.com", "TXT", timeout) if "|" in r]
        if not rows:
            return None
        parts = [_unquote(p).strip() for p in _unquote(rows[0]).split("|")]
        return parts[-1] if len(parts) >= 5 and parts[-1] else None


@register(
    CollectorSpec(
        name="ip_ptr",
        category=Category.INFRASTRUCTURE,
        description="Reverse DNS (PTR) names for the address",
        target_kinds=_IP,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class IpPtr(BaseCollector):
    async def collect(self) -> list[Finding]:
        ip = self.ctx.target.value
        try:
            reverse = dns.reversename.from_address(ip)
        except ValueError:
            return []
        names = await query_dns(str(reverse), "PTR", self.ctx.settings.http_timeout_s)
        findings = []
        for raw in names:
            name = _unquote(raw).rstrip(".").lower()
            if not name:
                continue
            hosting = any(
                token in name
                for token in ("compute", "amazonaws", "azure", "googleusercontent", "cloud", "vps", "server")
            )
            findings.append(
                self.finding(
                    "ip.ptr",
                    name,
                    detail="reverse DNS name" + (" (hosting provider signature)" if hosting else ""),
                    confidence=Confidence.HIGH,
                    tags=("dns", "ptr") + (("hosting",) if hosting else ()),
                    endpoint=f"DNS PTR {reverse}",
                    query=ip,
                )
            )
        return findings


@register(
    CollectorSpec(
        name="ip_geo",
        category=Category.INFRASTRUCTURE,
        description="Geolocation, ISP and hosting/proxy flags via ip-api.com",
        target_kinds=_IP,
        weight="normal",
        lawful_note="ip-api.com free tier (rate limited); no authentication.",
    )
)
class IpGeo(BaseCollector):
    FIELDS = (
        "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
        "hosting,proxy,mobile,reverse,query"
    )

    async def collect(self) -> list[Finding]:
        ip = self.ctx.target.value
        url = f"{_GEO}{ip}"
        payload = await self.ctx.get_json(url, params={"fields": self.FIELDS})
        if not isinstance(payload, dict):
            raise CollectorHttpError("ip-api returned an unexpected payload")
        if payload.get("status") == "fail":
            raise CollectorHttpError(f"ip-api: {payload.get('message', 'lookup failed')}")
        findings: list[Finding] = []
        parts = [str(payload.get(k)) for k in ("city", "regionName", "country") if payload.get(k)]
        if parts:
            findings.append(
                self.finding(
                    "ip.location",
                    ", ".join(parts),
                    detail="approximate geolocation",
                    confidence=Confidence.MEDIUM,
                    tags=("geo",),
                    evidence={
                        "country_code": payload.get("countryCode"),
                        "lat_lon_available": False,
                    },
                    endpoint=url,
                    query=ip,
                )
            )
        org = payload.get("org") or payload.get("isp")
        if org:
            findings.append(
                self.finding(
                    "ip.org",
                    str(org),
                    detail="network operator",
                    confidence=Confidence.HIGH,
                    tags=("org",),
                    evidence={"asn": payload.get("as"), "asname": payload.get("asname")},
                    endpoint=url,
                    query=ip,
                )
            )
        if payload.get("hosting") or payload.get("proxy"):
            flags = [flag for flag in ("hosting", "proxy", "mobile") if payload.get(flag)]
            findings.append(
                self.finding(
                    "ip.hosting",
                    ",".join(flags),
                    detail="address looks like datacentre/proxy infrastructure",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    tags=("hosting", "infrastructure"),
                    endpoint=url,
                    query=ip,
                )
            )
        return findings

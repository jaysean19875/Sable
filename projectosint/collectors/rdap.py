"""RDAP: the structured, machine-readable successor to WHOIS.

``rdap.org`` is a bootstrap redirector that maps any domain/IP to the correct
registry RDAP service, so a single adapter covers every TLD that publishes
RDAP without hardcoding a per-registry table.
"""

from __future__ import annotations

import json
from typing import Any

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

RDAP_BOOTSTRAP = "https://rdap.org"
_CATEGORY = Category.REGISTRATION


def _vcard_values(entity: dict[str, Any], wanted: str) -> list[str]:
    """Extract values of a vCard property (``fn``, ``email``, ``org``...)."""
    out: list[str] = []
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return out
    for prop in card[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        if str(prop[0]).lower() != wanted:
            continue
        value = prop[3]
        if isinstance(value, list):
            value = " ".join(str(v) for v in value)
        if str(value).strip():
            out.append(str(value).strip())
    return out


def _walk_entities(entities: list[Any], role: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if role in roles:
            found.append(entity)
        nested = entity.get("entities")
        if isinstance(nested, list):
            found.extend(_walk_entities(nested, role))
    return found


def _event_date(payload: dict[str, Any], action: str) -> str | None:
    for event in payload.get("events") or []:
        if str(event.get("eventAction", "")).lower() == action:
            return str(event.get("eventDate") or "") or None
    return None


class _RdapBase(BaseCollector):
    target_kind = TargetKind.DOMAIN
    endpoint = RDAP_BOOTSTRAP

    async def fetch(self) -> dict[str, Any]:
        value = self.ctx.target.value
        response = await self.ctx.get(self.url(value), headers={"Accept": "application/rdap+json"})
        if response.status == 404:
            raise CollectorHttpError("no RDAP object published for this target", status=404)
        if not response.ok:
            raise CollectorHttpError(f"RDAP returned HTTP {response.status}", status=response.status)
        try:
            payload = json.loads(response.text)
        except json.JSONDecodeError as exc:
            raise CollectorHttpError("RDAP returned non-JSON") from exc
        if not isinstance(payload, dict):
            raise CollectorHttpError("RDAP payload was not an object")
        return payload

    def url(self, value: str) -> str:
        raise NotImplementedError

    def common_findings(self, payload: dict[str, Any], endpoint: str) -> list[Finding]:
        findings: list[Finding] = []
        for action, kind, label in (
            ("registration", "rdap.registered", "registered"),
            ("expiration", "rdap.expires", "expires"),
            ("last changed", "rdap.updated", "last changed"),
            ("last update of rdap database", "rdap.registry_updated", "registry updated"),
        ):
            date = _event_date(payload, action)
            if date:
                findings.append(
                    self.finding(
                        kind,
                        date,
                        detail=f"registry record {label} on this date",
                        confidence=Confidence.HIGH,
                        tags=("registration",),
                        endpoint=endpoint,
                        query=self.ctx.target.value,
                    )
                )
        statuses = [str(s) for s in (payload.get("status") or [])]
        risky = {"client hold", "server hold", "pending delete", "pending delete restored", "inactive"}
        for status in statuses:
            findings.append(
                self.finding(
                    "rdap.status",
                    status,
                    detail="registry status flag",
                    severity=Severity.MEDIUM if status.lower() in risky else Severity.INFO,
                    confidence=Confidence.HIGH,
                    tags=("registration", "status"),
                    endpoint=endpoint,
                    query=self.ctx.target.value,
                )
            )
        for ns in payload.get("nameservers") or []:
            name = str(ns.get("ldhName") or "").lower()
            if name:
                findings.append(
                    self.finding(
                        "rdap.nameserver",
                        name,
                        detail="delegated nameserver per RDAP",
                        confidence=Confidence.HIGH,
                        tags=("dns",),
                        endpoint=endpoint,
                        query=self.ctx.target.value,
                    )
                )
        secure = payload.get("secureDNS")
        if isinstance(secure, dict):
            findings.append(
                self.finding(
                    "rdap.dnssec",
                    "signed" if secure.get("delegationSigned") else "unsigned",
                    detail="DNSSEC delegation state reported by the registry",
                    confidence=Confidence.HIGH,
                    tags=("dnssec",),
                    endpoint=endpoint,
                    query=self.ctx.target.value,
                )
            )
        return findings

    def entity_findings(
        self, entities: list[Any], endpoint: str, role: str, kind: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for entity in _walk_entities(entities, role):
            names = _vcard_values(entity, "fn") or _vcard_values(entity, "org")
            emails = _vcard_values(entity, "email")
            for name in names:
                findings.append(
                    self.finding(
                        kind,
                        name,
                        detail=f"{role} contact",
                        confidence=Confidence.MEDIUM,
                        tags=("registration", role),
                        evidence={"emails": emails, "handle": entity.get("handle")},
                        endpoint=endpoint,
                        query=self.ctx.target.value,
                    )
                )
            for email in emails:
                findings.append(
                    self.finding(
                        f"{kind}.email",
                        email,
                        detail=f"{role} contact email",
                        confidence=Confidence.MEDIUM,
                        tags=("registration", "email", role),
                        endpoint=endpoint,
                        query=self.ctx.target.value,
                    )
                )
        return findings


@register(
    CollectorSpec(
        name="rdap_domain",
        category=_CATEGORY,
        description="Domain registration: registrar, dates, status, nameservers, DNSSEC",
        target_kinds=frozenset({TargetKind.DOMAIN}),
        weight="normal",
        lawful_note="Public RDAP (registration data); redacted fields stay redacted.",
    )
)
class RdapDomain(_RdapBase):
    def url(self, value: str) -> str:
        return f"{RDAP_BOOTSTRAP}/domain/{value}"

    async def collect(self) -> list[Finding]:
        payload = await self.fetch()
        endpoint = self.url(self.ctx.target.value)
        findings = self.common_findings(payload, endpoint)
        entities = payload.get("entities") or []
        findings += self.entity_findings(entities, endpoint, "registrar", "rdap.registrar")
        findings += self.entity_findings(entities, endpoint, "registrant", "rdap.registrant")
        findings += self.entity_findings(entities, endpoint, "abuse", "rdap.abuse")
        for remark in payload.get("remarks") or []:
            text = " ".join(str(t) for t in (remark.get("description") or []))[:400]
            if text:
                findings.append(
                    self.finding(
                        "rdap.remark",
                        text,
                        detail="registry remark",
                        confidence=Confidence.LOW,
                        tags=("registration",),
                        endpoint=endpoint,
                        query=self.ctx.target.value,
                    )
                )
        return findings


@register(
    CollectorSpec(
        name="rdap_ip",
        category=_CATEGORY,
        description="IP registration: network range, holder, abuse contact, status",
        target_kinds=frozenset({TargetKind.IP}),
        weight="normal",
        lawful_note="Public RDAP (registration data).",
    )
)
class RdapIp(_RdapBase):
    def url(self, value: str) -> str:
        return f"{RDAP_BOOTSTRAP}/ip/{value}"

    async def collect(self) -> list[Finding]:
        payload = await self.fetch()
        endpoint = self.url(self.ctx.target.value)
        findings = self.common_findings(payload, endpoint)
        if payload.get("name"):
            findings.append(
                self.finding(
                    "rdap.network",
                    str(payload["name"]),
                    detail="registered network name",
                    confidence=Confidence.HIGH,
                    tags=("network",),
                    evidence={"handle": payload.get("handle")},
                    endpoint=endpoint,
                    query=self.ctx.target.value,
                )
            )
        if payload.get("startAddress") and payload.get("endAddress"):
            cidr = f"{payload['startAddress']} - {payload['endAddress']}"
            findings.append(
                self.finding(
                    "rdap.range",
                    cidr,
                    detail="network range covering this address",
                    confidence=Confidence.HIGH,
                    tags=("network",),
                    endpoint=endpoint,
                    query=self.ctx.target.value,
                )
            )
        findings += self.entity_findings(payload.get("entities") or [], endpoint, "registrant", "rdap.holder")
        findings += self.entity_findings(payload.get("entities") or [], endpoint, "abuse", "rdap.abuse")
        return findings

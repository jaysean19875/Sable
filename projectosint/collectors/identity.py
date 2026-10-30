"""Identity presence checks against public profile APIs.

Only endpoints that publish a profile to anonymous clients are used.  Nothing
here authenticates, scrapes behind a login, or enumerates private data: an
absent profile is simply an empty result.
"""

from __future__ import annotations

import asyncio
import hashlib

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register
from .dns import _unquote, query_dns

_USER = frozenset({TargetKind.USERNAME})
_EMAIL = frozenset({TargetKind.EMAIL})
_DOMAIN = frozenset({TargetKind.DOMAIN})


@register(
    CollectorSpec(
        name="github_user",
        category=Category.IDENTITY,
        description="Public GitHub profile facts for a username",
        target_kinds=_USER,
        weight="light",
        lawful_note="GitHub public REST API; unauthenticated rate limit applies.",
    )
)
class GitHubUser(BaseCollector):
    async def collect(self) -> list[Finding]:
        username = self.ctx.target.value
        url = f"https://api.github.com/users/{username}"
        response = await self.ctx.get(url, headers={"Accept": "application/vnd.github+json"})
        if response.status == 404:
            return []
        if not response.ok:
            raise CollectorHttpError(f"GitHub returned HTTP {response.status}", status=response.status)
        data = response.json()
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        findings.append(
            self.finding(
                "identity.github",
                str(data.get("html_url") or url),
                detail=f"GitHub account '{data.get('login')}' created {data.get('created_at', '?')}",
                confidence=Confidence.HIGH,
                tags=("identity", "github"),
                evidence={
                    "public_repos": data.get("public_repos"),
                    "followers": data.get("followers"),
                    "company": data.get("company"),
                },
                endpoint=url,
                query=username,
            )
        )
        for key, kind in (("name", "identity.name"), ("company", "identity.company"),
                          ("blog", "identity.website"), ("location", "identity.location")):
            value = str(data.get(key) or "").strip()
            if value:
                findings.append(
                    self.finding(
                        kind,
                        value,
                        detail=f"self-declared {key}",
                        confidence=Confidence.LOW,
                        tags=("identity", "github"),
                        endpoint=url,
                        query=username,
                    )
                )
        return findings


@register(
    CollectorSpec(
        name="keybase_user",
        category=Category.IDENTITY,
        description="Keybase profile and cryptographic proofs of other accounts",
        target_kinds=_USER,
        weight="light",
        lawful_note="Keybase public lookup API.",
    )
)
class KeybaseUser(BaseCollector):
    async def collect(self) -> list[Finding]:
        username = self.ctx.target.value
        url = "https://keybase.io/_/api/1.0/user/lookup.json"
        data = await self.ctx.get_json(url, params={"username": username, "fields": "basics,proofs"})
        them = ((data or {}).get("them") or [None])[0] if isinstance(data, dict) else None
        if not isinstance(them, dict):
            return []
        findings: list[Finding] = []
        profile = them.get("profile") or {}
        findings.append(
            self.finding(
                "identity.keybase",
                f"https://keybase.io/{username}",
                detail="Keybase profile exists",
                confidence=Confidence.HIGH,
                tags=("identity", "keybase"),
                evidence={"full_name": profile.get("full_name"), "location": profile.get("location")},
                endpoint=url,
                query=username,
            )
        )
        for proof in (them.get("proofs_summary") or {}).get("all") or []:
            platform = str(proof.get("proof_type") or "")
            handle = str(proof.get("nametag") or "")
            if platform and handle:
                findings.append(
                    self.finding(
                        f"identity.proof.{platform}",
                        handle,
                        detail=f"Keybase proof of {platform} account",
                        confidence=Confidence.HIGH,
                        tags=("identity", "proof"),
                        evidence={"url": proof.get("service_url")},
                        endpoint=url,
                        query=username,
                    )
                )
        return findings


@register(
    CollectorSpec(
        name="reddit_user",
        category=Category.IDENTITY,
        description="Public Reddit account age and karma",
        target_kinds=_USER,
        weight="light",
        lawful_note="Reddit public about.json endpoint.",
    )
)
class RedditUser(BaseCollector):
    async def collect(self) -> list[Finding]:
        username = self.ctx.target.value
        url = f"https://www.reddit.com/user/{username}/about.json"
        response = await self.ctx.get(url, headers={"Accept": "application/json"})
        if response.status in {404, 403}:
            return []
        if not response.ok:
            raise CollectorHttpError(f"Reddit returned HTTP {response.status}", status=response.status)
        try:
            payload = response.json()
        except ValueError:
            return []
        data = (payload or {}).get("data") or {}
        if not isinstance(data, dict) or not data.get("name"):
            return []
        created = data.get("created_utc")
        return [
            self.finding(
                "identity.reddit",
                f"https://www.reddit.com/user/{data['name']}",
                detail="Reddit account exists",
                confidence=Confidence.HIGH,
                tags=("identity", "reddit"),
                evidence={
                    "link_karma": data.get("link_karma"),
                    "comment_karma": data.get("comment_karma"),
                    "created_utc": created,
                    "is_employee": data.get("is_employee"),
                },
                endpoint=url,
                query=username,
            )
        ]


@register(
    CollectorSpec(
        name="gravatar",
        category=Category.IDENTITY,
        description="Gravatar profile presence for an email address (hashed lookup)",
        target_kinds=_EMAIL,
        weight="light",
        lawful_note="Gravatar public avatar/profile API; the email is only ever sent as its MD5 hash.",
    )
)
class Gravatar(BaseCollector):
    async def collect(self) -> list[Finding]:
        email = self.ctx.target.value.strip().lower()
        digest = hashlib.md5(email.encode()).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404"
        response = await self.ctx.get(avatar_url)
        if response.status == 404:
            return []
        findings = [
            self.finding(
                "identity.gravatar",
                f"https://www.gravatar.com/{digest}",
                detail="Gravatar profile is registered for this address",
                confidence=Confidence.MEDIUM,
                tags=("identity", "email"),
                endpoint=avatar_url,
                query=digest,
            )
        ]
        try:
            profile = await self.ctx.get_json(f"https://www.gravatar.com/{digest}.json")
        except (CollectorHttpError, ValueError):
            profile = None
        entry = ((profile or {}).get("entry") or [{}])[0] if isinstance(profile, dict) else {}
        for key, kind in (
            ("displayName", "identity.name"),
            ("aboutMe", "identity.bio"),
            ("currentLocation", "identity.location"),
        ):
            value = entry.get(key) if isinstance(entry, dict) else None
            if value:
                findings.append(
                    self.finding(
                        kind,
                        str(value)[:300],
                        detail=f"Gravatar public field: {key}",
                        confidence=Confidence.LOW,
                        tags=("identity", "gravatar"),
                        endpoint=f"https://www.gravatar.com/{digest}.json",
                        query=digest,
                    )
                )
        return findings


@register(
    CollectorSpec(
        name="email_domain",
        category=Category.IDENTITY,
        description="Mail infrastructure for an email's domain (MX, SPF presence)",
        target_kinds=_EMAIL,
        weight="light",
        lawful_note="Public DNS resolution.",
    )
)
class EmailDomain(BaseCollector):
    async def collect(self) -> list[Finding]:
        domain = self.ctx.target.host or self.ctx.target.value.split("@")[-1]
        timeout = self.ctx.settings.http_timeout_s
        mx, spf = await asyncio.gather(
            query_dns(domain, "MX", timeout),
            query_dns(domain, "TXT", timeout),
        )
        findings: list[Finding] = []
        for raw in mx:
            parts = _unquote(raw).split()
            exchange = (parts[1] if len(parts) == 2 else parts[0]).rstrip(".")
            findings.append(
                self.finding(
                    "email.mx",
                    exchange,
                    detail="mail exchanger for the address domain",
                    confidence=Confidence.HIGH,
                    tags=("email", "dns"),
                    endpoint=f"DNS MX {domain}",
                    query=domain,
                )
            )
        if any("v=spf1" in record.lower() for record in spf):
            findings.append(
                self.finding(
                    "email.spf",
                    "present",
                    detail="domain publishes an SPF record",
                    confidence=Confidence.MEDIUM,
                    tags=("email",),
                    endpoint=f"DNS TXT {domain}",
                    query=domain,
                )
            )
        if not mx:
            findings.append(
                self.finding(
                    "email.mx",
                    "none",
                    detail="domain publishes no MX records (cannot receive mail)",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    tags=("email", "dns"),
                    endpoint=f"DNS MX {domain}",
                    query=domain,
                )
            )
        return findings

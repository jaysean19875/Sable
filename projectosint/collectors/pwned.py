"""Have I Been Pwned integration for the Personal Data page.

Two keyless / key-gated layers, chosen for privacy before convenience:

* ``password_breach_count`` uses the Pwned Passwords *range* API with
  k-anonymity: the password never leaves the machine; only the first five
  hex characters of its SHA-1 are sent, and the response is padded so the
  service cannot even infer which suffix was queried.
* ``HibpPastes`` mirrors HIBP's paste index and needs an API key, like the
  breach lookup in ``threat.py``.
"""

from __future__ import annotations

import hashlib

from ..base import BaseCollector, CollectorHttpError
from ..http import OsintClient
from ..models import Category, Confidence, Finding, Severity, TargetKind
from ..registry import CollectorSpec, register

_PWNED_RANGE = "https://api.pwnedpasswords.com/range/"


def password_range_parts(password: str) -> tuple[str, str]:
    """Split a password's SHA-1 into the (sent) prefix and the (kept) suffix."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


async def password_breach_count(client: OsintClient, password: str) -> int | None:
    """Return how many times the password appears in breaches, or None on failure.

    k-anonymity: the password itself is hashed locally and never transmitted;
    only ``prefix`` travels, and ``Add-Padding`` hides even that level of
    detail from network observers.
    """
    prefix, suffix = password_range_parts(password)
    response = await client.get(
        f"{_PWNED_RANGE}{prefix}", headers={"Add-Padding": "true"}
    )
    if response.status == 404:
        raise CollectorHttpError("Pwned Passwords range returned HTTP 404", status=404)
    if not response.ok:
        raise CollectorHttpError(
            f"Pwned Passwords returned HTTP {response.status}", status=response.status
        )
    for line in response.text.splitlines():
        entry, _, count = line.partition(":")
        if entry.strip().upper() == suffix:
            return int(count.strip() or "0")
    return 0


@register(
    CollectorSpec(
        name="hibp_pastes",
        category=Category.EXPOSURE,
        description="Known paste exposure for an email address (Have I Been Pwned)",
        target_kinds=frozenset({TargetKind.EMAIL}),
        requires_key="hibp",
        weight="normal",
        lawful_note="HIBP API with a paid key; no enumeration of paste contents.",
    )
)
class HibpPastes(BaseCollector):
    async def collect(self) -> list[Finding]:
        email = self.ctx.target.value
        key = self.ctx.settings.api_keys.hibp
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        response = await self.ctx.get(
            url,
            headers={"hibp-api-key": key or "", "User-Agent": self.ctx.settings.user_agent},
        )
        if response.status == 404:
            return []
        if not response.ok:
            raise CollectorHttpError(f"HIBP returned HTTP {response.status}", status=response.status)
        pastes = response.json() or []
        findings: list[Finding] = []
        for paste in pastes:
            if not isinstance(paste, dict):
                continue
            findings.append(
                self.finding(
                    "breach.paste",
                    str(paste.get("Source") or "unknown"),
                    detail=(
                        f"paste '{paste.get('Title')}' "
                        f"({paste.get('Date') or 'unknown date'}, "
                        f"{paste.get('EmailCount', '?')} addresses)"
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    tags=("breach", "paste"),
                    evidence={"paste_id": paste.get("Id"), "date": paste.get("Date")},
                    endpoint=url,
                    query=email,
                )
            )
        return findings

"""Target parsing - one place decides what a scan subject *is*.

The collector registry routes on ``TargetKind``, so getting this wrong means
silently skipping half the catalog.  Parsing is deliberately strict: a value
that is not a valid IP, URL, domain or email is treated as a username rather
than being guessed into a domain.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .models import Target, TargetKind

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _as_domain(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return None
    try:
        candidate.encode("idna")
    except UnicodeError:
        return None
    ascii_form = candidate.encode("idna").decode("ascii")
    return ascii_form if _DOMAIN_RE.match(ascii_form) else None


def parse_target(value: str) -> Target:
    """Classify a raw subject string into a validated :class:`Target`."""
    raw = (value or "").strip()
    if not raw:
        raise ValueError("target must not be empty")

    if "://" in raw:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if not host:
            raise ValueError(f"URL has no host: {raw!r}")
        scheme = (parts.scheme or "https").lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"unsupported URL scheme: {scheme!r}")
        netloc = parts.netloc
        path = parts.path or "/"
        normalised = f"{scheme}://{netloc}{path}"
        if parts.query:
            normalised += f"?{parts.query}"
        return Target(kind=TargetKind.URL, value=normalised, host=host.lower())

    if _is_ip(raw):
        return Target(kind=TargetKind.IP, value=str(ipaddress.ip_address(raw)), host=raw)

    email = _EMAIL_RE.match(raw)
    if email:
        domain = _as_domain(email.group(1))
        if domain:
            return Target(kind=TargetKind.EMAIL, value=raw.lower(), host=domain)

    domain = _as_domain(raw)
    if domain:
        return Target(kind=TargetKind.DOMAIN, value=domain, host=domain)

    if _USER_RE.match(raw):
        return Target(kind=TargetKind.USERNAME, value=raw.lower(), host=None)

    raise ValueError(f"cannot classify target: {raw!r}")


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without a Public Suffix List dependency.

    Good enough for grouping (``a.b.example.co.uk`` -> ``example.co.uk``);
    multi-part suffixes beyond two labels are handled for the common ccTLD
    second-level set.
    """
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}
    if len(labels) >= 3 and labels[-2] in two_level and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

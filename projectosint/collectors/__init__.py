"""Collector package.

Importing this package is what populates the registry.  Order matters only in
that ``dns`` is imported first so DNS helpers exist before modules that reuse
them; the rest is alphabetical for reviewability.
"""

from __future__ import annotations

from . import (
    crtsh,
    identity,
    ip,
    rdap,
    search,
    threat,
    tls,
    wayback,
    web,
    whois,
)
from . import dns as _dns  # noqa: F401  (helpers consumed by ip/identity)

__all__ = [
    "crtsh",
    "dns",
    "identity",
    "ip",
    "rdap",
    "search",
    "threat",
    "tls",
    "wayback",
    "web",
    "whois",
]

"""Search-engine dorking - deliberately opt-in.

Search engines' terms of service vary on automated querying; rather than ship
a source whose legality depends on jurisdiction and volume, this adapter is
``default_enabled=False`` and must be enabled explicitly.  It still respects
robots-style pacing via the shared token bucket.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from ..base import BaseCollector
from ..models import Category, Confidence, Finding, TargetKind
from ..registry import CollectorSpec, register

DDG_HTML = "https://html.duckduckgo.com/html/"


@register(
    CollectorSpec(
        name="search_ddg",
        category=Category.SEARCH,
        description="site: dork results via DuckDuckGo HTML endpoint (opt-in, ToS-sensitive)",
        target_kinds=frozenset({TargetKind.DOMAIN}),
        default_enabled=False,
        weight="normal",
        lawful_note=(
            "Disabled by default: automated search queries may violate engine ToS. "
            "Enable deliberately and keep volume low."
        ),
        tags=("dork",),
    )
)
class DuckDuckGoDork(BaseCollector):
    async def collect(self) -> list[Finding]:
        host = self.ctx.target.host or self.ctx.target.value
        response = await self.ctx.get(
            DDG_HTML,
            params={"q": f"site:{host}"},
            headers={"Accept": "text/html"},
        )
        if not response.ok:
            return []
        soup = BeautifulSoup(response.text[:800_000], "html.parser")
        findings: list[Finding] = []
        for anchor in soup.select("a.result__a")[:30]:
            href = str(anchor.get("href") or "")
            title = anchor.get_text(" ", strip=True)[:200]
            if not href:
                continue
            findings.append(
                self.finding(
                    "search.result",
                    href,
                    detail=title or "indexed page",
                    confidence=Confidence.LOW,
                    tags=("search", "dork"),
                    endpoint=DDG_HTML,
                    query=f"site:{host}",
                )
            )
        return findings

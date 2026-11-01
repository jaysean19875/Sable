"""The collector contract.

Adapters are small, side-effect-free-of-I/O-state classes: construct with a
context, return findings, never raise for a source-specific failure (the
scheduler turns that into ``status=error`` while its siblings keep running).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from .config import Settings
from .http import HttpResult, OsintClient
from .logging_setup import get_logger
from .models import Category, Confidence, Finding, Provenance, Severity, Target
from .registry import CollectorSpec


@dataclass
class CollectorContext:
    """Per-scan dependencies handed to every adapter."""

    settings: Settings
    client: OsintClient
    target: Target
    scan_id: str
    calls: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        self.calls += 1
        return await self.client.get(url, params=params, headers=headers)

    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        result = await self.get(url, params=params, headers=headers)
        if not result.ok:
            raise CollectorHttpError(f"HTTP {result.status} for {result.url}", status=result.status)
        return result.json()

    async def get_text(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        result = await self.get(url, params=params, headers=headers)
        if not result.ok:
            raise CollectorHttpError(f"HTTP {result.status} for {result.url}", status=result.status)
        return result

    async def post_json(
        self,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """POST a JSON body through the shared (rate limited) client."""
        self.calls += 1
        response = await self.client.client.post(url, json=json_body, headers=headers)
        if not response.is_success:
            raise CollectorHttpError(f"HTTP {response.status_code} for {url}", status=response.status_code)
        return response.json()


class CollectorHttpError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class BaseCollector(ABC):
    """Base class for all source adapters."""

    spec: ClassVar[CollectorSpec]

    def __init__(self, ctx: CollectorContext) -> None:
        self.ctx = ctx
        self.log = get_logger(f"source.{self.spec.name}")

    @property
    def source(self) -> str:
        return self.spec.name

    @abstractmethod
    async def collect(self) -> list[Finding]:
        """Perform the lookup and return findings. May raise on hard failure."""

    # -- helpers ---------------------------------------------------------
    def provenance(self, *, endpoint: str | None = None, query: str | None = None) -> Provenance:
        return Provenance(
            source=self.spec.name,
            category=self.spec.category,
            endpoint=endpoint,
            query=query,
            terms=self.spec.lawful_note or None,
        )

    def finding(
        self,
        kind: str,
        value: str,
        *,
        detail: str = "",
        severity: Severity = Severity.INFO,
        confidence: Confidence = Confidence.MEDIUM,
        tags: tuple[str, ...] | list[str] = (),
        evidence: dict[str, Any] | None = None,
        endpoint: str | None = None,
        query: str | None = None,
    ) -> Finding:
        return Finding.build(
            source=self.spec.name,
            category=self.spec.category,
            kind=kind,
            value=value,
            detail=detail,
            severity=severity,
            confidence=confidence,
            tags=tags,
            evidence=evidence,
            provenance=self.provenance(endpoint=endpoint, query=query),
        )

    def category(self) -> Category:
        return self.spec.category

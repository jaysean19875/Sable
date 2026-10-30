"""Shared HTTP layer: one AsyncClient, bounded retries, no adapter-level httpx.

Keeping every request behind this module gives three guarantees the spec asks
for and that are easy to lose when adapters hand-roll their own clients:
connection pooling, a single honest user agent, and retries that respect
``Retry-After`` instead of hammering a struggling host.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Settings
from .logging_setup import get_logger
from .ratelimit import RateLimiter

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_BODY_BYTES = 4_000_000


class HttpError(RuntimeError):
    """Raised when a request exhausts its retry budget."""

    def __init__(self, message: str, *, status: int | None = None, url: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.url = url


@dataclass(slots=True)
class HttpResult:
    status: int
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 0.0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        import json

        return json.loads(self.text)

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


class OsintClient:
    """Thin, rate-limited wrapper around ``httpx.AsyncClient``."""

    def __init__(self, settings: Settings, limiter: RateLimiter | None = None) -> None:
        self.settings = settings
        self.limiter = limiter or RateLimiter(settings.rate_limit)
        self._client: httpx.AsyncClient | None = None
        self._log = get_logger("http")
        self.calls = 0

    async def __aenter__(self) -> OsintClient:
        self._client = httpx.AsyncClient(
            follow_redirects=self.settings.follow_redirects,
            verify=self.settings.verify_tls,
            timeout=httpx.Timeout(self.settings.http_timeout_s),
            headers={
                "User-Agent": self.settings.user_agent,
                "Accept": "*/*",
                "Accept-Language": "en",
            },
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("OsintClient used outside its context manager")
        return self._client

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        last: HttpError | None = None
        for attempt in range(self.settings.retries + 1):
            await self.limiter.acquire(url)
            started = time.perf_counter()
            self.calls += 1
            try:
                response = await self.client.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:  # transport, timeout, TLS...
                last = HttpError(f"{type(exc).__name__}: {exc}", url=url)
                if attempt >= self.settings.retries:
                    raise last from exc
                await asyncio.sleep(min(0.25 * 2**attempt, 2.0))
                continue

            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            if response.status_code in RETRY_STATUS and attempt < self.settings.retries:
                delay = _retry_delay(response) or min(0.25 * 2**attempt, 2.0)
                self._log.debug("retry {s} {u} in {d}s", s=response.status_code, u=url, d=delay)
                await asyncio.sleep(min(delay, 5.0))
                continue

            body = response.text
            truncated = len(body) > MAX_BODY_BYTES
            if truncated:
                body = body[:MAX_BODY_BYTES]
            return HttpResult(
                status=response.status_code,
                url=str(response.url),
                headers=dict(response.headers),
                text=body,
                elapsed_ms=elapsed_ms,
                truncated=truncated,
            )
        raise last or HttpError("unreachable", url=url)


def _retry_delay(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None

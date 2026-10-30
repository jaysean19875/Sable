"""SQLite-backed result cache.

Keyed by (schema, target, source) so a repeat scan of the same subject is
served from disk in milliseconds while a different subject never collides.
TTL is enforced on read, so expiry needs no background job.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import aiosqlite

from .models import SCHEMA_VERSION, CollectorResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS result_cache (
    key        TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_created ON result_cache(created_at);
"""


class ResultCache:
    def __init__(self, path: str | Path, ttl_s: float = 3600) -> None:
        self.path = str(path)
        self.ttl_s = ttl_s
        self._db: aiosqlite.Connection | None = None

    @property
    def enabled(self) -> bool:
        return self.ttl_s > 0

    async def open(self) -> ResultCache:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        return self

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> ResultCache:
        return await self.open()

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    @staticmethod
    def make_key(target: str, source: str) -> str:
        raw = f"v{SCHEMA_VERSION}|{target}|{source}".encode()
        return hashlib.sha1(raw).hexdigest()

    async def get(self, key: str) -> CollectorResult | None:
        if not self.enabled or self._db is None:
            return None
        cursor = await self._db.execute(
            "SELECT payload, created_at FROM result_cache WHERE key = ?", (key,)
        )
        row = await cursor.fetchone()
        await cursor.close()
        if row is None:
            return None
        if self.ttl_s and (time.time() - float(row["created_at"])) > self.ttl_s:
            await self._db.execute("DELETE FROM result_cache WHERE key = ?", (key,))
            await self._db.commit()
            return None
        try:
            result = CollectorResult.model_validate_json(row["payload"])
        except ValueError:  # stale schema in the cache is a miss, not a crash
            return None
        return result.model_copy(update={"from_cache": True})

    async def put(self, key: str, result: CollectorResult) -> None:
        if not self.enabled or self._db is None:
            return
        payload = result.model_copy(update={"from_cache": False}).model_dump_json()
        await self._db.execute(
            "INSERT OR REPLACE INTO result_cache(key, payload, created_at) VALUES (?, ?, ?)",
            (key, payload, time.time()),
        )
        await self._db.commit()

    async def purge_expired(self) -> int:
        if self._db is None or not self.enabled:
            return 0
        cutoff = time.time() - self.ttl_s
        cursor = await self._db.execute("DELETE FROM result_cache WHERE created_at < ?", (cutoff,))
        await self._db.commit()
        return cursor.rowcount or 0

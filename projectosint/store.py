"""SQLite persistence: one scan report, plus a queryable findings table.

The full report is stored as JSON (lossless, schema-versioned) *and* exploded
into a findings table so the UI and exports can filter without re-parsing
every report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

from .models import ScanReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    target_kind    TEXT NOT NULL,
    target_value   TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    duration_ms    REAL NOT NULL DEFAULT 0,
    deadline_s     REAL NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    sources_total  INTEGER NOT NULL DEFAULT 0,
    report_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id        TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id     TEXT NOT NULL,
    source         TEXT NOT NULL,
    category       TEXT NOT NULL,
    kind           TEXT NOT NULL,
    value          TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id, source)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_kind, target_value);
"""


class Store:
    def __init__(self, path: str | Path = "data/osint.db") -> None:
        self.path = str(path)
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> Store:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        return self

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> Store:
        return await self.open()

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Store used outside its context manager")
        return self._db

    # ------------------------------------------------------------------
    async def save(self, report: ScanReport) -> None:
        payload = report.model_dump_json()
        await self.db.execute("DELETE FROM findings WHERE scan_id = ?", (report.scan_id,))
        await self.db.execute(
            """
            INSERT OR REPLACE INTO scans
                (scan_id, target_kind, target_value, started_at, finished_at, duration_ms,
                 deadline_s, findings_total, sources_total, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.scan_id,
                report.target.kind.value,
                report.target.value,
                report.started_at.isoformat(),
                report.finished_at.isoformat() if report.finished_at else None,
                report.duration_ms,
                report.deadline_s,
                report.stats.total_findings,
                report.stats.sources_total,
                payload,
            ),
        )
        await self.db.executemany(
            """
            INSERT OR REPLACE INTO findings
                (scan_id, finding_id, source, category, kind, value, detail, severity,
                 confidence, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    report.scan_id,
                    finding.id,
                    finding.source,
                    finding.category.value,
                    finding.kind,
                    finding.value,
                    finding.detail,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.provenance.retrieved_at.isoformat(),
                )
                for finding in report.findings
            ],
        )
        await self.db.commit()

    async def get(self, scan_id: str) -> ScanReport | None:
        cursor = await self.db.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        await cursor.close()
        if row is None:
            return None
        return ScanReport.model_validate(json.loads(row["report_json"]))

    async def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            """
            SELECT scan_id, target_kind, target_value, started_at, duration_ms,
                   findings_total, sources_total
            FROM scans ORDER BY started_at DESC LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def findings(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        source: str | None = None,
        category: str | None = None,
        query: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings WHERE scan_id = ?"
        args: list[Any] = [scan_id]
        for column, value in (("severity", severity), ("source", source), ("category", category)):
            if value:
                sql += f" AND {column} = ?"
                args.append(value)
        if query:
            sql += " AND (value LIKE ? OR detail LIKE ? OR kind LIKE ?)"
            args.extend([f"%{query}%"] * 3)
        sql += " LIMIT ?"
        args.append(limit)
        cursor = await self.db.execute(sql, args)
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def stats(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for label, sql in (
            ("scans", "SELECT COUNT(*) AS n FROM scans"),
            ("findings", "SELECT COUNT(*) AS n FROM findings"),
        ):
            cursor = await self.db.execute(sql)
            row = await cursor.fetchone()
            await cursor.close()
            out[label] = int(row["n"]) if row else 0
        cursor = await self.db.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity ORDER BY n DESC"
        )
        rows = await cursor.fetchall()
        await cursor.close()
        out["by_severity"] = {row["severity"]: int(row["n"]) for row in rows}
        return out

    async def delete(self, scan_id: str) -> bool:
        cursor = await self.db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await self.db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        await self.db.commit()
        return (cursor.rowcount or 0) > 0

"""Command-line interface.

    python -m projectosint scan example.com
    python -m projectosint sources
    python -m projectosint serve --port 8080

The CLI is deliberately thin: it parses, delegates to the engine, renders.
Business logic lives in the engine so the API and the CLI cannot drift.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from . import __version__
from .cache import ResultCache
from .config import Settings, load_settings
from .export import write_report
from .logging_setup import setup_logging
from .models import Category, ScanReport
from .scheduler import ScanEngine
from .store import Store

_SEVERITY_COLOUR = {
    "critical": "\033[1;91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[90m",
}
_STATUS_MARK = {"ok": "ok  ", "cached": "cache", "partial": "part", "timeout": "tmout",
                "error": "err ", "skipped": "skip"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _colour_enabled(stream: object = sys.stdout) -> bool:
    return (
        hasattr(stream, "isatty")
        and stream.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="projectosint",
        description="Bounded, provenance-rich OSINT collection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m projectosint scan example.com --json out/report.json --pdf out/report.pdf\n"
            "  python -m projectosint scan 8.8.8.8 --categories infrastructure,registration\n"
            "  python -m projectosint sources\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"ProjectOSINT {__version__}")
    parser.add_argument("--config", type=Path, default=None, help="path to config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one target across the collector catalog")
    scan.add_argument("target", help="domain, IP, URL, email or username")
    scan.add_argument("--deadline", type=float, default=None, help="global deadline in seconds")
    scan.add_argument("--sources", default=None, help="comma-separated collector names")
    scan.add_argument("--categories", default=None, help="comma-separated categories")
    scan.add_argument("--exclude", default=None, help="comma-separated collector names to skip")
    scan.add_argument("--json", dest="json_path", default=None, help="write full report JSON")
    scan.add_argument("--csv", dest="csv_path", default=None, help="write findings CSV")
    scan.add_argument("--pdf", dest="pdf_path", default=None, help="write PDF report")
    scan.add_argument("--out", dest="out_dir", default=None, help="directory for default export paths")
    scan.add_argument("--no-cache", action="store_true", help="ignore and do not populate the cache")
    scan.add_argument("--no-store", action="store_true", help="do not persist the scan to SQLite")
    scan.add_argument("--format", choices=("table", "json"), default="table", help="stdout format")
    scan.add_argument("--limit", type=int, default=200, help="max findings printed to stdout")
    scan.add_argument("--quiet", action="store_true", help="suppress per-source progress lines")

    sub.add_parser("sources", help="list the collector catalog")
    sub.add_parser("stats", help="show stored scan statistics")
    cache_parser = sub.add_parser("cache", help="cache maintenance")
    cache_parser.add_argument("action", choices=("purge",), help="cache action")
    sub.add_parser("desktop", help="launch the native desktop app (requires PySide6)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    setup_logging(settings.log_level, json_logs=settings.log_json, log_dir=settings.data_dir / "logs")
    # The desktop app owns the main thread and its Qt event loop; it must not
    # be entered from inside asyncio.run.
    if args.command == "desktop":
        return _desktop(args, settings)
    try:
        return asyncio.run(_dispatch(args, settings))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


async def _dispatch(args: argparse.Namespace, settings: Settings) -> int:
    if args.command == "scan":
        return await _scan(args, settings)
    if args.command == "sources":
        return _sources()
    if args.command == "stats":
        return await _stats(settings)
    if args.command == "cache":
        return await _cache(args, settings)
    return 2


# ----------------------------------------------------------------------
async def _scan(args: argparse.Namespace, settings: Settings) -> int:
    paint = Painter(_colour_enabled())
    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    json_path = Path(args.json_path) if args.json_path else (out_dir / "report.json" if out_dir else None)
    csv_path = Path(args.csv_path) if args.csv_path else (out_dir / "findings.csv" if out_dir else None)
    pdf_path = Path(args.pdf_path) if args.pdf_path else (out_dir / "report.pdf" if out_dir else None)

    sources = _split(args.sources)
    categories = _categories(args.categories)
    excluded = set(_split(args.exclude) or [])

    def on_event(event: str, payload: dict) -> None:
        if args.quiet or args.format != "table":
            return
        if event == "source_done":
            mark = _STATUS_MARK.get(str(payload.get("status")), "?")
            extra = payload.get("error") or payload.get("note") or ""
            print(
                f"  {paint.wrap(_DIM, mark)} {payload.get('source', ''):<20} "
                f"{payload.get('count', 0):>4} findings {payload.get('duration_ms', 0):>7.0f} ms"
                + (f"  {paint.wrap(_DIM, str(extra)[:60])}" if extra else ""),
                flush=True,
            )

    cache = None
    if not args.no_cache and settings.cache_ttl_s > 0:
        cache = await ResultCache(settings.data_dir / "cache.db", settings.cache_ttl_s).open()
    try:
        engine = ScanEngine(settings, cache=cache, on_event=on_event)
        if not args.quiet and args.format == "table":
            print(
                paint.wrap(_BOLD, f"ProjectOSINT {__version__}")
                + f"  |  target {args.target}  |  deadline {args.deadline or settings.deadline_s:g}s"
            )
        report = await engine.scan(
            args.target,
            deadline_s=args.deadline,
            sources=[s for s in (sources or []) if s not in excluded] or None,
            categories=categories,
            use_cache=not args.no_cache,
        )
    finally:
        if cache is not None:
            await cache.close()

    if not args.no_store:
        try:
            async with Store(settings.db_path) as store:
                await store.save(report)
        except Exception as exc:  # persistence must not lose the report
            print(f"warning: could not persist scan: {exc}", file=sys.stderr)

    written = write_report(
        report,
        json_path=str(json_path) if json_path else None,
        csv_path=str(csv_path) if csv_path else None,
        pdf_path=str(pdf_path) if pdf_path else None,
    )

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    else:
        _render_report(report, paint, limit=args.limit)
        for path in written:
            print(f"  wrote {path}")
    return 0


def _render_report(report: ScanReport, paint: Painter, *, limit: int) -> None:
    stats = report.stats
    print()
    print(
        paint.wrap(_BOLD, "summary")
        + f"   {stats.total_findings} findings  |  {stats.sources_total} sources  |  "
        f"{report.duration_ms:.0f} ms  |  "
        + ", ".join(f"{k}={v}" for k, v in stats.by_status.items())
    )
    if report.notes:
        for note in report.notes:
            print(f"  {paint.wrap(_DIM, 'note')} {note}")
    print()
    if report.findings:
        print(paint.wrap(_BOLD, "findings"))
        for finding in report.findings[:limit]:
            colour = _SEVERITY_COLOUR.get(finding.severity.value, "")
            print(
                f"  {paint.wrap(colour, f'{finding.severity.value:<8}')}"
                f"{finding.source:<20}{finding.kind:<26}"
                f"{finding.value[:64]:<66}{paint.wrap(_DIM, finding.detail[:60])}"
            )
        if len(report.findings) > limit:
            print(f"  {paint.wrap(_DIM, f'... {len(report.findings) - limit} more (use --json/--csv)')}")
    else:
        print(paint.wrap(_DIM, "no findings"))


def _sources() -> int:
    from . import (
        collectors,  # noqa: F401  (populate registry)
        registry,
    )

    specs = sorted(registry.all_specs(), key=lambda s: (s.category.value, s.name))
    print(f"{'source':<22}{'category':<15}{'kinds':<22}{'weight':<8}{'key':<12}default")
    for spec in specs:
        kinds = ",".join(sorted(k.value for k in spec.target_kinds))
        print(
            f"{spec.name:<22}{spec.category.value:<15}{kinds:<22}{spec.weight:<8}"
            f"{(spec.requires_key or '-'):<12}{'yes' if spec.default_enabled else 'opt-in'}"
        )
    print(f"\n{len(specs)} collectors")
    return 0


async def _stats(settings: Settings) -> int:
    async with Store(settings.db_path) as store:
        stats = await store.stats()
        scans = await store.list_scans(limit=10)
    print(f"scans={stats['scans']} findings={stats['findings']}")
    if stats["by_severity"]:
        print("severity: " + ", ".join(f"{k}={v}" for k, v in stats["by_severity"].items()))
    for scan in scans:
        print(
            f"  {scan['scan_id']}  {scan['target_kind']}:{scan['target_value']}  "
            f"{scan['findings_total']} findings  {scan['started_at']}"
        )
    return 0


async def _cache(args: argparse.Namespace, settings: Settings) -> int:
    async with ResultCache(settings.data_dir / "cache.db", settings.cache_ttl_s) as cache:
        removed = await cache.purge_expired()
    print(f"purged {removed} expired cache row(s)")
    return 0


def _desktop(args: argparse.Namespace, settings: Settings) -> int:
    try:
        from .desktop import main as desktop_main
    except ImportError as exc:
        if "PySide6" in str(exc):
            print(
                "The desktop app needs PySide6. Install it into the venv with:\n"
                '  .venv\\Scripts\\python.exe -m pip install "PySide6-Essentials>=6.7,<7"',
                file=sys.stderr,
            )
            return 1
        raise
    return desktop_main(settings=settings)


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


def _categories(value: str | None) -> list[Category] | None:
    raw = _split(value)
    if not raw:
        return None
    valid = {c.value for c in Category}
    invalid = [c for c in raw if c not in valid]
    if invalid:
        raise SystemExit(f"unknown categories: {', '.join(invalid)} (valid: {', '.join(sorted(valid))})")
    return [Category(c) for c in raw]


if __name__ == "__main__":
    raise SystemExit(main())

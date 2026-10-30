"""Structured logging (loguru) with an optional JSON sink.

Console stays human-readable; ``data/logs/osint.jsonl`` is machine-readable
and is what an operator greps when they need to prove which endpoints were
queried during a scan.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from loguru import logger

_CONFIGURED = False


def setup_logging(level: str = "INFO", *, json_logs: bool = True, log_dir: Path | None = None) -> None:
    """Idempotent logging bootstrap for a process."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    configure_logging(level, json_logs=json_logs, log_dir=log_dir)
    _CONFIGURED = True


def configure_logging(
    level: str = "INFO", *, json_logs: bool = True, log_dir: Path | None = None
) -> None:
    """(Re)configure sinks unconditionally - also the seam the tests exercise.

    A ``--windowed`` PyInstaller build has ``sys.stderr is None``; adding a
    sink for it raises ``TypeError: Cannot log to objects of type 'NoneType'``.
    Guard every console sink so frozen builds fall back to the file log.
    """
    logger.remove()
    if sys.stderr is not None:
        logger.add(
            sys.stderr,
            level=level,
            colorize=True,
            format=(
                "<green>{time:HH:mm:ss.SSS}</green> | <level>{level: <7}</level> | "
                "<cyan>{extra[component]}</cyan> | <level>{message}</level>"
            ),
            filter=_ensure_component,
        )
    if json_logs:
        directory = log_dir or Path("data") / "logs"
        directory.mkdir(parents=True, exist_ok=True)
        logger.add(
            directory / "osint.jsonl",
            level=level,
            serialize=True,
            rotation="10 MB",
            retention=5,
            enqueue=False,
            filter=_ensure_component,
        )
    logger.configure(extra={"component": "core"})


def _ensure_component(record: Any) -> bool:
    """loguru filters may not bind defaults; keep the console format valid."""
    extra = record.setdefault("extra", {})
    if isinstance(extra, dict):
        extra.setdefault("component", "core")
    return True


def get_logger(component: str) -> Any:
    return logger.bind(component=component)

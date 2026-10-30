"""Structured logging: the JSON sink must be machine-readable and attributable."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from projectosint.logging_setup import configure_logging, get_logger


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_json_sink_writes_structured_records(tmp_path: Path) -> None:
    configure_logging("DEBUG", json_logs=True, log_dir=tmp_path)
    get_logger("unit").info("scanned {target}", target="example.com")

    path = tmp_path / "osint.jsonl"
    assert path.is_file()
    record = _records(path)[-1]["record"]
    assert record["message"] == "scanned example.com"
    assert record["extra"]["component"] == "unit"
    assert record["level"]["name"] == "INFO"
    assert record["time"]["timestamp"] > 0


def test_console_only_mode_writes_no_file(tmp_path: Path) -> None:
    configure_logging("DEBUG", json_logs=False, log_dir=tmp_path)
    get_logger("unit").info("console only")
    assert not (tmp_path / "osint.jsonl").exists()


def test_windowed_bundle_without_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PyInstaller --windowed sets sys.stderr to None; logging must not crash."""
    monkeypatch.setattr(sys, "stderr", None)
    configure_logging("INFO", json_logs=True, log_dir=tmp_path)
    get_logger("unit").info("still works")

    record = _records(tmp_path / "osint.jsonl")[-1]["record"]
    assert record["message"] == "still works"

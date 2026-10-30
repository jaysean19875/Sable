"""CLI surface: parsing, category validation, the scan path end to end."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from projectosint import cli
from projectosint.models import Category


def test_parser_defaults() -> None:
    args = cli.build_parser().parse_args(["scan", "example.com"])
    assert args.command == "scan"
    assert args.target == "example.com"
    assert args.limit == 200
    assert args.no_cache is False


def test_unknown_category_exits() -> None:
    with pytest.raises(SystemExit):
        cli._categories("dns,bogus")


def test_categories_parsed() -> None:
    parsed = cli._categories("dns,certificates")
    assert parsed == [Category.DNS, Category.CERTIFICATES]


def test_sources_listing(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli._sources() == 0
    output = capsys.readouterr().out
    assert "dns_a" in output
    assert "collectors" in output


def test_version_flag_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0


def test_desktop_dispatched_without_running_loop(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    """Qt owns the main thread: dispatching desktop inside asyncio.run would crash."""
    seen: dict[str, bool] = {}

    def fake_desktop(_args, _settings) -> int:
        seen["hit"] = True
        return 7

    monkeypatch.setattr(cli, "load_settings", lambda _path: settings)
    monkeypatch.setattr(cli, "_desktop", fake_desktop)
    assert cli.main(["desktop"]) == 7
    assert seen["hit"] is True


def test_parser_accepts_desktop() -> None:
    args = cli.build_parser().parse_args(["desktop"])
    assert args.command == "desktop"


def test_scan_command_writes_json(settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the real CLI path with a stub engine (no network)."""

    class StubEngine:
        def __init__(self, settings, *, cache=None, on_event=None) -> None:
            self.on_event = on_event

        async def scan(self, target, **_kwargs):
            from projectosint.models import ScanReport
            from projectosint.targets import parse_target

            report = ScanReport(target=parse_target(str(target)), scan_id="cli000000001")
            report.finalise()
            return report

    monkeypatch.setattr(cli, "ScanEngine", StubEngine)
    monkeypatch.setattr(cli, "load_settings", lambda _path: settings.model_copy(
        update={"data_dir": tmp_path / "data", "database": str(tmp_path / "data" / "osint.db")}
    ))
    output = tmp_path / "report.json"
    args = cli.build_parser().parse_args(["scan", "example.com", "--no-store", "--json", str(output)])
    code = asyncio.run(cli._scan(args, settings.model_copy(
        update={"data_dir": tmp_path / "data", "database": str(tmp_path / "data" / "osint.db")}
    )))
    assert code == 0
    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["target"]["value"] == "example.com"

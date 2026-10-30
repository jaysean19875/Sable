"""Configuration precedence: environment > YAML > field defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from projectosint.config import Settings, load_settings


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(__import__("os").environ):
        if key.startswith("OSINT_"):
            monkeypatch.delenv(key)
    settings = Settings()
    assert settings.deadline_s == 10.0
    assert settings.concurrency == 12
    assert settings.api_keys.shodan is None


def test_yaml_overrides_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "deadline_s: 7.5\nconcurrency: 4\nrate_limit:\n  default_rps: 2.5\n", encoding="utf-8"
    )
    settings = load_settings()
    assert settings.deadline_s == 7.5
    assert settings.concurrency == 4
    assert settings.rate_limit.default_rps == 2.5


def test_env_beats_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("deadline_s: 7.5\n", encoding="utf-8")
    monkeypatch.setenv("OSINT_DEADLINE_S", "42")
    assert load_settings(config).deadline_s == 42.0


def test_nested_env_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("api_keys:\n  shodan: null\n", encoding="utf-8")
    monkeypatch.setenv("OSINT_API_KEYS__SHODAN", "secret-key")
    settings = load_settings(config)
    assert settings.api_keys.shodan == "secret-key"


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValueError, match="log_level"):
        Settings(log_level="LOUD")


def test_rate_limit_bounds() -> None:
    with pytest.raises(ValueError):
        Settings(rate_limit={"default_rps": 0})

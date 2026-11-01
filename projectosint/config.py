"""Configuration: YAML for defaults, environment/.env for secrets.

Precedence is explicit and tested: environment variable > config.yaml >
field default.  Secrets belong in ``.env`` (never in the YAML that gets
committed).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "OSINT_"


class ApiKeys(BaseModel):
    """Optional credentials. A source with a missing key reports ``skipped``."""

    shodan: str | None = None
    hibp: str | None = None
    urlscan: str | None = None
    virustotal: str | None = None
    github: str | None = None

    def get(self, name: str) -> str | None:
        return getattr(self, name, None)


class RateLimitConfig(BaseModel):
    """Per-host token buckets. ``per_host`` overrides the default rps."""

    default_rps: float = Field(default=1.0, gt=0.0, le=50.0)
    burst: int = Field(default=2, ge=1, le=50)
    per_host: dict[str, float] = Field(default_factory=dict)


class Settings(BaseSettings):
    """Runtime configuration for a scan run or a server process."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # execution envelope
    deadline_s: float = Field(default=10.0, gt=0.0, le=300.0)
    source_timeout_s: float = Field(default=8.0, gt=0.0, le=300.0)
    concurrency: int = Field(default=12, ge=1, le=64)
    max_findings_per_source: int = Field(default=200, ge=1, le=5000)

    # storage / cache
    data_dir: Path = Path("data")
    database: str = "data/osint.db"
    cache_ttl_s: int = Field(default=3600, ge=0)

    # http
    user_agent: str = "ProjectOSINT/0.1 (authorised reconnaissance)"
    follow_redirects: bool = True
    verify_tls: bool = True
    respect_robots: bool = True
    http_timeout_s: float = Field(default=8.0, gt=0.0, le=120.0)
    retries: int = Field(default=2, ge=0, le=5)

    # logging
    log_level: str = "INFO"
    log_json: bool = True

    # sources
    disabled_sources: list[str] = Field(default_factory=list)
    enabled_categories: list[str] = Field(default_factory=list)
    personal_max_sources: int = Field(default=45, ge=1, le=200)

    # probe bot (OpenAI-compatible chat API; unset key = offline FAQ mode)
    probe_bot_base_url: str = "https://api.deepseek.com"
    probe_bot_api_key: str | None = None
    probe_bot_model: str = "deepseek-chat"

    api_keys: ApiKeys = Field(default_factory=ApiKeys)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        allowed = {"TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"}
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return v

    @property
    def db_path(self) -> Path:
        return Path(self.database)

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


def _coerce(raw: str) -> Any:
    """Treat env strings as YAML scalars so 'false'/'10'/'[a,b]' behave."""
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError:
        return raw


def _env_overrides() -> dict[str, Any]:
    """Collect ``OSINT_*`` variables, handling one level of ``__`` nesting."""
    out: dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        path = key[len(ENV_PREFIX) :].lower().split("__")
        cursor = out
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = _coerce(value)
    return out


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings(path: str | Path | None = None) -> Settings:
    """Load YAML defaults, then apply environment overrides."""
    data: dict[str, Any] = {}
    config_path = Path(path) if path else Path("config.yaml")
    if config_path.is_file():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{config_path} must contain a mapping at top level")
        data = loaded
    data = _deep_merge(data, _env_overrides())
    return Settings(**data)

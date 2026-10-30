"""Web layer: FastAPI application and static dashboard assets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

    from ..config import Settings

__all__ = ["create_app"]


def create_app(settings: Settings | None = None, **kwargs: Any) -> FastAPI:
    from .app import create_app as _create

    return _create(settings, **kwargs)

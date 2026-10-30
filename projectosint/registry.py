"""Collector catalog.

A collector advertises itself once, declaratively, and the registry is the
single source of truth for the CLI, the API, the UI and the docs.  Adding a
source is therefore a one-file change plus an import, with no wiring edits.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .models import Category, TargetKind

T = TypeVar("T", bound=type)

_WEIGHTS = ("light", "normal", "heavy")


@dataclass(frozen=True, slots=True)
class CollectorSpec:
    """Everything the platform needs to know about a source before calling it."""

    name: str
    category: Category
    description: str
    target_kinds: frozenset[TargetKind]
    requires_key: str | None = None
    lawful_note: str = ""
    default_enabled: bool = True
    weight: str = "normal"
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").isalnum():
            raise ValueError(f"invalid collector name: {self.name!r}")
        if self.weight not in _WEIGHTS:
            raise ValueError(f"{self.name}: weight must be one of {_WEIGHTS}")
        if not self.target_kinds:
            raise ValueError(f"{self.name}: at least one target kind is required")

    def supports(self, kind: TargetKind) -> bool:
        return kind in self.target_kinds

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "target_kinds": sorted(k.value for k in self.target_kinds),
            "requires_key": self.requires_key,
            "default_enabled": self.default_enabled,
            "weight": self.weight,
            "lawful_note": self.lawful_note,
            "tags": list(self.tags),
        }


_REGISTRY: dict[str, type[Any]] = {}


def register(spec: CollectorSpec) -> Callable[[T], T]:
    """Class decorator binding an adapter to its catalog entry."""

    def decorator(cls: T) -> T:
        if spec.name in _REGISTRY:
            raise ValueError(f"duplicate collector name: {spec.name}")
        if not hasattr(cls, "collect"):
            raise TypeError(f"{cls.__name__} must implement 'collect'")
        cls.spec = spec  # type: ignore[attr-defined]
        _REGISTRY[spec.name] = cls
        return cls

    return decorator


def all_specs() -> list[CollectorSpec]:
    return [cls.spec for cls in _REGISTRY.values()]


def names() -> list[str]:
    return sorted(_REGISTRY)


def get_class(name: str) -> type[Any]:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"unknown collector {name!r}; known: {', '.join(names())}") from exc


def select(
    *,
    kinds: Iterable[TargetKind] | None = None,
    categories: Iterable[Category] | None = None,
    sources: Sequence[str] | None = None,
    disabled: Iterable[str] = (),
) -> list[type[Any]]:
    """Resolve the active collector set.

    Explicit ``sources`` win over category/kind filters *by name* but still
    have to support the target kind - scanning a domain with an IP-only
    adapter is a configuration error, not a silent no-op.
    """
    kind_set = set(kinds) if kinds is not None else None
    cat_set = {c.value if isinstance(c, Category) else c for c in categories} if categories else None
    disabled_set = set(disabled)
    chosen: list[type[Any]] = []
    for name in sorted(_REGISTRY):
        cls = _REGISTRY[name]
        spec: CollectorSpec = cls.spec
        if spec.name in disabled_set:
            continue
        if sources is not None:
            if spec.name not in sources:
                continue
        else:
            if not spec.default_enabled:
                continue
            if cat_set is not None and spec.category.value not in cat_set:
                continue
        if kind_set is not None and not (spec.target_kinds & kind_set):
            continue
        chosen.append(cls)
    return chosen


def requirements_missing(spec: CollectorSpec, api_keys: Any) -> str | None:
    """Return the missing key name, or None when the source is usable."""
    if spec.requires_key is None:
        return None
    if api_keys is None:
        return spec.requires_key
    value = api_keys.get(spec.requires_key)
    return None if value else spec.requires_key

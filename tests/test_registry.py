"""Registry invariants: the catalog is the single source of truth."""

from __future__ import annotations

import pytest

from projectosint import registry
from projectosint.models import Category, TargetKind


def test_catalog_exceeds_twenty_five_sources() -> None:
    names = registry.names()
    assert len(names) >= 25, f"expected 25+ collectors, found {len(names)}"
    assert len(set(names)) == len(names)


def test_every_spec_has_lawful_note() -> None:
    for spec in registry.all_specs():
        assert spec.lawful_note, f"{spec.name} must document its lawful scope"
        assert spec.description
        assert spec.target_kinds


def test_select_by_target_kind_excludes_mismatch() -> None:
    chosen = registry.select(kinds={TargetKind.IP})
    names = {cls.spec.name for cls in chosen}
    assert "rdap_ip" in names
    assert "dns_a" not in names
    assert "crtsh" not in names


def test_select_sources_is_explicit() -> None:
    chosen = registry.select(kinds={TargetKind.DOMAIN}, sources=["dns_a", "rdap_ip"])
    assert [cls.spec.name for cls in chosen] == ["dns_a"]


def test_select_respects_disabled() -> None:
    chosen = registry.select(kinds={TargetKind.DOMAIN}, disabled={"dns_a"})
    assert "dns_a" not in {cls.spec.name for cls in chosen}


def test_select_skips_opt_in_by_default() -> None:
    default = {cls.spec.name for cls in registry.select(kinds={TargetKind.DOMAIN})}
    assert "search_ddg" not in default
    explicit = {cls.spec.name for cls in registry.select(kinds={TargetKind.DOMAIN}, sources=["search_ddg"])}
    assert explicit == {"search_ddg"}


def test_categories_filter() -> None:
    chosen = registry.select(kinds={TargetKind.DOMAIN}, categories=[Category.CERTIFICATES])
    assert {cls.spec.category for cls in chosen} == {Category.CERTIFICATES}


def test_requires_key_helpers() -> None:
    hibp = next(spec for spec in registry.all_specs() if spec.name == "hibp_breaches")
    assert registry.requirements_missing(hibp, None) == "hibp"
    assert registry.requirements_missing(hibp, type("K", (), {"get": lambda self, key: None})()) == "hibp"

    dns = next(spec for spec in registry.all_specs() if spec.name == "dns_a")
    assert registry.requirements_missing(dns, None) is None


def test_unknown_lookup_raises() -> None:
    with pytest.raises(KeyError):
        registry.get_class("nope")

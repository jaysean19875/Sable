"""Target classification - wrong routing here silently drops half the catalog."""

from __future__ import annotations

import pytest

from projectosint.models import TargetKind
from projectosint.targets import parse_target, registrable_domain


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("example.com", TargetKind.DOMAIN, "example.com"),
        ("EXAMPLE.com.", TargetKind.DOMAIN, "example.com"),
        ("www.example.co.uk", TargetKind.DOMAIN, "www.example.co.uk"),
        ("8.8.8.8", TargetKind.IP, "8.8.8.8"),
        ("2001:4860:4860::8888", TargetKind.IP, "2001:4860:4860::8888"),
        ("https://Example.com/path?q=1", TargetKind.URL, "https://Example.com/path?q=1"),
        ("analyst@example.com", TargetKind.EMAIL, "analyst@example.com"),
        ("some-handle", TargetKind.USERNAME, "some-handle"),
    ],
)
def test_parse_target(raw: str, kind: TargetKind, value: str) -> None:
    target = parse_target(raw)
    assert target.kind is kind
    assert target.value == value


def test_parse_strips_and_sets_host() -> None:
    target = parse_target("  Example.COM  ")
    assert target.value == "example.com"
    assert target.host == "example.com"
    assert target.label == "domain:example.com"


def test_email_host_is_domain() -> None:
    target = parse_target("analyst@Sub.Example.com")
    assert target.kind is TargetKind.EMAIL
    assert target.host == "sub.example.com"


def test_url_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="scheme"):
        parse_target("ftp://example.com/file")


@pytest.mark.parametrize("bad", ["", "   ", "not a target!", "http://"])
def test_invalid_targets(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_target(bad)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("a.b.example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
        ("deep.sub.example.org", "example.org"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected

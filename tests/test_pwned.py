"""HIBP Pwned Passwords k-anonymity maths and the paste collector."""

from __future__ import annotations

import httpx
import respx

from projectosint.collectors import pwned
from projectosint.collectors.pwned import HibpPastes, password_breach_count, password_range_parts
from projectosint.http import OsintClient
from projectosint.models import Severity


def test_password_range_parts_sha1_split() -> None:
    prefix, suffix = password_range_parts("password")
    # sha1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


async def test_password_breach_count(settings) -> None:
    async with OsintClient(settings) as client:
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["headers"] = dict(request.headers)
            return httpx.Response(
                200,
                text=(
                    "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n"
                    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n"
                    "FFF00DDEEFF00DDEEFF00DDEEFF00DDEEFF00D:0\n"
                ),
            )

        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://api.pwnedpasswords.com/range/5BAA6").mock(side_effect=handler)
            assert await password_breach_count(client, "password") == 3861493
        # k-anonymity: only the 5-char prefix travels, padding requested
        assert seen["url"].endswith("/range/5BAA6")
        assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8" not in seen["url"]
        assert seen["headers"]["add-padding"] == "true"


async def test_password_breach_count_not_found(settings) -> None:
    async with OsintClient(settings) as client:
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://api.pwnedpasswords.com/range/5BAA6").mock(
                return_value=httpx.Response(200, text="00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n")
            )
            assert await password_breach_count(client, "password") == 0


async def test_hibp_pastes_parses(settings, context) -> None:
    settings.api_keys.hibp = "test-key"
    payload = [
        {
            "Source": "Pastebin",
            "Id": "abcd1234",
            "Title": "example dump",
            "Date": "2024-01-02T00:00:00Z",
            "EmailCount": 5000,
        }
    ]
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["hibp-api-key"] = request.headers.get("hibp-api-key")
        return httpx.Response(200, json=payload)

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://haveibeenpwned.com/api/v3/pasteaccount/example.com").mock(
            side_effect=handler
        )
        findings = await HibpPastes(context).collect()
    assert findings[0].kind == "breach.paste"
    assert findings[0].value == "Pastebin"
    assert findings[0].severity is Severity.HIGH
    assert seen["hibp-api-key"] == "test-key"


async def test_hibp_pastes_404_is_empty(settings, context) -> None:
    settings.api_keys.hibp = "test-key"
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://haveibeenpwned.com/api/v3/pasteaccount/example.com").mock(
            return_value=httpx.Response(404)
        )
        assert await HibpPastes(context).collect() == []


def test_module_registers_paste_collector() -> None:
    from projectosint import registry

    spec = next(s for s in registry.all_specs() if s.name == "hibp_pastes")
    assert spec.requires_key == "hibp"
    assert pwned  # module imported cleanly

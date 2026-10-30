"""Collector adapters tested offline: mocked DNS and mocked HTTP transports."""

from __future__ import annotations

import ssl
from datetime import UTC, datetime

import httpx
import pytest
import respx

from projectosint.base import CollectorContext
from projectosint.collectors import crtsh, dns, identity, rdap, tls, wayback, web, whois
from projectosint.models import Severity


async def test_dns_a(monkeypatch: pytest.MonkeyPatch, context: CollectorContext) -> None:
    async def fake_query(name: str, rrtype: str, timeout: float = 5.0) -> list[str]:
        return ["93.184.216.34", "93.184.216.35"] if rrtype == "A" else []

    monkeypatch.setattr(dns, "query_dns", fake_query)
    findings = await dns.DnsA(context).collect()
    assert [f.value for f in findings] == ["93.184.216.34", "93.184.216.35"]
    assert all(f.category.value == "dns" for f in findings)


async def test_dns_mx_identifies_provider(
    monkeypatch: pytest.MonkeyPatch, context: CollectorContext
) -> None:
    async def fake_query(name: str, rrtype: str, timeout: float = 5.0) -> list[str]:
        return ['10 aspmx.l.google.com.'] if rrtype == "MX" else []

    monkeypatch.setattr(dns, "query_dns", fake_query)
    findings = await dns.DnsMx(context).collect()
    assert findings[0].value == "aspmx.l.google.com"
    assert "Google Workspace" in findings[0].detail
    assert "mail-provider:Google Workspace" in findings[0].tags


async def test_dns_spf_flags_permissive_policy(
    monkeypatch: pytest.MonkeyPatch, context: CollectorContext
) -> None:
    async def fake_query(name: str, rrtype: str, timeout: float = 5.0) -> list[str]:
        return ['"v=spf1 +all"'] if rrtype == "TXT" else []

    monkeypatch.setattr(dns, "query_dns", fake_query)
    findings = await dns.DnsSpf(context).collect()
    assert findings[0].severity is Severity.MEDIUM
    assert "+all" in findings[0].detail


async def test_dns_spf_missing(monkeypatch: pytest.MonkeyPatch, context: CollectorContext) -> None:
    async def fake_query(name: str, rrtype: str, timeout: float = 5.0) -> list[str]:
        return []

    monkeypatch.setattr(dns, "query_dns", fake_query)
    findings = await dns.DnsSpf(context).collect()
    assert findings[0].value == "missing"
    assert findings[0].severity is Severity.LOW


async def test_dns_dmarc_none_policy(
    monkeypatch: pytest.MonkeyPatch, context: CollectorContext
) -> None:
    async def fake_query(name: str, rrtype: str, timeout: float = 5.0) -> list[str]:
        assert name == "_dmarc.example.com"
        return ['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"']

    monkeypatch.setattr(dns, "query_dns", fake_query)
    findings = await dns.DnsDmarc(context).collect()
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["p"] == "none"


async def test_crtsh_extracts_subdomains(context: CollectorContext) -> None:
    payload = [
        {
            "name_value": "www.example.com\n*.api.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
        },
        {
            "name_value": "shop.example.com",
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
            "not_before": "2024-02-01T00:00:00",
            "not_after": "2025-02-01T00:00:00",
        },
    ]
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=payload))
        findings = await crtsh.CrtShCollector(context).collect()
    subdomains = sorted(f.value for f in findings if f.kind == "host.subdomain")
    assert subdomains == ["api.example.com", "shop.example.com", "www.example.com"]
    issuers = [f.value for f in findings if f.kind == "cert.issuer"]
    assert "Let's Encrypt" in issuers


async def test_crtsh_handles_outage_page(context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://crt.sh/").mock(return_value=httpx.Response(200, text="<html>maintenance"))
        with pytest.raises(crtsh.CollectorHttpError):
            await crtsh.CrtShCollector(context).collect()


def test_issuer_org_handles_quoted_dn() -> None:
    assert crtsh._issuer_org('C=US, O="thawte, Inc.", CN=thawte TLS RSA CA G1') == "thawte, Inc."
    assert crtsh._issuer_org("C=US, O=Let's Encrypt, CN=R3") == "Let's Encrypt"
    assert crtsh._issuer_org("CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc") == "DigiCert Inc"
    assert crtsh._issuer_org("Issuer Not Found") is None


async def test_crtsh_drops_placeholder_issuers(context: CollectorContext) -> None:
    payload = [
        {"name_value": "www.example.com", "issuer_name": "Issuer Not Found"},
        {"name_value": "api.example.com", "issuer_name": 'C=US, O="thawte, Inc.", CN=thawte TLS RSA CA G1'},
    ]
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=payload))
        findings = await crtsh.CrtShCollector(context).collect()
    issuers = [f.value for f in findings if f.kind == "cert.issuer"]
    assert issuers == ["thawte, Inc."]


async def test_rdap_domain_parses_registration(context: CollectorContext) -> None:
    payload = {
        "ldhName": "EXAMPLE.COM",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
        ],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
            }
        ],
    }
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://rdap.org/domain/example.com").mock(
            return_value=httpx.Response(200, json=payload)
        )
        findings = await rdap.RdapDomain(context).collect()
    kinds = {f.kind for f in findings}
    assert "rdap.registered" in kinds
    assert "rdap.registrar" in kinds
    assert "rdap.dnssec" in kinds
    registered = next(f for f in findings if f.kind == "rdap.registered")
    assert registered.value.startswith("1995-08-14")


async def test_http_fingerprint(context: CollectorContext) -> None:
    html = """<html><head><title>Example Domain</title>
    <meta name="generator" content="WordPress 6.4"></head><body>ok</body></html>"""
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                text=html,
                headers={"content-type": "text/html", "server": "nginx/1.25.3"},
            )
        )
        findings = await web.HttpFingerprint(context).collect()
    kinds = {f.kind for f in findings}
    assert "web.title" in kinds
    assert "web.server" in kinds
    assert "web.generator" in kinds
    assert "web.security_headers" in kinds
    generator = next(f for f in findings if f.kind == "web.generator")
    assert "WordPress" in generator.value


async def test_wayback_cdx(context: CollectorContext) -> None:
    rows = [
        ["20200101000000", "http://admin.example.com/login"],
        ["20210101000000", "http://example.com/"],
        ["20220101000000", "http://example.com/backup/db.sql"],
    ]
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://web.archive.org/cdx/search/cdx").mock(
            return_value=httpx.Response(200, json=rows)
        )
        findings = await wayback.WaybackCdx(context).collect()
    kinds = {f.kind for f in findings}
    assert "host.subdomain" in kinds
    assert "web.archive.sensitive" in kinds
    assert any(f.value == "admin.example.com" for f in findings)


def test_whois_field_parsing() -> None:
    text = (
        "Registrar: Example Registrar, Inc.\n"
        "Name Server: NS1.EXAMPLE.COM\n"
        "Domain Status: clientTransferProhibited\n"
    )
    fields = whois._fields(text)
    assert fields["registrar"] == ["Example Registrar, Inc."]
    assert fields["name server"] == ["NS1.EXAMPLE.COM"]
    assert whois._parse_date("2024-01-02T03:04:05Z") == datetime(
        2024, 1, 2, 3, 4, 5, tzinfo=UTC
    )


def test_tls_name_part_extraction() -> None:
    cert = {"subject": ((("commonName", "example.com"),),), "issuer": ((("organizationName", "Acme CA"),),)}
    assert tls._name_part(cert, "subject") == "example.com"
    assert tls._org_part(cert, "issuer") == "Acme CA"


def test_tls_context_is_verified_with_certifi() -> None:
    context = tls.ssl_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert len(context.get_ca_certs()) > 50  # certifi bundle, not the thin OS store


async def test_github_user_404_is_empty(settings) -> None:
    from projectosint.base import CollectorContext
    from projectosint.http import OsintClient
    from projectosint.targets import parse_target

    async with OsintClient(settings) as client:
        ctx = CollectorContext(
            settings=settings, client=client, target=parse_target("ghost"), scan_id="t"
        )
        with respx.mock(assert_all_called=False) as mock:
            mock.get("https://api.github.com/users/ghost").mock(return_value=httpx.Response(404))
            findings = await identity.GitHubUser(ctx).collect()
    assert findings == []

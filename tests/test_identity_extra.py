"""The keyless public-profile sweep sources, offline via respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from projectosint import registry
from projectosint.base import CollectorContext
from projectosint.collectors import identity_extra
from projectosint.http import OsintClient
from projectosint.targets import parse_target

NAMES = {
    "steam_user",
    "gitlab_user",
    "stackexchange_user",
    "mastodon_user",
    "wikipedia_user",
    "chesscom_user",
    "codeforces_user",
    "devto_user",
}


def test_all_extra_sources_registered() -> None:
    registered = set(registry.names())
    assert registered >= NAMES


@pytest.fixture
async def user_context(settings):
    async with OsintClient(settings) as client:
        yield CollectorContext(
            settings=settings, client=client, target=parse_target("someuser"), scan_id="t"
        )


async def test_steam_profile_found(user_context: CollectorContext) -> None:
    xml = "<profile><steamID64>76561198000000000</steamID64></profile>"
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://steamcommunity.com/id/someuser/").mock(return_value=httpx.Response(200, text=xml))
        findings = await identity_extra.SteamUser(user_context).collect()
    assert findings[0].kind == "identity.steam"
    assert findings[0].evidence["steamid64"] == "76561198000000000"


async def test_steam_profile_missing(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://steamcommunity.com/id/someuser/").mock(
            return_value=httpx.Response(200, text="The specified profile could not be found")
        )
        assert await identity_extra.SteamUser(user_context).collect() == []


async def test_gitlab_profile(user_context: CollectorContext) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        return httpx.Response(
            200, json=[{"username": "someuser", "name": "Some User",
                        "web_url": "https://gitlab.com/someuser", "state": "active"}]
        )

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://gitlab.com/api/v4/users").mock(side_effect=handler)
        findings = await identity_extra.GitLabUser(user_context).collect()
    assert findings[0].value == "https://gitlab.com/someuser"
    assert seen["params"]["username"] == "someuser"


async def test_gitlab_missing(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://gitlab.com/api/v4/users").mock(return_value=httpx.Response(200, json=[]))
        assert await identity_extra.GitLabUser(user_context).collect() == []


async def test_stackexchange_profile(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://api.stackexchange.com/2.3/users").mock(
            return_value=httpx.Response(
                200,
                json={"items": [{"user_id": 42, "account_id": 7, "display_name": "someuser",
                                 "reputation": 1234, "link": "https://stackoverflow.com/users/42"}]},
            )
        )
        findings = await identity_extra.StackExchangeUser(user_context).collect()
    assert "1234 reputation" in findings[0].detail


async def test_mastodon_webfinger(user_context: CollectorContext) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "subject": "acct:someuser@mastodon.social",
                "links": [{"rel": "self", "href": "https://mastodon.social/@someuser"}],
            },
        )

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://mastodon.social/.well-known/webfinger").mock(side_effect=handler)
        findings = await identity_extra.MastodonUser(user_context).collect()
    assert findings[0].value == "https://mastodon.social/@someuser"
    assert seen["params"]["resource"] == "acct:someuser@mastodon.social"


async def test_mastodon_missing(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://mastodon.social/.well-known/webfinger").mock(
            return_value=httpx.Response(404)
        )
        assert await identity_extra.MastodonUser(user_context).collect() == []


async def test_wikipedia_presence(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://en.wikipedia.org/w/api.php").mock(
            return_value=httpx.Response(
                200, json={"query": {"users": [{"userid": 9, "name": "Someuser"}]}}
            )
        )
        findings = await identity_extra.WikipediaUser(user_context).collect()
    assert findings[0].kind == "identity.wikipedia"


async def test_chesscom_and_codeforces_missing(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://api.chess.com/pub/player/someuser").mock(return_value=httpx.Response(404))
        mock.get("https://codeforces.com/api/user.info").mock(return_value=httpx.Response(400))
        assert await identity_extra.ChessComUser(user_context).collect() == []
        assert await identity_extra.CodeforcesUser(user_context).collect() == []


async def test_devto_missing(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://dev.to/api/users/by_username").mock(return_value=httpx.Response(404))
        assert await identity_extra.DevToUser(user_context).collect() == []

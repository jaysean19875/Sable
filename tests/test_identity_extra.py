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
    "mojang_user",
    "roblox_user",
    "lichess_user",
    "bitbucket_user",
    "codeberg_user",
    "bluesky_user",
    "npm_user",
    "speedrun_user",
    "scratch_user",
    "osrs_hiscores",
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


async def test_mojang_profile(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://api.mojang.com/users/profiles/minecraft/someuser").mock(
            return_value=httpx.Response(200, json={"id": "abc123", "name": "someuser"})
        )
        findings = await identity_extra.MojangUser(user_context).collect()
    assert findings[0].kind == "identity.mojang"
    assert findings[0].evidence["uuid"] == "abc123"


async def test_roblox_profile(user_context: CollectorContext) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={"data": [{"id": 77, "name": "someuser"}]})

    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://users.roblox.com/v1/usernames/users").mock(side_effect=handler)
        findings = await identity_extra.RobloxUser(user_context).collect()
    assert findings[0].kind == "identity.roblox"
    assert "someuser" in seen["body"]


async def test_roblox_missing(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://users.roblox.com/v1/usernames/users").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        assert await identity_extra.RobloxUser(user_context).collect() == []


async def test_lichess_bitbucket_codeberg(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://lichess.org/api/user/someuser").mock(
            return_value=httpx.Response(200, json={"id": "someuser", "username": "someuser"})
        )
        mock.get("https://api.bitbucket.org/2.0/users/someuser").mock(
            return_value=httpx.Response(
                200,
                json={
                    "username": "someuser",
                    "display_name": "Some User",
                    "links": {"html": {"href": "https://bitbucket.org/someuser"}},
                },
            )
        )
        mock.get("https://codeberg.org/api/v1/users/someuser").mock(
            return_value=httpx.Response(200, json={"login": "someuser"})
        )
        lichess_findings = await identity_extra.LichessUser(user_context).collect()
        bitbucket_findings = await identity_extra.BitbucketUser(user_context).collect()
        codeberg_findings = await identity_extra.CodebergUser(user_context).collect()
    assert lichess_findings[0].kind == "identity.lichess"
    assert bitbucket_findings[0].value == "https://bitbucket.org/someuser"
    assert codeberg_findings[0].kind == "identity.codeberg"


async def test_bluesky_profile(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile").mock(
            return_value=httpx.Response(
                200, json={"did": "did:plc:abc", "handle": "someuser.bsky.social"}
            )
        )
        findings = await identity_extra.BlueskyUser(user_context).collect()
    assert findings[0].kind == "identity.bluesky"


async def test_npm_and_speedrun_and_scratch(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://registry.npmjs.org/-/user/org.couchdb.user:someuser").mock(
            return_value=httpx.Response(200, json={"name": "someuser", "created": "2020-01-01"})
        )
        mock.get("https://www.speedrun.com/api/v1/users").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "abc",
                            "names": {"international": "someuser"},
                            "weblink": "https://www.speedrun.com/users/someuser",
                        }
                    ]
                },
            )
        )
        mock.get("https://api.scratch.mit.edu/users/someuser").mock(
            return_value=httpx.Response(200, json={"id": 9, "username": "someuser"})
        )
        npm_findings = await identity_extra.NpmUser(user_context).collect()
        speedrun_findings = await identity_extra.SpeedrunUser(user_context).collect()
        scratch_findings = await identity_extra.ScratchUser(user_context).collect()
    assert npm_findings[0].kind == "identity.npm"
    assert speedrun_findings[0].kind == "identity.speedrun"
    assert scratch_findings[0].kind == "identity.scratch"


async def test_osrs_hiscores(user_context: CollectorContext) -> None:
    csv_text = "1,200000000,120\n2,50000000,99\n"
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://secure.runescape.com/m=hiscore_oldschool/index_lite.ws").mock(
            return_value=httpx.Response(200, text=csv_text)
        )
        findings = await identity_extra.OsrsHiscores(user_context).collect()
    assert findings[0].kind == "identity.osrs"
    assert findings[0].evidence["hiscores_entries"] == 2


async def test_new_sources_missing_are_empty(user_context: CollectorContext) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://api.mojang.com/users/profiles/minecraft/someuser").mock(
            return_value=httpx.Response(404)
        )
        mock.get("https://lichess.org/api/user/someuser").mock(return_value=httpx.Response(404))
        mock.get("https://api.bitbucket.org/2.0/users/someuser").mock(
            return_value=httpx.Response(404)
        )
        mock.get("https://codeberg.org/api/v1/users/someuser").mock(
            return_value=httpx.Response(404)
        )
        mock.get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile").mock(
            return_value=httpx.Response(400)
        )
        mock.get("https://registry.npmjs.org/-/user/org.couchdb.user:someuser").mock(
            return_value=httpx.Response(404)
        )
        mock.get("https://api.scratch.mit.edu/users/someuser").mock(
            return_value=httpx.Response(404)
        )
        for collector in (
            identity_extra.MojangUser,
            identity_extra.LichessUser,
            identity_extra.BitbucketUser,
            identity_extra.CodebergUser,
            identity_extra.BlueskyUser,
            identity_extra.NpmUser,
            identity_extra.ScratchUser,
        ):
            assert await collector(user_context).collect() == []

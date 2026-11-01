"""Additional keyless public-profile presence checks for the Personal Data page.

Every endpoint here is callable without authentication and without touching a
login wall.  A profile that is not found is simply an empty result; the
Personal Data orchestrator reports it as "no public profile found".
"""

from __future__ import annotations

from typing import Any

from ..base import BaseCollector, CollectorHttpError
from ..models import Category, Confidence, Finding, TargetKind
from ..registry import CollectorSpec, register

_USER = frozenset({TargetKind.USERNAME})
_CATEGORY = Category.IDENTITY


class _PublicProfileCollector(BaseCollector):
    """Shared shape: query the profile endpoint, emit a presence finding."""

    endpoint = ""
    finding_kind = "identity.profile"
    service = "profile"

    async def collect(self) -> list[Finding]:
        username = self.ctx.target.value
        payload = await self.lookup(username)
        if payload is None:
            return []
        return self.render(payload)

    async def lookup(self, username: str) -> Any | None:
        """Return parsed evidence, or None when no public profile exists."""
        raise NotImplementedError

    def render(self, payload: Any) -> list[Finding]:
        raise NotImplementedError


@register(
    CollectorSpec(
        name="steam_user",
        category=_CATEGORY,
        description="Steam public profile and SteamID",
        target_kinds=_USER,
        weight="light",
        lawful_note="Steam community profile XML, public and unauthenticated.",
    )
)
class SteamUser(_PublicProfileCollector):
    endpoint = "https://steamcommunity.com/id/{u}/?xml=1"

    async def lookup(self, username: str) -> Any | None:
        response = await self.ctx.get(self.endpoint.format(u=username))
        if "The specified profile could not be found" in response.text:
            return None
        if "<steamID64>" not in response.text:
            raise CollectorHttpError(
                f"Steam returned HTTP {response.status}", status=response.status
            )
        return {"steamid64": response.text.split("<steamID64>")[1].split("<")[0]}

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.steam",
                f"https://steamcommunity.com/id/{self.ctx.target.value}",
                detail=f"Steam profile exists (SteamID {payload['steamid64']})",
                confidence=Confidence.HIGH,
                tags=("identity", "steam"),
                evidence=payload,
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="gitlab_user",
        category=_CATEGORY,
        description="GitLab.com public profile",
        target_kinds=_USER,
        weight="light",
        lawful_note="GitLab.com public REST API, unauthenticated user lookup.",
    )
)
class GitLabUser(_PublicProfileCollector):
    endpoint = "https://gitlab.com/api/v4/users"

    async def lookup(self, username: str) -> Any | None:
        payload = await self.ctx.get_json(
            self.endpoint, params={"username": username, "without_project_count": "true"}
        )
        if not isinstance(payload, list) or not payload:
            return None
        return payload[0]

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.gitlab",
                str(payload.get("web_url") or f"https://gitlab.com/{payload.get('username')}"),
                detail=f"GitLab account '{payload.get('name') or payload.get('username')}'",
                confidence=Confidence.HIGH,
                tags=("identity", "gitlab"),
                evidence={"username": payload.get("username"), "state": payload.get("state")},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="stackexchange_user",
        category=_CATEGORY,
        description="Stack Exchange network account (Stack Overflow)",
        target_kinds=_USER,
        weight="light",
        lawful_note="Stack Exchange public API, unauthenticated quota.",
    )
)
class StackExchangeUser(_PublicProfileCollector):
    endpoint = "https://api.stackexchange.com/2.3/users"

    async def lookup(self, username: str) -> Any | None:
        payload = await self.ctx.get_json(
            self.endpoint,
            params={
                "inname": username,
                "site": "stackoverflow",
                "order": "desc",
                "sort": "reputation",
            },
        )
        items = payload.get("items") if isinstance(payload, dict) else None
        if not items:
            return None
        return items[0]

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.stackexchange",
                str(payload.get("link") or f"https://stackoverflow.com/users/{payload.get('user_id')}"),
                detail=f"Stack Overflow account '{payload.get('display_name')}' "
                f"({payload.get('reputation', 0)} reputation)",
                confidence=Confidence.HIGH,
                tags=("identity", "stackexchange"),
                evidence={
                    "user_id": payload.get("user_id"),
                    "account_id": payload.get("account_id"),
                    "reputation": payload.get("reputation"),
                },
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="mastodon_user",
        category=_CATEGORY,
        description="Mastodon profile via webfinger (mastodon.social)",
        target_kinds=_USER,
        weight="light",
        lawful_note="Public ActivityPub webfinger endpoint.",
    )
)
class MastodonUser(_PublicProfileCollector):
    endpoint = "https://mastodon.social/.well-known/webfinger"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(
                self.endpoint,
                params={"resource": f"acct:{username}@mastodon.social"},
            )
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        if not isinstance(payload, dict) or not payload.get("subject"):
            return None
        profile = next(
            (link.get("href") for link in payload.get("links", []) if link.get("rel") == "self"),
            None,
        )
        return {"subject": payload["subject"], "profile": profile}

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.mastodon",
                str(payload["profile"] or payload["subject"]),
                detail="Mastodon profile found via webfinger",
                confidence=Confidence.HIGH,
                tags=("identity", "mastodon"),
                evidence={"subject": payload["subject"]},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="wikipedia_user",
        category=_CATEGORY,
        description="Wikipedia registered account",
        target_kinds=_USER,
        weight="light",
        lawful_note="Wikimedia public API.",
    )
)
class WikipediaUser(_PublicProfileCollector):
    endpoint = "https://en.wikipedia.org/w/api.php"

    async def lookup(self, username: str) -> Any | None:
        payload = await self.ctx.get_json(
            self.endpoint,
            params={
                "action": "query",
                "list": "users",
                "ususers": username,
                "format": "json",
            },
        )
        users = payload.get("query", {}).get("users", []) if isinstance(payload, dict) else []
        if not users or users[0].get("missing"):
            return None
        return users[0]

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.wikipedia",
                f"https://en.wikipedia.org/wiki/User:{self.ctx.target.value}",
                detail="Wikipedia account exists",
                confidence=Confidence.HIGH,
                tags=("identity", "wikipedia"),
                evidence={"userid": payload.get("userid"), "name": payload.get("name")},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="chesscom_user",
        category=_CATEGORY,
        description="Chess.com public player profile",
        target_kinds=_USER,
        weight="light",
        lawful_note="Chess.com public player API.",
    )
)
class ChessComUser(_PublicProfileCollector):
    endpoint = "https://api.chess.com/pub/player/{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status in {404, 403}:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.chesscom",
                str(payload.get("url") or self.endpoint.format(u=self.ctx.target.value)),
                detail="Chess.com profile exists",
                confidence=Confidence.HIGH,
                tags=("identity", "chess.com"),
                evidence={"player_id": payload.get("player_id"), "joined": payload.get("joined")},
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="codeforces_user",
        category=_CATEGORY,
        description="Codeforces competitive programming profile",
        target_kinds=_USER,
        weight="light",
        lawful_note="Codeforces public API.",
    )
)
class CodeforcesUser(_PublicProfileCollector):
    endpoint = "https://codeforces.com/api/user.info"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint, params={"handles": username})
        except CollectorHttpError as exc:
            if exc.status in {400, 404}:
                return None
            raise
        result = payload.get("result") if isinstance(payload, dict) else None
        if not result:
            return None
        return result[0]

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.codeforces",
                f"https://codeforces.com/profile/{self.ctx.target.value}",
                detail=f"Codeforces handle '{payload.get('handle')}' "
                f"(rating {payload.get('rating', 'unrated')})",
                confidence=Confidence.HIGH,
                tags=("identity", "codeforces"),
                evidence={"rating": payload.get("rating"), "rank": payload.get("rank")},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="devto_user",
        category=_CATEGORY,
        description="dev.to public profile",
        target_kinds=_USER,
        weight="light",
        lawful_note="dev.to public API.",
    )
)
class DevToUser(_PublicProfileCollector):
    endpoint = "https://dev.to/api/users/by_username"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint, params={"url": username})
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.devto",
                f"https://dev.to/{self.ctx.target.value}",
                detail=f"dev.to account '{payload.get('name') or self.ctx.target.value}'",
                confidence=Confidence.HIGH,
                tags=("identity", "dev.to"),
                evidence={"summary": str(payload.get("summary") or "")[:200]},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="mojang_user",
        category=_CATEGORY,
        description="Minecraft (Java) account UUID via Mojang's public API",
        target_kinds=_USER,
        weight="light",
        lawful_note="Mojang public profile API; username to UUID only.",
    )
)
class MojangUser(_PublicProfileCollector):
    endpoint = "https://api.mojang.com/users/profiles/minecraft/{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status in {204, 404}:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.mojang",
                str(payload.get("name") or self.ctx.target.value),
                detail="Minecraft account exists (Mojang)",
                confidence=Confidence.HIGH,
                tags=("identity", "minecraft"),
                evidence={"uuid": payload.get("id")},
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="roblox_user",
        category=_CATEGORY,
        description="Roblox account presence via the public users API",
        target_kinds=_USER,
        weight="light",
        lawful_note="Roblox public users endpoint; username lookup only.",
    )
)
class RobloxUser(_PublicProfileCollector):
    endpoint = "https://users.roblox.com/v1/usernames/users"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.post_json(
                self.endpoint,
                json_body={"usernames": [username], "excludeBannedUsers": False},
            )
        except CollectorHttpError as exc:
            if exc.status in {400, 404}:
                return None
            raise
        data = payload.get("data") if isinstance(payload, dict) else []
        return data[0] if data else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.roblox",
                f"https://www.roblox.com/users/{payload.get('id')}/profile",
                detail=f"Roblox account '{payload.get('name') or self.ctx.target.value}'",
                confidence=Confidence.HIGH,
                tags=("identity", "roblox"),
                evidence={"id": payload.get("id"), "display_name": payload.get("displayName")},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="lichess_user",
        category=_CATEGORY,
        description="Lichess public player profile",
        target_kinds=_USER,
        weight="light",
        lawful_note="Lichess public API.",
    )
)
class LichessUser(_PublicProfileCollector):
    endpoint = "https://lichess.org/api/user/{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.lichess",
                f"https://lichess.org/@/{self.ctx.target.value}",
                detail="Lichess profile exists",
                confidence=Confidence.HIGH,
                tags=("identity", "chess"),
                evidence={"id": payload.get("id"), "created_at": payload.get("createdAt")},
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="bitbucket_user",
        category=_CATEGORY,
        description="Bitbucket public account",
        target_kinds=_USER,
        weight="light",
        lawful_note="Bitbucket public API.",
    )
)
class BitbucketUser(_PublicProfileCollector):
    endpoint = "https://api.bitbucket.org/2.0/users/{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.bitbucket",
                str(payload.get("links", {}).get("html", {}).get("href")
                    or f"https://bitbucket.org/{payload.get('username')}"),
                detail=f"Bitbucket account '{payload.get('display_name') or payload.get('username')}'",
                confidence=Confidence.HIGH,
                tags=("identity", "bitbucket"),
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="codeberg_user",
        category=_CATEGORY,
        description="Codeberg public account",
        target_kinds=_USER,
        weight="light",
        lawful_note="Codeberg public API.",
    )
)
class CodebergUser(_PublicProfileCollector):
    endpoint = "https://codeberg.org/api/v1/users/{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.codeberg",
                f"https://codeberg.org/{self.ctx.target.value}",
                detail="Codeberg account exists",
                confidence=Confidence.HIGH,
                tags=("identity", "codeberg"),
                evidence={"login": payload.get("login")},
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="bluesky_user",
        category=_CATEGORY,
        description="Bluesky handle resolution via the public API",
        target_kinds=_USER,
        weight="light",
        lawful_note="Bluesky public API; handle lookup only.",
    )
)
class BlueskyUser(_PublicProfileCollector):
    endpoint = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint, params={"actor": username})
        except CollectorHttpError as exc:
            if exc.status in {400, 404}:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.bluesky",
                f"https://bsky.app/profile/{payload.get('handle') or payload.get('did')}",
                detail=f"Bluesky profile '{payload.get('displayName') or payload.get('handle')}'",
                confidence=Confidence.HIGH,
                tags=("identity", "bluesky"),
                evidence={"did": payload.get("did"), "handle": payload.get("handle")},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="npm_user",
        category=_CATEGORY,
        description="npm registry account",
        target_kinds=_USER,
        weight="light",
        lawful_note="npm public registry user lookup.",
    )
)
class NpmUser(_PublicProfileCollector):
    endpoint = "https://registry.npmjs.org/-/user/org.couchdb.user:{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.npm",
                f"https://www.npmjs.com/~{self.ctx.target.value}",
                detail=f"npm account '{payload.get('name') or self.ctx.target.value}'",
                confidence=Confidence.HIGH,
                tags=("identity", "npm"),
                evidence={"created": payload.get("created")},
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="speedrun_user",
        category=_CATEGORY,
        description="speedrun.com public profile",
        target_kinds=_USER,
        weight="light",
        lawful_note="speedrun.com public API.",
    )
)
class SpeedrunUser(_PublicProfileCollector):
    endpoint = "https://www.speedrun.com/api/v1/users"

    async def lookup(self, username: str) -> Any | None:
        payload = await self.ctx.get_json(self.endpoint, params={"name": username})
        data = payload.get("data") if isinstance(payload, dict) else None
        if not data:
            return None
        return data[0]

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.speedrun",
                str(payload.get("weblink") or f"https://www.speedrun.com/users/{payload.get('id')}"),
                detail=f"speedrun.com profile '{payload.get('names', {}).get('international')}'",
                confidence=Confidence.HIGH,
                tags=("identity", "speedrun"),
                evidence={"id": payload.get("id"), "signup": payload.get("signup")},
                endpoint=self.endpoint,
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="scratch_user",
        category=_CATEGORY,
        description="Scratch (MIT) public account",
        target_kinds=_USER,
        weight="light",
        lawful_note="Scratch public API.",
    )
)
class ScratchUser(_PublicProfileCollector):
    endpoint = "https://api.scratch.mit.edu/users/{u}"

    async def lookup(self, username: str) -> Any | None:
        try:
            payload = await self.ctx.get_json(self.endpoint.format(u=username))
        except CollectorHttpError as exc:
            if exc.status == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def render(self, payload: Any) -> list[Finding]:
        return [
            self.finding(
                "identity.scratch",
                f"https://scratch.mit.edu/users/{self.ctx.target.value}/",
                detail="Scratch account exists",
                confidence=Confidence.HIGH,
                tags=("identity", "scratch"),
                evidence={"id": payload.get("id"), "joined": payload.get("history", {}).get("joined")},
                endpoint=self.endpoint.format(u=self.ctx.target.value),
                query=self.ctx.target.value,
            )
        ]


@register(
    CollectorSpec(
        name="osrs_hiscores",
        category=_CATEGORY,
        description="Old School RuneScape hiscores entry (public lookup)",
        target_kinds=_USER,
        weight="light",
        lawful_note="Jagex public hiscores endpoint.",
    )
)
class OsrsHiscores(BaseCollector):
    endpoint = "https://secure.runescape.com/m=hiscore_oldschool/index_lite.ws"

    async def collect(self) -> list[Finding]:
        username = self.ctx.target.value
        response = await self.ctx.get(self.endpoint, params={"player": username})
        if response.status != 200:
            raise CollectorHttpError(
                f"hiscores returned HTTP {response.status}", status=response.status
            )
        rows = response.text.strip().splitlines()
        if not rows or not any("," in row for row in rows):
            return []
        return [
            self.finding(
                "identity.osrs",
                username,
                detail="Old School RuneScape hiscores entry exists",
                confidence=Confidence.HIGH,
                tags=("identity", "gaming"),
                evidence={"hiscores_entries": len(rows)},
                endpoint=self.endpoint,
                query=username,
            )
        ]

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

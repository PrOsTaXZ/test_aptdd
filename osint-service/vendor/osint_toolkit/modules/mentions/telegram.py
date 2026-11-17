"""Telegram public channels without an account: search inside channels via the t.me/s preview.

1. Channels: ``OSINT_TG_CHANNELS`` plus usernames found by ``"<identifier>" site:t.me`` through
   the search provider chain (up to ``OSINT_TG_MAX_CHANNELS``).
2. For each channel and each main spelling: ``GET https://t.me/s/<channel>?q=<spelling>``
   (robots.txt honoured, ``OSINT_TG_MIN_INTERVAL`` between requests, stop on 429).
3. A post is reported only if the identifier is in its text (Telegram's own search is fuzzy).
   No account, no joining, no member lists; groups and private chats are out of reach.
"""

from __future__ import annotations

from typing import ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    Finding,
    JsonValue,
    ModuleStatus,
    Target,
    TargetType,
)
from osint_toolkit.dorks import variants_for
from osint_toolkit.dorks.builder import is_initials_form
from osint_toolkit.integrations.search import select_providers
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import HttpStatusError, NetworkError
from osint_toolkit.search.executor import SearchChain
from osint_toolkit.search.matching import Match, find_identifier
from osint_toolkit.search.relevance import markers_for, mentions_identifier
from osint_toolkit.search.telegram import (
    USERNAME_RE,
    Post,
    channel_from_url,
    has_preview,
    parse_preview,
    preview_url,
)
from osint_toolkit.search.verify import CHECK_LABELS, Check, PageVerifier, decode_html

TELEGRAM_SERVICE = ExternalService(
    name="Telegram — веб-просмотр публичных каналов (t.me/s), без аккаунта",
    url="https://t.me",
    data_sent="поисковые запросы с идентификатором внутри каждого канала; Telegram видит ваш IP",
)


class TelegramMentionsModule(BaseModule):
    name = "mentions.telegram"
    title = "Telegram: публичные каналы (без аккаунта)"
    description = (
        "Ищет идентификатор в публичных Telegram-каналах через веб-просмотр t.me/s: каналы из "
        "OSINT_TG_CHANNELS и найденные поиском «site:t.me». Без аккаунта и без вступления."
    )
    target_types = frozenset(
        {TargetType.EMAIL, TargetType.PHONE, TargetType.NAME, TargetType.USERNAME}
    )
    external_services: ClassVar[tuple[ExternalService, ...]] = (TELEGRAM_SERVICE,)
    limitations: ClassVar[tuple[str, ...]] = (
        "Только публичные каналы с включённым веб-просмотром: группы, личные чаты и закрытые "
        "каналы так не читаются. Глобального поиска по всему Telegram нет — ищется только в "
        "известных каналах.",
        "Упоминание в посте не устанавливает личность: это может быть однофамилец или чужой номер.",
    )

    # ------------------------------------------------------------------ planning
    @staticmethod
    def configured_channels(settings: Settings) -> list[str]:
        names = [c.strip().lstrip("@") for c in settings.tg_channels.split(",") if c.strip()]
        return list(dict.fromkeys(n for n in names if USERNAME_RE.match(n)))

    @staticmethod
    def spellings(target: Target, settings: Settings) -> list[str]:
        variants = [v for v in variants_for(target) if not is_initials_form(target, v)]
        return variants[: settings.tg_variants]

    def discovery_queries(self, target: Target, settings: Settings) -> list[str]:
        if not select_providers(settings):
            return []
        spellings = self.spellings(target, settings)[: settings.tg_discovery_queries]
        return [f'"{v}" site:t.me' for v in spellings]

    def availability(self, settings: Settings) -> Availability:
        if settings.tg_max_channels == 0:
            return Availability(False, "OSINT_TG_MAX_CHANNELS=0")
        if not select_providers(settings) and not self.configured_channels(settings):
            return Availability(
                False,
                "нет каналов: задайте OSINT_TG_CHANNELS или поисковый провайдер "
                "(каналы находятся поиском «site:t.me»)",
            )
        return Availability(True)

    def services_for(self, settings: Settings) -> tuple[ExternalService, ...]:
        providers = tuple(p.service() for p in select_providers(settings))
        return (
            (TELEGRAM_SERVICE, *providers) if settings.tg_discovery_queries else (TELEGRAM_SERVICE,)
        )

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        lines = [f"поиск каналов: {q}" for q in self.discovery_queries(target, settings)]
        channels = self.configured_channels(settings)
        if channels:
            lines.append("ваши каналы: " + ", ".join(channels[: settings.tg_max_channels]))
        lines.append(
            f"в каждом канале (до {settings.tg_max_channels}): "
            + ", ".join(f"t.me/s/<канал>?q={v}" for v in self.spellings(target, settings))
        )
        return tuple(lines)

    def effective_timeout(self, settings: Settings) -> float:
        requests = settings.tg_max_channels * settings.tg_variants + 4
        return float(min(3600, requests * (settings.tg_min_interval + 8) + 60))

    # ------------------------------------------------------------------ run
    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        channels = self.configured_channels(settings)
        discovered = await self._discover(target, ctx, out)
        channels += [c for c in discovered if c.lower() not in {x.lower() for x in channels}]
        channels = channels[: settings.tg_max_channels]
        spellings = self.spellings(target, settings)
        verifier = PageVerifier(ctx.net, settings)
        limiter = ctx.net.limiter("telegram", settings.tg_min_interval)
        found: dict[str, tuple[Post, str | None, Match, str]] = {}
        unavailable: list[str] = []
        searched = 0
        stopped: str | None = None
        for channel in channels:
            for spelling in spellings:
                url = preview_url(channel, spelling)
                if not await verifier.allowed(url):
                    stopped = "robots.txt t.me запрещает автоматический доступ"
                    break
                await limiter.wait()
                try:
                    response = await ctx.net.http.fetch(
                        url,
                        headers={"Accept": "text/html", "Accept-Language": "ru,en;q=0.8"},
                        request_timeout=settings.page_timeout,
                        max_bytes=4 << 20,
                        retries=0,
                    )
                except HttpStatusError as exc:
                    if exc.status_code == 429:
                        stopped = "Telegram ограничил частоту запросов (429)"
                        break
                    out.errors.append(f"{channel}: {exc}")
                    continue
                except NetworkError as exc:
                    out.errors.append(f"{channel}: {exc}")
                    continue
                searched += 1
                if not has_preview(response.final_url or url):
                    unavailable.append(channel)
                    break  # a group, a user or an unknown name: no other spelling will help
                page = parse_preview(channel, decode_html(response.body, "text/html"))
                for post in page.posts:
                    match = find_identifier(target, post.text)
                    if match and post.url not in found:
                        found[post.url] = (post, page.title, match, spelling)
            if stopped:
                break
        if stopped:
            out.limitations.append(f"Поиск по каналам остановлен: {stopped}")
        if unavailable:
            out.limitations.append(
                "Без публичного веб-просмотра (группа, пользователь или нет такого канала): "
                + ", ".join(unavailable[:15])
            )
        if channels and searched == 0 and out.errors:
            raise NetworkError(out.errors[0])
        out.findings.append(
            self._scope(target, channels, discovered, unavailable, searched, len(found))
        )
        out.findings.extend(
            self._post_finding(target, post, title, match, spelling)
            for post, title, match, spelling in found.values()
        )
        if not found:
            out.status = ModuleStatus.NO_RESULTS
        return out

    async def _discover(self, target: Target, ctx: ModuleContext, out: ModuleOutput) -> list[str]:
        providers = select_providers(ctx.settings)
        queries = self.discovery_queries(target, ctx.settings)
        if not providers or not queries:
            return []
        chain = SearchChain(providers, retry_wait=max(5.0, ctx.settings.searxng_min_interval * 5))
        markers = markers_for(target)
        names: list[str] = []
        for query in queries:
            try:
                _, response = await chain.search(ctx.net, query, ctx.settings.search_results)
            except NetworkError as exc:
                out.limitations.append(f"Поиск каналов «{query}» не выполнен: {exc}")
                continue
            for hit in response.hits:
                name = channel_from_url(hit.url)
                if name and mentions_identifier(target.type, markers, hit) and name not in names:
                    names.append(name)
        return names

    # ------------------------------------------------------------------ findings
    def _scope(
        self,
        target: Target,
        channels: list[str],
        discovered: list[str],
        unavailable: list[str],
        searched: int,
        posts: int,
    ) -> Finding:
        value: dict[str, JsonValue] = {
            "channels": list(channels),
            "found_by_search": list(discovered),
            "without_preview": list(unavailable),
            "requests": searched,
            "posts_with_identifier": posts,
        }
        return self.finding(
            target,
            "mention.telegram_search_scope",
            value,
            Confidence.CONFIRMED,
            "Telegram t.me/s",
            "https://t.me",
            f"Каналов: {len(channels)} (найдено поиском: {len(discovered)}); запросов к "
            f"t.me/s: {searched}; постов с идентификатором: {posts}. Это параметры поиска, а не "
            "сведения о человеке.",
            exclusive=True,
        )

    def _post_finding(
        self, target: Target, post: Post, title: str | None, match: Match, spelling: str
    ) -> Finding:
        value: dict[str, JsonValue] = {
            "url": post.url,
            "final_url": None,
            "title": title or post.channel,
            "site": "t.me",
            "resource": "social",
            "resource_label": "Соцсеть",
            "platform": f"Telegram @{post.channel}",
            "doc_type": None,
            "verification": Check.CONFIRMED.value,
            "verification_label": CHECK_LABELS[Check.CONFIRMED],
            "location": post.date[:10] if post.date else None,
            "fragment": match.fragment,
            "matched": match.variant,
            "weak_match": match.weak,
            "snippet": "",
            "snippet_match": False,
            "query": f"t.me/s/{post.channel}?q={spelling}",
            "dork_group": "Telegram (публичный канал)",
            "dorks": 1,
            "provider": "Telegram t.me/s",
        }
        weak = " (только инициалы — слабое совпадение)" if match.weak else ""
        return self.finding(
            target,
            "mention.telegram",
            value,
            Confidence.UNVERIFIED if match.weak else Confidence.LIKELY,
            f"Telegram: @{post.channel}",
            post.url,
            f"Пост в публичном канале @{post.channel}"
            + (f" от {post.date[:10]}" if post.date else "")
            + f" содержит «{match.variant}»{weak}. Найдено поиском t.me/s по «{spelling}». "
            "Упоминание может относиться к другому человеку; совпадение не устанавливает "
            "личность.",
        )

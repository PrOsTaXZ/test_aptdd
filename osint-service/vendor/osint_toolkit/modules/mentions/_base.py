"""Shared logic of mention modules: execute dorks, open the hits, confirm the identifier.

1. Simple, engine-friendly dorks (:func:`simple_dorks`) are executed through the provider chain
   (Brave Search API first if configured, local SearXNG as fallback) within
   ``OSINT_SEARCH_MAX_QUERIES``; every dork's result count is recorded and only dorks with
   results are reported (helper findings ``dork.hit``).
2. Result URLs are deduplicated; the most-supported ones (found by several dorks, best rank)
   are opened (``OSINT_VERIFY_PAGES``) by :class:`PageVerifier`: robots.txt, no JavaScript,
   size/time limits, documents parsed in the sandbox.
3. One finding per URL: resource type, fragment around the identifier, verification status.
   ``likely`` only when the identifier was found in the downloaded text; a snippet alone stays
   ``unverified``. Even a confirmed occurrence is not proof of identity.

Each module searches only for its own target; nothing found is turned into a new target.
"""

from __future__ import annotations

import asyncio
from abc import abstractmethod
from collections import Counter
from dataclasses import replace
from typing import ClassVar
from urllib.parse import urlsplit

from osint_toolkit.analysis.entities import entities_to_json, extract_near
from osint_toolkit.config import Settings
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    Finding,
    JsonValue,
    ModuleStatus,
    Target,
)
from osint_toolkit.dorks import Dork, simple_dorks
from osint_toolkit.dorks.builder import manual_links
from osint_toolkit.integrations.search import (
    MAX_QUERY_CHARS,
    SearchHit,
    provider_problem,
    select_providers,
)
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import NetworkError
from osint_toolkit.search.executor import DorkRun, SearchChain, run_dorks
from osint_toolkit.search.relevance import markers_for, relevant
from osint_toolkit.search.resources import classify, manual_only
from osint_toolkit.search.verify import Check, PageVerifier, Verification, manual_verification

GENERIC_SERVICE = ExternalService(
    name="Поисковый провайдер (Brave Search API и/или локальный SearXNG)",
    url="задаётся в настройках",
    data_sent="поисковые запросы с идентификатором",
)
PAGES_SERVICE = ExternalService(
    name="Сайты из результатов поиска",
    url="страницы и документы, найденные поисковиком",
    data_sent="обычный запрос страницы (без JavaScript, с учётом robots.txt); сайты видят "
    "ваш IP и User-Agent osint-toolkit",
)


class _Seen:
    """A result URL with every dork that returned it."""

    __slots__ = ("best", "dorks", "provider")

    def __init__(self, hit: SearchHit, dork: Dork, provider: str) -> None:
        self.best = hit
        self.dorks = [dork]
        self.provider = provider

    def add(self, hit: SearchHit, dork: Dork) -> None:
        self.dorks.append(dork)
        if hit.rank < self.best.rank:
            self.best = hit

    @property
    def score(self) -> tuple[int, int]:
        return (-len(self.dorks), self.best.rank)


class MentionModule(BaseModule):
    attribute: ClassVar[str]  # e.g. "mention.email"
    noun: ClassVar[str]  # "адрес", "номер", "ФИО" — for evidence texts
    external_services: ClassVar[tuple[ExternalService, ...]] = (GENERIC_SERVICE, PAGES_SERVICE)

    # ------------------------------------------------------------------ hooks
    @abstractmethod
    def snippet_contains(self, target: Target, text: str) -> bool:
        """Whether text literally contains the identifier (any accepted spelling)."""

    # ------------------------------------------------------------------ planning & consent
    def all_dorks(self, target: Target, settings: Settings) -> list[Dork]:
        dorks = simple_dorks(
            target,
            default_region=settings.default_region,
            enabled_groups=settings.enabled_dork_groups(),
        )
        return [d for d in dorks if len(d.query) <= MAX_QUERY_CHARS]

    def planned_dorks(self, target: Target, settings: Settings) -> list[Dork]:
        return self.all_dorks(target, settings)[: settings.search_max_queries]

    def planned_queries(self, target: Target, settings: Settings) -> list[str]:
        return [d.query for d in self.planned_dorks(target, settings)]

    def availability(self, settings: Settings) -> Availability:
        if not select_providers(settings):
            return Availability(False, provider_problem(settings))
        return Availability(True)

    def effective_timeout(self, settings: Settings) -> float:
        queries = settings.search_max_queries
        interval = max(settings.brave_min_interval, settings.searxng_min_interval)
        opened = settings.verify_pages + settings.verify_documents + settings.verify_social
        pages = opened / max(1, settings.verify_concurrency)
        budget = queries * (interval + 4) + pages * (settings.page_timeout + 5) + 60
        return float(min(max(budget, settings.module_timeout), 3600))

    def services_for(self, settings: Settings) -> tuple[ExternalService, ...]:
        chain = select_providers(settings)
        services = tuple(p.service() for p in chain) or (GENERIC_SERVICE,)
        opens = settings.verify_pages or settings.verify_documents or settings.verify_social
        return services + ((PAGES_SERVICE,) if opens else ())

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        chain = select_providers(settings)
        names = " → ".join(p.label for p in chain) or "провайдер"
        dorks = self.planned_dorks(target, settings)
        total = len(self.all_dorks(target, settings))
        lines = [f"[{d.title}] {d.query}" for d in dorks]
        lines.insert(0, f"{len(dorks)} запрос(ов) через {names} (пауза между запросами)")
        if total > len(dorks):
            lines.append(
                f"ещё {total - len(dorks)} запрос(ов) не войдут в лимит "
                f"OSINT_SEARCH_MAX_QUERIES={settings.search_max_queries}"
            )
        if settings.verify_pages or settings.verify_documents or settings.verify_social:
            lines.append(
                f"будут открыты для проверки до {settings.verify_pages} страниц, "
                f"{settings.verify_social} страниц соцсетей и {settings.verify_documents} "
                "документов (robots.txt соблюдается, без JavaScript; документы разбираются в "
                "песочнице без сети; VK, Facebook, Instagram, LinkedIn, TikTok, X не "
                "открываются — только ручная проверка)"
            )
        if any(not p.persist_results for p in chain):
            lines.append("результаты Brave будут показаны только в этой сессии (условия Brave API)")
        return tuple(lines)

    # ------------------------------------------------------------------ run
    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        providers = select_providers(settings)
        if not providers:
            out.errors.append(provider_problem(settings))
            return out
        chain = SearchChain(providers, retry_wait=max(5.0, settings.searxng_min_interval * 10))
        dorks = self.planned_dorks(target, settings)
        runs = await run_dorks(chain, ctx.net, dorks, settings.search_results, ctx.progress)
        dropped = self._drop_irrelevant(target, runs)
        executed = [r for r in runs if r.error is None]
        if dorks and not executed:  # nothing searched: an error, never "no mentions"
            raise NetworkError(runs[0].error or "поиск не выполнен")
        seen = self._collect(runs)
        verifications = await self._verify(target, ctx, seen)
        ephemeral_providers = {p.label for p in providers if not p.persist_results}

        for run in runs:
            if run.response is not None:
                out.limitations.extend(n for n in run.response.notes if n not in out.limitations)
        failed = [r for r in runs if r.error is not None]
        for label, reason in chain.down.items():
            out.limitations.append(f"{label} отключён до конца исследования: {reason}")
        if failed:
            out.limitations.append(
                f"Не выполнено запросов: {len(failed)} из {len(runs)} "
                f"(первая ошибка: {failed[0].error})"
            )
        if dropped:
            out.limitations.append(
                f"Отброшено нерелевантных результатов поисковиков: {dropped} (не тот сайт или "
                "тип файла, либо в заголовке, фрагменте и адресе нет идентификатора)"
            )
        out.findings.append(self._scope(target, chain, runs, verifications, dropped))
        out.findings.extend(self._dork_hits(target, runs, ephemeral_providers))
        for url, entry in sorted(seen.items(), key=lambda item: item[1].score):
            finding = self._page_finding(
                target, url, entry, verifications.get(url), settings.default_region
            )
            if entry.provider in ephemeral_providers:
                finding = finding.model_copy(update={"ephemeral": True})
            out.findings.append(finding)
        if any(p in ephemeral_providers for p in (e.provider for e in seen.values())):
            out.limitations.append(
                "Результаты Brave показаны только в этой сессии: условия Brave Search API "
                "запрещают сохранять поисковую выдачу, поэтому в историю и отчёты они не попадут."
            )
        if not seen:
            out.status = ModuleStatus.NO_RESULTS
        return out

    # ------------------------------------------------------------------ steps
    @staticmethod
    def _drop_irrelevant(target: Target, runs: list[DorkRun]) -> int:
        """Engines may ignore operators; keep only hits that fit the dork and the identifier."""
        markers = markers_for(target)
        dropped = 0
        for run in runs:
            if run.response is None:
                continue
            kept = [h for h in run.response.hits if relevant(target.type, markers, run.dork, h)]
            dropped += len(run.response.hits) - len(kept)
            run.response = replace(run.response, hits=kept)
        return dropped

    @staticmethod
    def _collect(runs: list[DorkRun]) -> dict[str, _Seen]:
        seen: dict[str, _Seen] = {}
        for run in runs:
            if run.response is None:
                continue
            for hit in run.response.hits:
                key = hit.url.split("#", 1)[0]
                if key in seen:
                    seen[key].add(hit, run.dork)
                else:
                    seen[key] = _Seen(hit, run.dork, run.provider or "?")
        return seen

    async def _verify(
        self, target: Target, ctx: ModuleContext, seen: dict[str, _Seen]
    ) -> dict[str, Verification]:
        settings = ctx.settings
        if not seen:
            return {}
        ranked = sorted(seen, key=lambda url: seen[url].score)
        # JS/sign-in-only platforms are never opened and never use a budget
        manual = {u: manual_verification(u) for u in ranked if manual_only(u)}
        rest = [u for u in ranked if u not in manual]
        kinds = {u: classify(u).kind for u in rest}
        # separate budgets, so ordinary pages can never use up documents or social networks
        ordered = (
            [u for u in rest if kinds[u] == "document"][: settings.verify_documents]
            + [u for u in rest if kinds[u] == "social"][: settings.verify_social]
            + [u for u in rest if kinds[u] not in ("document", "social")][: settings.verify_pages]
        )
        if not ordered:
            return manual
        verifier = PageVerifier(ctx.net, settings)
        semaphore = asyncio.Semaphore(settings.verify_concurrency)
        total, done = len(ordered), 0
        ctx.progress(0, total, f"Проверено страниц: 0 из {total}")

        async def one(url: str) -> tuple[str, Verification]:
            nonlocal done
            async with semaphore:
                result = url, await verifier.verify(target, url)
            done += 1
            ctx.progress(done, total, f"Проверено страниц: {done} из {total}")
            return result

        return manual | dict(await asyncio.gather(*(one(url) for url in ordered)))

    def _scope(
        self,
        target: Target,
        chain: SearchChain,
        runs: list[DorkRun],
        verifications: dict[str, Verification],
        dropped: int = 0,
    ) -> Finding:
        with_hits = sum(1 for r in runs if r.count)
        counts = Counter(v.status.label for v in verifications.values())
        statuses: dict[str, JsonValue] = dict(counts)
        scope: dict[str, JsonValue] = {
            "providers": chain.labels,
            "queries_planned": len(runs),
            "queries_with_results": with_hits,
            "queries_empty": sum(1 for r in runs if r.error is None and not r.count),
            "queries_failed": sum(1 for r in runs if r.error is not None),
            "irrelevant_dropped": dropped,
            "pages_checked": len(verifications),
            "verification": statuses,
        }
        confirmed = sum(1 for v in verifications.values() if v.status is Check.CONFIRMED)
        return self.finding(
            target,
            f"{self.attribute}_search_scope",
            scope,
            Confidence.CONFIRMED,
            " → ".join(chain.labels),
            _provider_url(chain.labels[0] if chain.labels else ""),
            f"Запросов с результатами: {with_hits} из {len(runs)}; открыто страниц: "
            f"{len(verifications)}, идентификатор подтверждён на {confirmed}. Это параметры "
            "поиска, а не сведения о человеке.",
            exclusive=True,
        )

    def _dork_hits(
        self, target: Target, runs: list[DorkRun], ephemeral_providers: set[str]
    ) -> list[Finding]:
        findings = []
        for run in runs:
            if not run.count:
                continue
            value: dict[str, JsonValue] = {
                "group": run.dork.title,
                "query": run.dork.query,
                "hits": run.count,
                "provider": run.provider,
                **manual_links(run.dork.query),
            }
            finding = self.finding(
                target,
                "dork.hit",
                value,
                Confidence.CONFIRMED,
                f"Дорк «{run.dork.title}»",
                value["google"],  # type: ignore[arg-type]
                f"{run.provider} вернул {run.count} результат(ов) по этому запросу.",
            )
            if run.provider in ephemeral_providers:
                finding = finding.model_copy(update={"ephemeral": True})
            findings.append(finding)
        return findings

    def _page_finding(
        self,
        target: Target,
        url: str,
        entry: _Seen,
        check: Verification | None,
        region: str | None = None,
    ) -> Finding:
        hit = entry.best
        resource = check.resource if check else classify(url)
        snippet_match = self.snippet_contains(target, f"{hit.title} {hit.snippet}")
        status = check.status if check else Check.SKIPPED
        fragment = check.match.fragment if check and check.match else hit.snippet
        if check and check.status is Check.CONFIRMED:
            entities = list(check.entities)
            entities_from: str | None = "page"
        else:  # only the search engine's words: typed from the title and snippet
            entities = extract_near(
                target,
                f"{hit.title}\n{hit.snippet}",
                region=region,
                whole=True,
            )
            entities_from = "snippet" if entities else None
        value: dict[str, JsonValue] = {
            "url": url,
            "final_url": check.final_url if check else None,
            "title": hit.title,
            "site": urlsplit(url).hostname,
            "resource": resource.kind,
            "resource_label": resource.label,
            "platform": resource.platform,
            "doc_type": resource.doc_type,
            "verification": status.value,
            "verification_label": status.label,
            "location": check.location if check else None,
            "fragment": fragment,
            "matched": check.match.variant if check and check.match else None,
            "weak_match": bool(check and check.match and check.match.weak),
            "snippet": hit.snippet,
            "snippet_match": snippet_match,
            "http_status": check.http_status if check else None,
            "detail": check.detail if check else None,
            "query": entry.dorks[0].query,
            "dork_group": entry.dorks[0].title,
            "dorks": len(entry.dorks),
            "provider": entry.provider,
            "entities": entities_to_json(entities),
            "entities_from": entities_from,
        }
        confirmed = status is Check.CONFIRMED
        where = f" ({check.location})" if check and check.location else ""
        matched = check.match.variant if check and check.match else ""
        evidence = (
            (
                f"Страница загружена, {self.noun} найден в её тексте{where}: «{matched}»"
                + (" (только инициалы — слабое совпадение)" if value["weak_match"] else "")
                + ". "
                if confirmed
                else f"Проверка страницы: {status.label}"
                + (f" — {check.detail}" if check and check.detail else "")
                + ". Совпадение известно только со слов поисковика"
                + (" (фрагмент содержит идентификатор). " if snippet_match else ". ")
            )
            + f"Найдено {entry.provider} по {len(entry.dorks)} запрос(ам), первый: "
            f"«{entry.dorks[0].query}». Упоминание может относиться к другому человеку; "
            "совпадение не устанавливает личность."
        )
        return self.finding(
            target,
            self.attribute,
            value,
            Confidence.LIKELY if confirmed and not value["weak_match"] else Confidence.UNVERIFIED,
            f"{resource.label}: {resource.platform or urlsplit(url).hostname}",
            url,
            evidence,
        )


def _provider_url(label: str) -> str:
    return (
        "https://brave.com/search/api/"
        if label.startswith("Brave")
        else "https://docs.searxng.org/dev/search_api.html"
    )

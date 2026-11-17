"""Run dorks through a chain of search providers with failover, caching and a budget.

The chain tries providers in order (official APIs first, SearXNG as fallback). A provider that
reports an exhausted quota, a rejected key or rate limiting is switched off for the rest of the
investigation; a SearXNG answer with no results while its engines failed is retried once after a
pause and then reported as an error ("result unknown"), never as "nothing found"; after several
such answers in a row the provider is switched off. "Its engines failed" means every engine that
already returned results in this run is among the failed ones (an always-failing engine such as
a CAPTCHA-blocked one does not turn honest empty answers into errors). Identical queries are
answered from a per-run cache.
Pacing between requests is done by each provider's shared rate limiter.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field

from osint_toolkit.dorks import Dork
from osint_toolkit.integrations.search import SearchProvider, SearchResponse
from osint_toolkit.net import NetworkError, NetworkServices

FATAL_MARKERS = ("429", "квот", "ключ", "лимит", "suspended", "too many")


@dataclass(slots=True)
class DorkRun:
    dork: Dork
    provider: str | None = None
    response: SearchResponse | None = None
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.response.hits) if self.response else 0


@dataclass(slots=True)
class SearchChain:
    providers: list[SearchProvider]
    retry_wait: float = 20.0  # pause before re-asking a provider whose engines did not answer
    max_degraded: int = 3  # consecutive "engines did not answer" before switching it off
    down: dict[str, str] = field(default_factory=dict)  # provider label → reason
    _cache: dict[str, tuple[str, SearchResponse]] = field(default_factory=dict)
    _degraded: dict[str, int] = field(default_factory=dict)
    _answering: dict[str, set[str]] = field(default_factory=dict)  # engines that gave results

    @property
    def labels(self) -> list[str]:
        return [p.label for p in self.providers]

    @property
    def persist_results(self) -> bool:
        return all(p.persist_results for p in self.providers)

    async def _ask(
        self, provider: SearchProvider, net: NetworkServices, query: str, count: int
    ) -> SearchResponse:
        """One provider; an empty answer while its engines failed is retried once, then is an
        error — never "nothing found"."""
        response = await provider.search(net, query, count)
        if not self._blind(provider.label, response):
            return response
        await asyncio.sleep(self.retry_wait)
        response = await provider.search(net, query, count)
        if not self._blind(provider.label, response):
            return response
        failures = self._degraded.get(provider.label, 0) + 1
        self._degraded[provider.label] = failures
        engines = ", ".join(response.failed_engines)
        reason = f"поисковики не ответили ({engines}) — результат неизвестен"
        if failures >= self.max_degraded:
            self.down[provider.label] = (
                f"движки перестали отвечать {failures} раз подряд (вероятно, ограничение "
                "частоты запросов)"
            )
        raise NetworkError(reason)

    def _blind(self, label: str, response: SearchResponse) -> bool:
        """True if the answer cannot be trusted: no hits and all useful engines failed."""
        answering = self._answering.setdefault(label, set())
        for hit in response.hits:
            answering.update(hit.engines)
        if response.hits or not response.degraded:
            self._degraded[label] = 0
            return False
        failed = set(response.failed_engines)
        if answering and not answering <= failed:
            self._degraded[label] = 0
            return False  # a working engine answered: the query is genuinely empty
        return True

    async def search(
        self, net: NetworkServices, query: str, count: int
    ) -> tuple[str, SearchResponse]:
        if query in self._cache:
            return self._cache[query]
        errors: list[str] = []
        for provider in self.providers:
            if provider.label in self.down:
                continue
            try:
                response = await self._ask(provider, net, query, count)
            except NetworkError as exc:
                text = str(exc)
                errors.append(f"{provider.label}: {text}")
                if any(m in text.lower() for m in FATAL_MARKERS):
                    self.down[provider.label] = text
                continue
            self._cache[query] = (provider.label, response)
            return provider.label, response
        raise NetworkError("; ".join(errors) or "нет доступных поисковых провайдеров")


async def run_dorks(
    chain: SearchChain,
    net: NetworkServices,
    dorks: list[Dork],
    count: int,
    progress: Callable[[int, int | None, str], None] | None = None,
) -> list[DorkRun]:
    """Execute every dork (sequentially; providers pace themselves)."""
    runs: list[DorkRun] = []
    for dork in dorks:
        if progress is not None:
            progress(len(runs), len(dorks), f"Поисковых запросов: {len(runs)} из {len(dorks)}")
        run = DorkRun(dork)
        try:
            run.provider, run.response = await chain.search(net, dork.query, count)
        except NetworkError as exc:
            run.error = str(exc)
        runs.append(run)
        if len(chain.down) == len(chain.providers):
            for rest in dorks[len(runs) :]:
                runs.append(DorkRun(rest, error="все поисковые провайдеры недоступны"))
            break
    return runs

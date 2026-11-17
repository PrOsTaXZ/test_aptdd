"""Web search providers for public-mention modules.

* **SearXNG** (self-hosted, AGPL; we only call its HTTP API): ``GET /search?q=…&format=json``.
  JSON must be enabled in ``settings.yml`` (``search.formats: [html, json]``), otherwise the
  instance answers 403. Results are stored like any other finding.
* **Brave Search API**: ``GET https://api.search.brave.com/res/v1/web/search`` with header
  ``X-Subscription-Token``. Brave's API terms (§3(b)(i)) forbid storing or caching search
  results beyond transient use, so Brave findings are marked ephemeral: shown in the session,
  never written to history or reports.

Both providers share a per-investigation rate limiter and go through :class:`HttpClient`
(timeouts, size caps, 429/5xx handling). No result is ever merged across identifiers.
"""

from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from osint_toolkit.config import Settings
from osint_toolkit.core.models import ExternalService
from osint_toolkit.net import HttpStatusError, NetworkError, NetworkServices

BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
BRAVE_TERMS = "https://api-dashboard.search.brave.com/terms-of-service"
_TAG_RE = re.compile(r"<[^>]{0,200}>")
MAX_QUERY_CHARS = 380


def clean_text(value: Any, limit: int = 400) -> str:
    """Plain text from provider snippets (tags removed, entities decoded, whitespace folded)."""
    if not isinstance(value, str):
        return ""
    text = " ".join(html.unescape(_TAG_RE.sub("", value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True, slots=True)
class SearchHit:
    title: str
    url: str
    snippet: str
    rank: int
    engines: tuple[str, ...] = ()


@dataclass(slots=True)
class SearchResponse:
    provider: str
    query: str
    hits: list[SearchHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    failed_engines: list[str] = field(default_factory=list)  # SearXNG engines that did not answer

    @property
    def degraded(self) -> bool:
        return bool(self.failed_engines)


class SearchProvider(Protocol):
    key: str
    label: str
    persist_results: bool
    supports_or: bool

    def service(self) -> ExternalService: ...

    async def search(self, net: NetworkServices, query: str, count: int) -> SearchResponse: ...


def _web_url(url: Any) -> str | None:
    if isinstance(url, str) and url.startswith(("https://", "http://")) and len(url) < 2048:
        return url
    return None


# --------------------------------------------------------------------------- SearXNG
def is_local_host(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".lan", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


class SearxngProvider:
    key = "searxng"
    persist_results = True
    supports_or = True  # passed through to Google/Bing-style engines

    def __init__(self, base_url: str, settings: Settings) -> None:
        self.base_url = base_url.rstrip("/")
        self.settings = settings
        self.label = f"SearXNG ({urlsplit(self.base_url).netloc})"

    def service(self) -> ExternalService:
        where = (
            "локальный экземпляр"
            if is_local_host(self.base_url)
            else "ВНЕШНИЙ экземпляр — его владелец увидит запросы"
        )
        return ExternalService(
            name=f"SearXNG — {where}",
            url=self.base_url,
            data_sent="поисковые запросы ниже; SearXNG пересылает их выбранным поисковикам",
        )

    async def search(self, net: NetworkServices, query: str, count: int) -> SearchResponse:
        await net.limiter(self.key, self.settings.searxng_min_interval).wait()
        try:
            data = await net.http.get_json(
                f"{self.base_url}/search",
                params={"q": query, "format": "json", "pageno": "1", "safesearch": "0"},
                headers={"Accept": "application/json", "Accept-Language": "ru,en;q=0.8"},
            )
        except HttpStatusError as exc:
            if exc.status_code == 403:
                raise NetworkError(
                    "SearXNG отклонил JSON-запрос (403): включите формат json в settings.yml "
                    "(search: formats: [html, json]) и/или добавьте этот хост в pass_ip лимитера"
                ) from exc
            if exc.status_code == 429:
                raise NetworkError("SearXNG ограничил частоту запросов (429, limiter)") from exc
            raise
        response = SearchResponse(self.label, query)
        if not isinstance(data, dict):
            raise NetworkError("SearXNG вернул неожиданный формат")
        for index, item in enumerate(data.get("results") or []):
            if not isinstance(item, dict) or len(response.hits) >= count:
                continue
            url = _web_url(item.get("url"))
            if url is None:
                continue
            engines = item.get("engines") or ([item["engine"]] if item.get("engine") else [])
            response.hits.append(
                SearchHit(
                    title=clean_text(item.get("title"), 200) or url,
                    url=url,
                    snippet=clean_text(item.get("content")),
                    rank=index + 1,
                    engines=tuple(str(e) for e in engines if isinstance(e, str)),
                )
            )
        failed = data.get("unresponsive_engines") or []
        if failed:
            names = sorted(
                {str(e[0]) if isinstance(e, list | tuple) and e else str(e) for e in failed}
            )
            response.failed_engines = names
            response.notes.append(f"Не ответили поисковики: {', '.join(names)}")
        return response


# --------------------------------------------------------------------------- Brave
class BraveProvider:
    key = "brave"
    label = "Brave Search API"
    supports_or = False  # OR is not documented for the API: one variant per query
    persist_results = False  # API terms §3(b)(i): no storing/caching of search results

    def __init__(self, api_key: str, settings: Settings) -> None:
        self._api_key = api_key
        self.settings = settings

    def service(self) -> ExternalService:
        return ExternalService(
            name="Brave Search API",
            url="https://api.search.brave.com",
            data_sent="поисковые запросы ниже и ваш API-ключ; Brave видит ваш IP",
        )

    async def search(self, net: NetworkServices, query: str, count: int) -> SearchResponse:
        await net.limiter(self.key, self.settings.brave_min_interval).wait()
        try:
            result = await net.http.fetch(
                BRAVE_ENDPOINT,
                params={"q": query, "count": str(min(count, 20)), "safesearch": "off"},
                headers={"X-Subscription-Token": self._api_key, "Accept": "application/json"},
            )
        except HttpStatusError as exc:
            if exc.status_code in (401, 403):
                raise NetworkError(
                    "Brave отклонил ключ API (HTTP "
                    f"{exc.status_code}): проверьте OSINT_BRAVE_API_KEY"
                ) from exc
            if exc.status_code == 429:
                reset = exc.headers.get("x-ratelimit-reset", "")
                hint = f", сброс через {reset} с" if reset else ""
                raise NetworkError(f"Brave: превышен лимит запросов или квота (429{hint})") from exc
            raise
        data = result.json()
        response = SearchResponse(self.label, query)
        web = data.get("web") if isinstance(data, dict) else None
        items = web.get("results") if isinstance(web, dict) else None
        for index, item in enumerate(items or []):
            if not isinstance(item, dict) or len(response.hits) >= count:
                continue
            url = _web_url(item.get("url"))
            if url is None:
                continue
            response.hits.append(
                SearchHit(
                    title=clean_text(item.get("title"), 200) or url,
                    url=url,
                    snippet=clean_text(item.get("description")),
                    rank=index + 1,
                )
            )
        remaining = result.headers.get("x-ratelimit-remaining") or result.headers.get(
            "X-RateLimit-Remaining"
        )
        if remaining:
            response.notes.append(f"Brave: остаток лимитов (секунда, месяц): {remaining}")
        return response


def select_providers(settings: Settings) -> list[SearchProvider]:
    """Provider chain: the official API first (if a key is set), SearXNG as fallback."""
    searxng = str(settings.searxng_url) if settings.searxng_url else None
    brave = settings.brave_api_key.get_secret_value() if settings.brave_api_key else None
    choice = settings.search_provider
    chain: list[SearchProvider] = []
    if choice in ("auto", "brave") and brave:
        chain.append(BraveProvider(brave, settings))
    if choice in ("auto", "searxng") and searxng:
        chain.append(SearxngProvider(searxng, settings))
    return chain


def select_provider(settings: Settings) -> SearchProvider | None:
    chain = select_providers(settings)
    return chain[0] if chain else None


def provider_problem(settings: Settings) -> str:
    if settings.search_provider == "searxng":
        return "не задан OSINT_SEARXNG_URL (локальный SearXNG с форматом json)"
    if settings.search_provider == "brave":
        return "не задан OSINT_BRAVE_API_KEY"
    return "нет поискового провайдера: задайте OSINT_SEARXNG_URL или OSINT_BRAVE_API_KEY"

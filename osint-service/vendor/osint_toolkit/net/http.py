"""HTTP client with concurrency limits, timeouts, response size caps and bounded retries."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from osint_toolkit import __version__
from osint_toolkit.config import Settings
from osint_toolkit.net.errors import (
    HttpStatusError,
    NetworkError,
    NetworkTimeoutError,
    ResponseTooLargeError,
)

log = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_RETRY_AFTER = 5.0
USER_AGENT = f"osint-toolkit/{__version__} (personal research tool)"


class HttpClient:
    """Thin wrapper over :class:`httpx.AsyncClient`.

    Limits: ``http_concurrency`` requests in flight in total and ``http_per_host`` per host.
    ``trust_env`` is off so ``~/.netrc`` credentials are never attached; a proxy can be set
    explicitly with ``OSINT_HTTP_PROXY``.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        retry_delay: float = 1.0,
    ) -> None:
        self.settings = settings
        self.retry_delay = retry_delay
        self._global = asyncio.Semaphore(settings.http_concurrency)
        self._hosts: dict[str, asyncio.Semaphore] = {}
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout, connect=min(10.0, settings.http_timeout)),
            limits=httpx.Limits(
                max_connections=settings.http_concurrency,
                max_keepalive_connections=settings.http_concurrency,
            ),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"},
            follow_redirects=True,
            max_redirects=5,
            trust_env=False,
            proxy=str(settings.http_proxy) if settings.http_proxy else None,
            transport=transport,
        )

    @property
    def raw(self) -> httpx.AsyncClient:
        """Underlying client for libraries that need one (use inside :meth:`slot`)."""
        return self._client

    @asynccontextmanager
    async def slot(self, url: str) -> AsyncIterator[None]:
        """Acquire the global and per-host concurrency slots for a request to ``url``."""
        host = urlsplit(url).hostname or ""
        per_host = self._hosts.setdefault(host, asyncio.Semaphore(self.settings.http_per_host))
        async with self._global, per_host:
            yield

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ requests
    async def fetch(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        request_timeout: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        retries: int = 1,
        accept_status: frozenset[int] = frozenset({200}),
    ) -> HttpResponse:
        """GET with limits and bounded retries (timeouts, 429, 502-504)."""
        host = urlsplit(url).hostname or url
        attempt = 0
        while True:
            attempt += 1
            try:
                async with self.slot(url):
                    return await self._fetch(
                        url, params, headers, request_timeout, max_bytes, accept_status
                    )
            except (NetworkTimeoutError, HttpStatusError) as exc:
                status = getattr(exc, "status_code", None)
                retryable = isinstance(exc, NetworkTimeoutError) or status in RETRY_STATUSES
                if not retryable or attempt > retries:
                    raise
                delay = getattr(exc, "retry_after", None) or self.retry_delay * attempt
                if delay > MAX_RETRY_AFTER:  # e.g. monthly quota: waiting would not help
                    raise
                log.info("retrying %s after %s (attempt %d)", host, type(exc).__name__, attempt)
                await asyncio.sleep(delay)

    async def get_bytes(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        request_timeout: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        retries: int = 1,
        accept_status: frozenset[int] = frozenset({200}),
    ) -> tuple[int, bytes]:
        response = await self.fetch(
            url,
            params=params,
            request_timeout=request_timeout,
            max_bytes=max_bytes,
            retries=retries,
            accept_status=accept_status,
        )
        return response.status, response.body

    async def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        request_timeout: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        retries: int = 1,
    ) -> Any:
        response = await self.fetch(
            url,
            params=params,
            headers=headers,
            request_timeout=request_timeout,
            max_bytes=max_bytes,
            retries=retries,
        )
        return response.json()

    async def post_multipart(
        self,
        url: str,
        *,
        files: Mapping[str, tuple[str, bytes, str]],
        data: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        request_timeout: float | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> HttpResponse:
        """Single multipart POST (no automatic retry: uploads may be billed)."""
        host = urlsplit(url).hostname
        effective = request_timeout or self.settings.http_timeout
        try:
            async with self.slot(url):
                response = await self._client.post(
                    url,
                    files=dict(files),
                    data=dict(data or {}),
                    headers=dict(headers or {}),
                    timeout=httpx.Timeout(effective, connect=10.0),
                )
        except httpx.TimeoutException as exc:
            raise NetworkTimeoutError(f"{host} не ответил за {effective:g} с") from exc
        except httpx.ConnectError as exc:
            raise NetworkError(f"Не удалось подключиться к {host}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"Ошибка HTTP при обращении к {host}: {type(exc).__name__}") from exc
        if len(response.content) > max_bytes:
            raise ResponseTooLargeError(f"Ответ {host} превысил лимит {max_bytes // 1024} КБ")
        return HttpResponse(url, response.status_code, response.content, dict(response.headers))

    async def head(self, url: str) -> httpx.Response:
        host = urlsplit(url).hostname
        try:
            async with self.slot(url):
                return await self._client.head(url)
        except httpx.TimeoutException as exc:
            raise NetworkTimeoutError(f"{host} не ответил вовремя") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"Ошибка соединения с {host}: {type(exc).__name__}") from exc

    async def _fetch(
        self,
        url: str,
        params: Mapping[str, str] | None,
        headers: Mapping[str, str] | None,
        request_timeout: float | None,
        max_bytes: int,
        accept_status: frozenset[int],
    ) -> HttpResponse:
        host = urlsplit(url).hostname
        effective = request_timeout or self.settings.http_timeout
        try:
            async with self._client.stream(
                "GET",
                url,
                params=params,
                headers=dict(headers or {}),
                timeout=httpx.Timeout(effective, connect=10.0),
            ) as response:
                if response.status_code not in accept_status:
                    error = HttpStatusError(
                        f"{host} ответил HTTP {response.status_code}",
                        response.status_code,
                        headers=dict(response.headers),
                    )
                    retry_after = response.headers.get("Retry-After", "")
                    if retry_after.isdigit():
                        error.retry_after = float(retry_after)
                    elif response.status_code == 429:
                        error.retry_after = rate_limit_wait(response.headers)
                    raise error
                declared = response.headers.get("Content-Length", "")
                if declared.isdigit() and int(declared) > max_bytes:
                    raise ResponseTooLargeError(
                        f"Ответ {host} слишком большой ({int(declared) // 1024} КБ)"
                    )
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ResponseTooLargeError(
                            f"Ответ {host} превысил лимит {max_bytes // 1024} КБ"
                        )
                    chunks.append(chunk)
                return HttpResponse(
                    url,
                    response.status_code,
                    b"".join(chunks),
                    dict(response.headers),
                    final_url=str(response.url),
                )
        except httpx.TimeoutException as exc:
            raise NetworkTimeoutError(f"{host} не ответил за {effective:g} с") from exc
        except httpx.TooManyRedirects as exc:
            raise NetworkError(f"{host}: слишком много перенаправлений") from exc
        except httpx.ConnectError as exc:
            raise NetworkError(f"Не удалось подключиться к {host}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"Ошибка HTTP при обращении к {host}: {type(exc).__name__}") from exc


def rate_limit_wait(headers: Mapping[str, str]) -> float | None:
    """Seconds until an exhausted window resets, from ``X-RateLimit-Reset`` (comma-separated,
    one value per window) and ``X-RateLimit-Remaining``. A long wait means a quota is used up,
    so retrying is pointless; a short one is a per-second limit."""
    lowered = {k.lower(): v for k, v in headers.items()}
    resets = [p.strip() for p in lowered.get("x-ratelimit-reset", "").split(",")]
    remaining = [p.strip() for p in lowered.get("x-ratelimit-remaining", "").split(",")]
    values = [float(r) for r in resets if r.replace(".", "", 1).isdigit()]
    if not values:
        return None
    exhausted = [
        float(r)
        for r, left in zip(resets, remaining, strict=False)
        if left == "0" and r.replace(".", "", 1).isdigit()
    ]
    return max(exhausted) if exhausted else max(values)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    url: str
    status: int
    body: bytes
    headers: dict[str, str]
    final_url: str | None = None  # after redirects

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise NetworkError(f"{urlsplit(self.url).hostname} вернул некорректный JSON") from exc

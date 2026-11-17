"""Lazily created network services for one investigation."""

from __future__ import annotations

from collections.abc import Callable

from osint_toolkit.config import Settings
from osint_toolkit.net.dns import DnsClient, DnsResult, SystemDnsClient
from osint_toolkit.net.errors import NetworkDisabledError
from osint_toolkit.net.http import HttpClient
from osint_toolkit.net.ratelimit import RateLimiter

_DISABLED_MESSAGE = "Сетевой доступ запрещён для этого модуля (офлайн или нет согласия)"


class NetworkServices:
    """HTTP and DNS clients, created on first use and shared by allowed modules.

    Nothing touches the network until a module actually calls ``http`` or ``dns``; in offline
    mode the engine never creates an instance at all.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        http_factory: Callable[[Settings], HttpClient] | None = None,
        dns_factory: Callable[[Settings], DnsClient] | None = None,
    ) -> None:
        self.settings = settings
        self._http_factory: Callable[[Settings], HttpClient] = http_factory or HttpClient
        self._dns_factory: Callable[[Settings], DnsClient] = dns_factory or SystemDnsClient
        self._http: HttpClient | None = None
        self._dns: DnsClient | None = None
        self._limiters: dict[str, RateLimiter] = {}

    @property
    def enabled(self) -> bool:
        return True

    @property
    def http(self) -> HttpClient:
        if self._http is None:
            self._http = self._http_factory(self.settings)
        return self._http

    @property
    def dns(self) -> DnsClient:
        if self._dns is None:
            self._dns = self._dns_factory(self.settings)
        return self._dns

    def limiter(self, key: str, min_interval: float) -> RateLimiter:
        """Shared per-provider limiter (one per investigation)."""
        if key not in self._limiters:
            self._limiters[key] = RateLimiter(min_interval)
        return self._limiters[key]

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None


class _DisabledDns:
    resolver_label = "disabled"

    async def query(self, name: str, rdtype: str) -> DnsResult:
        raise NetworkDisabledError(_DISABLED_MESSAGE)


class _DisabledNetwork(NetworkServices):
    def __init__(self) -> None:
        pass

    @property
    def enabled(self) -> bool:
        return False

    @property
    def http(self) -> HttpClient:
        raise NetworkDisabledError(_DISABLED_MESSAGE)

    @property
    def dns(self) -> DnsClient:
        return _DisabledDns()

    def limiter(self, key: str, min_interval: float) -> RateLimiter:
        raise NetworkDisabledError(_DISABLED_MESSAGE)

    async def aclose(self) -> None:
        return None


DISABLED_NETWORK: NetworkServices = _DisabledNetwork()

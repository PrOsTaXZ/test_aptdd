"""DNS client with explicit result states.

The distinction matters for honest reporting:

* ``NXDOMAIN`` — the name does not exist;
* ``NODATA``   — the name exists but has no records of this type;
* ``ERROR``    — timeout, SERVFAIL, refused, no resolver… — *nothing* can be concluded.
"""

from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

from osint_toolkit.config import Settings


class DnsStatus(enum.StrEnum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class DnsResult:
    name: str
    rdtype: str
    status: DnsStatus
    records: tuple[str, ...] = ()
    ttl: int | None = None
    resolver: str = "system"
    canonical_name: str | None = None  # set when the answer followed a CNAME
    error: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def source_url(self) -> str:
        """RFC 4501 DNS URI naming the resolver, the name and the record type."""
        authority = self.resolver if self.resolver not in ("", "system") else ""
        return f"dns://{authority}/{quote(self.name.rstrip('.'))}?type={self.rdtype}"

    @property
    def source_name(self) -> str:
        return f"DNS {self.rdtype} (резолвер {self.resolver})"


class DnsClient(Protocol):
    resolver_label: str

    async def query(self, name: str, rdtype: str) -> DnsResult: ...


def _text(rdtype: str, rdata: object) -> str:
    if rdtype == "TXT":
        strings = getattr(rdata, "strings", ())
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(rdata.to_text())  # type: ignore[attr-defined]


class SystemDnsClient:
    """Uses the system resolver configuration (``/etc/resolv.conf``)."""

    def __init__(self, settings: Settings) -> None:
        self._semaphore = asyncio.Semaphore(settings.dns_concurrency)
        self._timeout = settings.dns_timeout
        self._config_error: str | None = None
        self._resolver: dns.asyncresolver.Resolver | None
        self.resolver_label: str = "system"
        try:
            self._resolver = dns.asyncresolver.Resolver()
        except dns.resolver.NoResolverConfiguration as exc:
            self._resolver = None
            self._config_error = f"DNS-резолвер не настроен: {exc}"
            return
        self._resolver.lifetime = settings.dns_timeout
        self._resolver.timeout = min(2.0, settings.dns_timeout)
        if self._resolver.nameservers:
            self.resolver_label = str(self._resolver.nameservers[0])

    def _make(
        self, name: str, rdtype: str, status: DnsStatus, error: str | None = None
    ) -> DnsResult:
        return DnsResult(
            name=name, rdtype=rdtype, status=status, resolver=self.resolver_label, error=error
        )

    async def query(self, name: str, rdtype: str) -> DnsResult:
        if self._resolver is None:
            return self._make(name, rdtype, DnsStatus.ERROR, self._config_error)
        try:
            async with self._semaphore:
                answer = await self._resolver.resolve(name, rdtype, search=False)
        except dns.resolver.NXDOMAIN:
            return self._make(name, rdtype, DnsStatus.NXDOMAIN)
        except dns.resolver.NoAnswer:
            return self._make(name, rdtype, DnsStatus.NODATA)
        except dns.resolver.LifetimeTimeout:
            return self._make(name, rdtype, DnsStatus.ERROR, f"таймаут DNS ({self._timeout:g} с)")
        except dns.resolver.NoNameservers as exc:
            return self._make(
                name, rdtype, DnsStatus.ERROR, f"серверы не дали ответа (SERVFAIL/REFUSED): {exc}"
            )
        except (dns.name.LabelTooLong, dns.name.NameTooLong, dns.name.EmptyLabel) as exc:
            return self._make(name, rdtype, DnsStatus.ERROR, f"некорректное имя: {exc}")
        except dns.exception.DNSException as exc:
            return self._make(name, rdtype, DnsStatus.ERROR, f"{type(exc).__name__}: {exc}")
        records = tuple(_text(rdtype, r) for r in answer)
        canonical = answer.canonical_name.to_text().rstrip(".")
        rrset = answer.rrset
        return DnsResult(
            name=name,
            rdtype=rdtype,
            status=DnsStatus.OK if records else DnsStatus.NODATA,
            records=records,
            ttl=rrset.ttl if rrset is not None else None,
            resolver=self.resolver_label,
            canonical_name=canonical if canonical.lower() != name.rstrip(".").lower() else None,
        )

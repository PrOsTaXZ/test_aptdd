"""Shared pieces for DNS-based modules."""

from __future__ import annotations

from typing import ClassVar

from osint_toolkit.core.models import Confidence, ExternalService, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleOutput
from osint_toolkit.net import DnsResult, DnsStatus

DNS_SERVICE = ExternalService(
    name="DNS-резолвер системы и авторитетные DNS-серверы",
    url="настройки /etc/resolv.conf",
    data_sent="доменное имя (и служебные имена вроде _dmarc.<домен>)",
)

DNS_LIMITATION = (
    "Ответы DNS отражают состояние на момент запроса через ваш резолвер; кэш и split-horizon "
    "DNS могут давать другие ответы в других сетях."
)


def target_domain(target: Target) -> str:
    """Domain of a DOMAIN target or of an EMAIL target's address."""
    if target.type is TargetType.EMAIL:
        return str(target.details.get("domain") or target.normalized.rpartition("@")[2]).lower()
    return target.normalized.lower()


class DnsModule(BaseModule):
    """Base for modules that query DNS for a domain (or an email's domain)."""

    external_services: ClassVar[tuple[ExternalService, ...]] = (DNS_SERVICE,)
    limitations: ClassVar[tuple[str, ...]] = (DNS_LIMITATION,)

    def dedupe_key(self, target: Target) -> str:
        return f"domain:{target_domain(target)}"

    def record_error(self, out: ModuleOutput, result: DnsResult) -> None:
        out.errors.append(
            f"{result.rdtype} {result.name}: {result.error or 'ошибка DNS'} — вывод не делается"
        )

    def nxdomain(self, target: Target, out: ModuleOutput, result: DnsResult) -> None:
        """Record that the name does not exist (confirmed by the resolver)."""
        out.findings.append(
            self.finding(
                target,
                "domain.exists",
                False,
                Confidence.CONFIRMED,
                result.source_name,
                result.source_url,
                f"Резолвер ответил NXDOMAIN на запрос {result.rdtype} {result.name}: такого имени "
                "в DNS нет.",
                subject=result.name.rstrip("."),
                exclusive=True,
            )
        )


def is_nxdomain(result: DnsResult) -> bool:
    return result.status is DnsStatus.NXDOMAIN

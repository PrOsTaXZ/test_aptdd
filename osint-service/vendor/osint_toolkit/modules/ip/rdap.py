"""IP network registration data from the responsible Regional Internet Registry (RDAP)."""

from __future__ import annotations

from typing import Any, ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Confidence, ExternalService, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import NetworkError
from osint_toolkit.net.rdap import RdapUnsupportedError, endpoint_for, ensure_bootstrap, parse_rdap


def non_global_reason(target: Target) -> str | None:
    if target.details.get("is_global"):
        return None
    return (
        "адрес не глобальный (частный, служебный или зарезервированный) — внешний запрос не нужен"
    )


class IpRdapModule(BaseModule):
    name = "ip.rdap"
    title = "Регистрация IP-сети (RDAP)"
    description = (
        "Сеть, диапазон, тип назначения, страна из записи RIR, организация и abuse-контакт по "
        "данным регионального интернет-регистратора."
    )
    target_types = frozenset({TargetType.IP})
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="IANA RDAP bootstrap",
            url="https://data.iana.org/rdap/",
            data_sent="ничего о цели (списки серверов, кэшируются на 7 дней)",
        ),
        ExternalService(
            name="RDAP-сервер RIR (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC)",
            url="по данным IANA",
            data_sent="IP-адрес",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "Страна в записи RIR — страна владельца сети по регистрации, а не местоположение адреса.",
    )
    timeout = 60

    def applicability(self, target: Target, settings: Settings) -> str | None:
        return non_global_reason(target)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        await ensure_bootstrap(ctx.net.http, ctx.settings.cache_dir)
        try:
            url = endpoint_for("ip", target.normalized)
        except RdapUnsupportedError as exc:
            out.errors.append(f"RDAP-сервер для адреса не определён: {exc}")
            return out
        data = await ctx.net.http.get_json(url)
        if not isinstance(data, dict):
            raise NetworkError("RDAP вернул неожиданный формат ответа")
        rec = parse_rdap(data, url)
        src = f"RDAP {rec.server}"
        add = out.findings.append

        def fact(attribute: str, value: Any, evidence: str, exclusive: bool = True) -> None:
            add(
                self.finding(
                    target,
                    attribute,
                    value,
                    Confidence.CONFIRMED,
                    src,
                    rec.url,
                    evidence,
                    exclusive=exclusive,
                )
            )

        if rec.cidrs or (rec.start_address and rec.end_address):
            fact(
                "ip.network",
                {"cidr": rec.cidrs, "start": rec.start_address, "end": rec.end_address},
                "Диапазон адресов, в который входит IP, по записи RIR.",
            )
        if rec.name:
            fact("ip.network_name", rec.name, "Имя сети (netname) в реестре.")
        if rec.handle:
            fact("ip.network_handle", rec.handle, "Идентификатор записи в реестре.")
        if rec.network_type:
            fact("ip.assignment_type", rec.network_type, "Тип назначения адресного блока.")
        if rec.country:
            fact(
                "ip.registry_country",
                rec.country,
                "Страна, указанная в регистрационной записи сети (не геолокация).",
            )
        if rec.org_name:
            fact("ip.registrant_org", rec.org_name, "Организация-владелец сети (vCard kind=org).")
        if rec.abuse_emails:
            fact(
                "ip.abuse_contact",
                rec.abuse_emails,
                "Контакт для жалоб (роль abuse).",
                exclusive=False,
            )
        for action, attribute in (
            ("registration", "ip.registered"),
            ("last changed", "ip.last_changed"),
        ):
            if action in rec.events:
                fact(attribute, rec.events[action], f"Событие RDAP «{action}».")
        return out

"""Domain registration data: RDAP (RFC 9083) with WHOIS (port 43) fallback.

Collected: registrar, key dates, status codes, delegated name servers, DNSSEC delegation, abuse
contact. Registrant personal data is deliberately not requested or stored. Registry and registrar
RDAP answers are recorded as separate sources, so disagreements surface as contradictions.
"""

from __future__ import annotations

import asyncio
from datetime import date
from typing import Any, ClassVar

import whois
from whois.exceptions import PywhoisError, WhoisDomainNotFoundError

from osint_toolkit.core.models import Confidence, ExternalService, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import HttpStatusError, NetworkError
from osint_toolkit.net.rdap import (
    RdapRecord,
    RdapUnsupportedError,
    endpoint_for,
    ensure_bootstrap,
    parse_rdap,
)

EVENT_ATTRIBUTES = {
    "registration": ("domain.registration_date", "Дата регистрации домена"),
    "expiration": ("domain.expiration_date", "Дата окончания регистрации"),
    "last changed": ("domain.last_changed", "Дата последнего изменения записи о домене"),
}
PRIVATE_MARKERS = ("private person", "redacted", "privacy", "not disclosed", "data protected")


class DomainRegistrationModule(BaseModule):
    name = "domain.registration"
    title = "Регистрация домена (RDAP/WHOIS)"
    description = (
        "Регистратор, даты регистрации/окончания/изменения, статусы, NS, DNSSEC и abuse-контакт "
        "из RDAP; WHOIS — если у зоны нет RDAP."
    )
    target_types = frozenset({TargetType.DOMAIN})
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="IANA RDAP bootstrap",
            url="https://data.iana.org/rdap/",
            data_sent="ничего о цели (списки серверов, кэшируются на 7 дней)",
        ),
        ExternalService(
            name="RDAP-серверы реестра и регистратора",
            url="по данным IANA",
            data_sent="доменное имя",
        ),
        ExternalService(
            name="WHOIS-сервер реестра (порт 43)",
            url="только если у зоны нет RDAP",
            data_sent="доменное имя",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "Данные владельца (имя, адрес, телефон) не запрашиваются и не сохраняются.",
        "Регистрационные данные описывают домен, а не установленного владельца.",
    )
    timeout = 60

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target.normalized
        await ensure_bootstrap(ctx.net.http, ctx.settings.cache_dir)
        try:
            url = endpoint_for("domain", domain)
        except RdapUnsupportedError:
            out.limitations.append("У зоны нет RDAP-сервера в реестре IANA — использован WHOIS.")
            await self._whois(target, ctx, out)
            return out
        try:
            data = await ctx.net.http.get_json(url)
        except HttpStatusError as exc:
            if exc.status_code == 404:
                out.findings.append(
                    self.finding(
                        target,
                        "domain.registered",
                        False,
                        Confidence.CONFIRMED,
                        f"RDAP {url.split('/')[2]}",
                        url,
                        "RDAP-сервер реестра ответил 404: домен не найден (вероятно, не "
                        "зарегистрирован).",
                        exclusive=True,
                    )
                )
                return out
            raise
        if not isinstance(data, dict):
            raise NetworkError("RDAP вернул неожиданный формат ответа")
        registry = parse_rdap(data, url)
        self._record(target, out, registry, "реестр")
        if registry.related:
            try:
                related = await ctx.net.http.get_json(registry.related)
                if isinstance(related, dict):
                    self._record(target, out, parse_rdap(related, registry.related), "регистратор")
            except NetworkError as exc:
                out.limitations.append(f"RDAP регистратора недоступен: {exc}")
        return out

    # ------------------------------------------------------------------ RDAP
    def _record(self, target: Target, out: ModuleOutput, rec: RdapRecord, role: str) -> None:
        src = f"RDAP {rec.server} ({role})"
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

        fact("domain.registered", True, f"RDAP-сервер ({role}) вернул запись о домене.")
        if rec.registrar:
            iana = f" (IANA ID {rec.registrar_iana_id})" if rec.registrar_iana_id else ""
            fact("domain.registrar", rec.registrar, f"Регистратор по данным RDAP{iana}.")
        for action, (attribute, label) in EVENT_ATTRIBUTES.items():
            if action in rec.events:
                fact(attribute, rec.events[action], f"{label} (событие RDAP «{action}»).")
        if rec.status:
            fact(
                "domain.status",
                rec.status,
                "Статусы домена (EPP/RDAP), напр. clientTransferProhibited.",
                exclusive=False,
            )
        if rec.nameservers:
            fact(
                "domain.delegated_ns",
                rec.nameservers,
                "Делегированные DNS-серверы по RDAP.",
                exclusive=False,
            )
        if rec.dnssec is not None:
            fact(
                "domain.dnssec_signed",
                rec.dnssec,
                "Делегирование подписано DNSSEC (secureDNS.delegationSigned)."
                if rec.dnssec
                else "RDAP явно сообщает, что делегирование не подписано DNSSEC.",
            )
        if rec.abuse_emails:
            fact(
                "domain.abuse_contact",
                rec.abuse_emails,
                "Контакт для жалоб (роль abuse) — служебный адрес регистратора.",
                exclusive=False,
            )

    # ------------------------------------------------------------------ WHOIS fallback
    async def _whois(self, target: Target, ctx: ModuleContext, out: ModuleOutput) -> None:
        domain = target.normalized
        server = whois.NICClient().choose_server(domain) or ""
        src_url = f"whois://{server}/{domain}"
        src = f"WHOIS {server or '(сервер зоны)'}"
        timeout = max(5, int(ctx.settings.http_timeout))
        try:
            entry = await asyncio.to_thread(
                whois.whois, domain, ignore_socket_errors=False, quiet=True, timeout=timeout
            )
        except WhoisDomainNotFoundError:
            out.findings.append(
                self.finding(
                    target,
                    "domain.registered",
                    False,
                    Confidence.CONFIRMED,
                    src,
                    src_url,
                    "WHOIS-сервер сообщил, что домен не найден.",
                    exclusive=True,
                )
            )
            return
        except (TimeoutError, OSError) as exc:
            raise NetworkError(f"WHOIS {server or ''} недоступен: {exc}") from exc
        except PywhoisError as exc:
            raise NetworkError(f"Ошибка WHOIS: {exc}") from exc
        data = dict(entry or {})
        if not any(data.get(k) for k in ("registrar", "creation_date", "name_servers", "status")):
            out.limitations.append(
                "Ответ WHOIS не содержит распознаваемых полей — вывод не делается."
            )
            return
        add = out.findings.append
        evidence = "разобрано из текстового ответа WHOIS-сервера"

        def fact(attribute: str, value: Any, label: str, exclusive: bool = True) -> None:
            add(
                self.finding(
                    target,
                    attribute,
                    value,
                    Confidence.CONFIRMED,
                    src,
                    src_url,
                    f"{label} ({evidence}).",
                    exclusive=exclusive,
                )
            )

        fact("domain.registered", True, "WHOIS-сервер вернул запись о домене")
        registrar = _text(data.get("registrar"))
        if registrar:
            fact("domain.registrar", registrar, "Регистратор")
        for key, attribute, label in (
            ("creation_date", "domain.registration_date", "Дата регистрации"),
            ("expiration_date", "domain.expiration_date", "Дата окончания регистрации"),
            ("updated_date", "domain.last_changed", "Дата последнего изменения"),
        ):
            dates = _dates(data.get(key))
            if len(dates) == 1:
                fact(attribute, dates[0], label)
            elif len(dates) > 1:
                fact(
                    attribute,
                    dates,
                    f"{label}: WHOIS содержит несколько разных значений",
                    exclusive=False,
                )
        servers = sorted({s.lower().rstrip(".") for s in _list(data.get("name_servers"))})
        if servers:
            fact("domain.delegated_ns", servers, "DNS-серверы по WHOIS", exclusive=False)
        status = _list(data.get("status"))
        if status:
            fact("domain.status", status, "Статусы домена", exclusive=False)
        org = _text(data.get("org"))
        if org and not any(m in org.lower() for m in PRIVATE_MARKERS):
            fact("domain.registrant_org", org, "Организация-владелец, указанная в WHOIS")


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list | tuple | set) else [value]
    return [str(v).strip() for v in items if str(v).strip()]


def _text(value: Any) -> str | None:
    items = _list(value)
    return items[0] if items else None


def _dates(value: Any) -> list[str]:
    items = value if isinstance(value, list | tuple) else [value]
    out: list[str] = []
    for item in items:
        if isinstance(item, date):  # datetime is a subclass of date
            text = item.isoformat()
        else:
            continue
        if text not in out and not any(o[:10] == text[:10] for o in out):
            out.append(text)
    return out

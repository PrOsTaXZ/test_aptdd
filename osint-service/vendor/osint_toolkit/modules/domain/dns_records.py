"""Core DNS records of a domain: A, AAAA, CNAME, NS, SOA, CAA, TXT."""

from __future__ import annotations

import asyncio
import re

from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.modules.base import ModuleContext, ModuleOutput
from osint_toolkit.modules.domain._dns_common import DnsModule, is_nxdomain, target_domain
from osint_toolkit.net import DnsResult, DnsStatus

RECORD_TYPES = ("A", "AAAA", "NS", "SOA", "CAA", "TXT")

# TXT prefixes published by services to prove domain control.
VERIFICATION_PREFIXES: tuple[tuple[str, str], ...] = (
    ("google-site-verification=", "Google (Search Console / Workspace)"),
    ("ms=", "Microsoft 365"),
    ("facebook-domain-verification=", "Meta (Facebook)"),
    ("apple-domain-verification=", "Apple"),
    ("atlassian-domain-verification=", "Atlassian"),
    ("docusign=", "DocuSign"),
    ("zoom-verification=", "Zoom"),
    ("yandex-verification:", "Яндекс"),
    ("yandex-verification=", "Яндекс"),
    ("mailru-verification:", "Mail.ru / VK"),
    ("adobe-idp-site-verification=", "Adobe"),
    ("stripe-verification=", "Stripe"),
    ("globalsign-domain-verification=", "GlobalSign"),
    ("_github-challenge", "GitHub"),
    ("openai-domain-verification=", "OpenAI"),
    ("hubspot-developer-verification=", "HubSpot"),
    ("dropbox-domain-verification=", "Dropbox"),
)
_SOA_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$")


def verification_services(txt_records: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for record in txt_records:
        lowered = record.lower()
        for prefix, service in VERIFICATION_PREFIXES:
            if lowered.startswith(prefix) and service not in found:
                found.append(service)
    return found


class DnsRecordsModule(DnsModule):
    name = "domain.dns"
    title = "DNS-записи домена"
    description = "A, AAAA, CNAME, NS, SOA, CAA и TXT через системный резолвер."
    target_types = frozenset({TargetType.DOMAIN})

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target_domain(target)
        results = dict(
            zip(
                RECORD_TYPES,
                await asyncio.gather(*(ctx.net.dns.query(domain, t) for t in RECORD_TYPES)),
                strict=True,
            )
        )
        if all(is_nxdomain(r) or r.status is DnsStatus.ERROR for r in results.values()) and any(
            is_nxdomain(r) for r in results.values()
        ):
            self.nxdomain(target, out, next(r for r in results.values() if is_nxdomain(r)))
            for r in results.values():
                if r.status is DnsStatus.ERROR:
                    self.record_error(out, r)
            return out

        answered = [r for r in results.values() if r.status in (DnsStatus.OK, DnsStatus.NODATA)]
        if answered:
            first = answered[0]
            out.findings.append(
                self.finding(
                    target,
                    "domain.exists",
                    True,
                    Confidence.CONFIRMED,
                    first.source_name,
                    first.source_url,
                    "Резолвер вернул ответ NOERROR: имя существует в DNS.",
                    exclusive=True,
                )
            )
        inconsistent = [t for t, r in results.items() if is_nxdomain(r)]
        if inconsistent and answered:
            out.limitations.append(
                f"Противоречивые ответы DNS: NXDOMAIN для {', '.join(inconsistent)}, но NOERROR "
                "для других типов. Возможна нестабильность или ошибка конфигурации зоны."
            )

        missing: list[str] = []
        for rdtype, result in results.items():
            if result.status is DnsStatus.ERROR:
                self.record_error(out, result)
            elif result.status is DnsStatus.NODATA:
                missing.append(rdtype)
            elif result.status is DnsStatus.OK:
                self._records(target, out, rdtype, result)
        if missing:
            ref = results[missing[0]]
            out.findings.append(
                self.finding(
                    target,
                    "dns.absent_types",
                    missing,
                    Confidence.CONFIRMED,
                    f"DNS (резолвер {ref.resolver})",
                    ref.source_url,
                    "Имя существует, но записей этих типов нет (ответ NOERROR без данных).",
                )
            )
        return out

    def _records(self, target: Target, out: ModuleOutput, rdtype: str, result: DnsResult) -> None:
        add = out.findings.append
        records = sorted(result.records)
        ttl = f" TTL {result.ttl} с." if result.ttl is not None else ""
        if rdtype in ("A", "AAAA") and result.canonical_name:
            add(
                self.finding(
                    target,
                    "dns.cname",
                    result.canonical_name,
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    f"Имя является псевдонимом (CNAME) для {result.canonical_name}.",
                    exclusive=True,
                )
            )
        if rdtype == "SOA":
            match = _SOA_RE.match(records[0])
            value: JsonValue = records[0]
            if match:
                mname, rname, serial, *_ = match.groups()
                value = {
                    "primary_ns": mname.rstrip("."),
                    "responsible": rname.rstrip("."),
                    "serial": int(serial),
                }
            add(
                self.finding(
                    target,
                    "dns.soa",
                    value,
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    "Запись SOA: первичный сервер зоны и контакт администратора зоны "
                    "(обычно служебный адрес)." + ttl,
                    exclusive=True,
                )
            )
            return
        evidence = {
            "A": "IPv4-адреса домена.",
            "AAAA": "IPv6-адреса домена.",
            "NS": "Авторитетные DNS-серверы зоны.",
            "CAA": "Центры сертификации, которым разрешено выпускать сертификаты (RFC 8659).",
            "TXT": "Текстовые записи домена.",
        }[rdtype]
        cleaned = [r.rstrip(".") for r in records] if rdtype == "NS" else records
        add(
            self.finding(
                target,
                f"dns.{rdtype.lower()}",
                cleaned,
                Confidence.CONFIRMED,
                result.source_name,
                result.source_url,
                evidence + ttl,
            )
        )
        if rdtype == "TXT":
            services = verification_services(result.records)
            if services:
                add(
                    self.finding(
                        target,
                        "dns.verification_records",
                        services,
                        Confidence.LIKELY,
                        result.source_name,
                        result.source_url,
                        "TXT-записи подтверждения владения доменом для этих сервисов: "
                        "домен, вероятно, проходил в них верификацию (запись могла "
                        "остаться после прекращения использования).",
                    )
                )

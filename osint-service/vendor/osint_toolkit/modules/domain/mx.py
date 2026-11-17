"""Mail exchangers of a domain (MX), null MX, implicit MX and MX host resolution."""

from __future__ import annotations

import asyncio
import ipaddress

from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.modules.base import ModuleContext, ModuleOutput
from osint_toolkit.modules.domain._dns_common import DnsModule, is_nxdomain, target_domain
from osint_toolkit.net import DnsResult, DnsStatus

RFC5321_URL = "https://www.rfc-editor.org/rfc/rfc5321#section-5.1"
RFC7505_URL = "https://www.rfc-editor.org/rfc/rfc7505"
MAX_HOSTS = 5

# MX host suffix → mail provider (infrastructure hint, not ownership).
MX_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("aspmx.l.google.com", "Google Workspace / Gmail"),
    ("googlemail.com", "Google Workspace / Gmail"),
    ("google.com", "Google Workspace / Gmail"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft (Outlook.com / 365)"),
    ("mx.yandex.net", "Яндекс 360"),
    ("yandex.ru", "Яндекс"),
    ("mxs.mail.ru", "VK WorkMail / Mail.ru"),
    ("mail.ru", "VK WorkMail / Mail.ru"),
    ("protonmail.ch", "Proton Mail"),
    ("icloud.com", "Apple iCloud Mail"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("mimecast.com", "Mimecast (фильтрация почты)"),
    ("pphosted.com", "Proofpoint (фильтрация почты)"),
    ("messagelabs.com", "Broadcom Email Security.cloud"),
    ("secureserver.net", "GoDaddy"),
    ("fastmail.com", "Fastmail"),
    ("mailgun.org", "Mailgun"),
    ("amazonaws.com", "Amazon SES / AWS"),
)


def parse_mx(record: str) -> tuple[int, str] | None:
    parts = record.split()
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1].rstrip(".").lower()


def provider_for(host: str) -> str | None:
    for suffix, provider in MX_PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return provider
    return None


class MxModule(DnsModule):
    name = "mail.mx"
    title = "Почтовые серверы (MX)"
    description = (
        "MX-записи, null MX (RFC 7505), неявный MX (RFC 5321), разрешимость MX-хостов и "
        "вероятный почтовый провайдер."
    )
    target_types = frozenset({TargetType.EMAIL, TargetType.DOMAIN})

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target_domain(target)
        mx = await ctx.net.dns.query(domain, "MX")
        if mx.status is DnsStatus.ERROR:
            self.record_error(out, mx)
            return out
        if is_nxdomain(mx):
            self.nxdomain(target, out, mx)
            return out
        if mx.status is DnsStatus.NODATA:
            await self._implicit_mx(target, ctx, out, domain, mx)
            return out

        entries: list[tuple[int, str]] = []
        malformed: list[str] = []
        for record in mx.records:
            parsed = parse_mx(record)
            (entries.append(parsed) if parsed else malformed.append(record))
        entries.sort()
        subject = domain
        if malformed:
            out.limitations.append(f"Некорректные MX-записи пропущены: {', '.join(malformed)}")

        null_mx = [e for e in entries if e[1] in ("", ".")]
        if null_mx:
            if len(entries) == 1:
                out.findings.append(
                    self.finding(
                        target,
                        "mail.null_mx",
                        True,
                        Confidence.CONFIRMED,
                        mx.source_name,
                        mx.source_url,
                        "Опубликован null MX («0 .»): домен явно заявляет, что не "
                        "принимает почту (RFC 7505).",
                        subject=subject,
                        exclusive=True,
                    )
                )
                return out
            out.findings.append(
                self.finding(
                    target,
                    "mail.mx_misconfiguration",
                    "null MX вместе с другими MX",
                    Confidence.CONFIRMED,
                    mx.source_name,
                    mx.source_url,
                    "Null MX опубликован вместе с обычными MX-записями. RFC 7505 требует, "
                    "чтобы null MX был единственной записью, поэтому поведение отправителей "
                    "непредсказуемо.",
                    subject=subject,
                )
            )
            entries = [e for e in entries if e not in null_mx]

        value: list[JsonValue] = [{"preference": p, "host": h} for p, h in entries]
        out.findings.append(
            self.finding(
                target,
                "mail.mx",
                value,
                Confidence.CONFIRMED,
                mx.source_name,
                mx.source_url,
                "Почтовые серверы домена в порядке приоритета (меньше — выше).",
                subject=subject,
            )
        )

        providers = sorted({p for _, h in entries if (p := provider_for(h))})
        if providers:
            out.findings.append(
                self.finding(
                    target,
                    "mail.provider",
                    providers,
                    Confidence.LIKELY,
                    mx.source_name,
                    mx.source_url,
                    "MX указывает на инфраструктуру этого провайдера: почта домена, "
                    "вероятно, обслуживается им. Это не говорит о владельце домена.",
                    subject=subject,
                )
            )
        await self._check_hosts(target, ctx, out, subject, [h for _, h in entries], mx)
        return out

    async def _implicit_mx(
        self, target: Target, ctx: ModuleContext, out: ModuleOutput, domain: str, mx: DnsResult
    ) -> None:
        a, aaaa = await asyncio.gather(
            ctx.net.dns.query(domain, "A"), ctx.net.dns.query(domain, "AAAA")
        )
        if DnsStatus.ERROR in (a.status, aaaa.status) and DnsStatus.OK not in (
            a.status,
            aaaa.status,
        ):
            for r in (a, aaaa):
                if r.status is DnsStatus.ERROR:
                    self.record_error(out, r)
            out.limitations.append("MX нет, а адресные записи проверить не удалось.")
            return
        addresses = [*a.records, *aaaa.records]
        if addresses:
            out.findings.append(
                self.finding(
                    target,
                    "mail.implicit_mx",
                    sorted(addresses),
                    Confidence.CONFIRMED,
                    a.source_name if a.records else aaaa.source_name,
                    a.source_url if a.records else aaaa.source_url,
                    "MX-записей нет (NODATA). По RFC 5321 отправители доставляют почту на "
                    "A/AAAA-адреса домена. Принимает ли там почту сервер, DNS не сообщает.",
                    subject=domain,
                )
            )
        else:
            out.findings.append(
                self.finding(
                    target,
                    "mail.no_route",
                    True,
                    Confidence.CONFIRMED,
                    mx.source_name,
                    mx.source_url,
                    "Нет ни MX, ни A/AAAA-записей: доставить почту на этот домен невозможно.",
                    subject=domain,
                    exclusive=True,
                )
            )

    async def _check_hosts(
        self,
        target: Target,
        ctx: ModuleContext,
        out: ModuleOutput,
        subject: str,
        hosts: list[str],
        src: DnsResult,
    ) -> None:
        checked = hosts[:MAX_HOSTS]
        if len(hosts) > MAX_HOSTS:
            out.limitations.append(f"Проверена разрешимость первых {MAX_HOSTS} MX-хостов.")
        literals = [h for h in checked if _is_ip(h)]
        if literals:
            out.findings.append(
                self.finding(
                    target,
                    "mail.mx_misconfiguration",
                    f"IP-адрес вместо имени: {', '.join(literals)}",
                    Confidence.CONFIRMED,
                    src.source_name,
                    src.source_url,
                    "MX должен указывать на имя хоста, а не на IP-адрес (RFC 5321 §5.1).",
                    subject=subject,
                )
            )
        names = [h for h in checked if not _is_ip(h)]
        lookups = await asyncio.gather(
            *(ctx.net.dns.query(h, t) for h in names for t in ("A", "AAAA"))
        )
        dangling: list[str] = []
        dangling_source = "dns:///"
        aliased: list[str] = []
        aliased_source = "dns:///"
        for index, host in enumerate(names):
            a, aaaa = lookups[2 * index], lookups[2 * index + 1]
            statuses = {a.status, aaaa.status}
            if DnsStatus.OK in statuses:
                if a.canonical_name or aaaa.canonical_name:
                    aliased.append(host)
                    aliased_source = a.source_url if a.canonical_name else aaaa.source_url
            elif DnsStatus.ERROR in statuses:
                self.record_error(out, a if a.status is DnsStatus.ERROR else aaaa)
            else:
                dangling.append(host)
                dangling_source = a.source_url
        if dangling:
            out.findings.append(
                self.finding(
                    target,
                    "mail.mx_unresolvable",
                    dangling,
                    Confidence.CONFIRMED,
                    "DNS A/AAAA для MX-хостов",
                    dangling_source,
                    "У этих MX-хостов нет A/AAAA-записей (NXDOMAIN или NODATA): почта на них не "
                    "может быть доставлена.",
                    subject=subject,
                )
            )
        if aliased:
            out.findings.append(
                self.finding(
                    target,
                    "mail.mx_misconfiguration",
                    f"MX указывает на CNAME: {', '.join(aliased)}",
                    Confidence.CONFIRMED,
                    "DNS A/AAAA для MX-хостов",
                    aliased_source,
                    "MX-запись указывает на псевдоним (CNAME), что запрещено RFC 2181 §10.3; "
                    "большинство серверов это терпят, но не все.",
                    subject=subject,
                )
            )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True

"""DMARC (RFC 7489): policy record lookup, validation and the effective policy.

Lookup: ``_dmarc.<domain>`` and, if absent, the parent domains (without a public-suffix list the
organisational domain is found by walking up the DNS tree; a parent that is a public suffix simply
has no record). A lookup error stops the walk: absence is never concluded from a failure.
"""

from __future__ import annotations

import re

from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.modules.base import ModuleContext, ModuleOutput
from osint_toolkit.modules.domain._dns_common import DnsModule, target_domain
from osint_toolkit.net import DnsResult, DnsStatus

RFC7489_URL = "https://www.rfc-editor.org/rfc/rfc7489"
POLICIES = ("none", "quarantine", "reject")
POLICY_MEANING = {
    "none": "только мониторинг, письма не блокируются",
    "quarantine": "не прошедшие проверку письма помещаются в спам/карантин",
    "reject": "не прошедшие проверку письма отклоняются",
}
_DMARC_RE = re.compile(r"^v\s*=\s*DMARC1\s*(;|$)", re.IGNORECASE)


def dmarc_records(txt: tuple[str, ...]) -> list[str]:
    return [r.strip() for r in txt if _DMARC_RE.match(r.strip())]


def parse_dmarc(record: str) -> tuple[dict[str, str], list[str]]:
    tags: dict[str, str] = {}
    errors: list[str] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep:
            errors.append(f"тег без значения: «{part}»")
            continue
        key = key.strip().lower()
        if key in tags:
            errors.append(f"тег «{key}» повторяется")
        tags[key] = value.strip()
    policy = tags.get("p", "").lower()
    if not policy:
        errors.append("обязательный тег «p» отсутствует")
    elif policy not in POLICIES:
        errors.append(f"недопустимое значение p={policy}")
    sp = tags.get("sp", "").lower()
    if sp and sp not in POLICIES:
        errors.append(f"недопустимое значение sp={sp}")
    pct = tags.get("pct")
    if pct is not None and (not pct.isdigit() or not 0 <= int(pct) <= 100):
        errors.append(f"недопустимое значение pct={pct}")
    for tag in ("adkim", "aspf"):
        if tag in tags and tags[tag].lower() not in ("r", "s"):
            errors.append(f"недопустимое значение {tag}={tags[tag]}")
    return tags, errors


def _report_uris(value: str | None) -> list[str]:
    if not value:
        return []
    return [u.strip() for u in value.split(",") if u.strip()]


def parents(domain: str) -> list[str]:
    """``a.b.example.org`` → [a.b.example.org, b.example.org, example.org] (never the bare TLD)."""
    labels = domain.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


class DmarcModule(DnsModule):
    name = "mail.dmarc"
    title = "DMARC"
    description = (
        "Запись DMARC домена или родительского домена, политика p/sp, pct, выравнивание и "
        "адреса отчётов; проверка синтаксиса по RFC 7489."
    )
    target_types = frozenset({TargetType.EMAIL, TargetType.DOMAIN})

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target_domain(target)
        found: tuple[str, DnsResult, list[str]] | None = None
        checked: list[str] = []
        for candidate in parents(domain):
            result = await ctx.net.dns.query(f"_dmarc.{candidate}", "TXT")
            checked.append(f"_dmarc.{candidate}")
            if result.status is DnsStatus.ERROR:
                self.record_error(out, result)
                out.limitations.append(
                    "Поиск DMARC прерван из-за ошибки DNS: отсутствие записи не установлено."
                )
                return out
            records = dmarc_records(result.records) if result.status is DnsStatus.OK else []
            if records:
                found = (candidate, result, records)
                break
        add = out.findings.append
        if found is None:
            last = f"dns:///_dmarc.{parents(domain)[-1]}?type=TXT" if parents(domain) else "dns:///"
            add(
                self.finding(
                    target,
                    "mail.dmarc_present",
                    False,
                    Confidence.CONFIRMED,
                    "DNS TXT",
                    last,
                    f"DMARC-записи нет (проверены: {', '.join(checked)}). Получатели не "
                    "получают от домена политики для писем, не прошедших SPF/DKIM.",
                    subject=domain,
                    exclusive=True,
                )
            )
            return out

        where, result, records = found
        inherited = where != domain
        add(
            self.finding(
                target,
                "mail.dmarc_present",
                True,
                Confidence.CONFIRMED,
                result.source_name,
                result.source_url,
                f"DMARC-запись найдена на _dmarc.{where}"
                + (" (родительский домен)." if inherited else "."),
                subject=domain,
                exclusive=True,
            )
        )
        if len(records) > 1:
            add(
                self.finding(
                    target,
                    "mail.dmarc_records",
                    records,
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    "Опубликовано несколько DMARC-записей.",
                    subject=domain,
                )
            )
            add(
                self.finding(
                    target,
                    "mail.dmarc_valid",
                    False,
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    "Несколько записей «v=DMARC1»: по RFC 7489 §6.6.3 получатели "
                    "считают, что DMARC не опубликован.",
                    subject=domain,
                    exclusive=True,
                )
            )
            return out

        record = records[0]
        tags, errors = parse_dmarc(record)
        add(
            self.finding(
                target,
                "mail.dmarc_record",
                record,
                Confidence.CONFIRMED,
                result.source_name,
                result.source_url,
                f"DMARC-запись _dmarc.{where}.",
                subject=domain,
                exclusive=True,
            )
        )
        add(
            self.finding(
                target,
                "mail.dmarc_valid",
                not errors,
                Confidence.CONFIRMED,
                result.source_name,
                result.source_url,
                "Синтаксис записи корректен (RFC 7489)."
                if not errors
                else "Нарушения RFC 7489: " + "; ".join(errors) + ".",
                subject=domain,
                exclusive=True,
            )
        )
        policy = tags.get("p", "").lower()
        if policy in POLICIES:
            sub_policy = tags.get("sp", "").lower() or policy
            effective = sub_policy if inherited else policy
            source_tag = ("sp" if "sp" in tags else "p") if inherited else "p"
            add(
                self.finding(
                    target,
                    "mail.dmarc_policy",
                    effective,
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    f"Действующая политика для {domain}: {effective} — "
                    f"{POLICY_MEANING[effective]} (тег {source_tag}"
                    + (f" записи родительского домена {where})." if inherited else ")."),
                    subject=domain,
                    exclusive=True,
                )
            )
            if not inherited and "sp" in tags and sub_policy != policy:
                add(
                    self.finding(
                        target,
                        "mail.dmarc_subdomain_policy",
                        sub_policy,
                        Confidence.CONFIRMED,
                        result.source_name,
                        result.source_url,
                        f"Для поддоменов действует политика {sub_policy} (тег sp).",
                        subject=domain,
                        exclusive=True,
                    )
                )
        pct = tags.get("pct")
        if pct and pct.isdigit() and int(pct) < 100:
            add(
                self.finding(
                    target,
                    "mail.dmarc_pct",
                    int(pct),
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    f"Политика применяется только к {pct}% писем.",
                    subject=domain,
                    exclusive=True,
                )
            )
        alignment: dict[str, JsonValue] = {
            "dkim": "strict" if tags.get("adkim", "r").lower() == "s" else "relaxed",
            "spf": "strict" if tags.get("aspf", "r").lower() == "s" else "relaxed",
        }
        add(
            self.finding(
                target,
                "mail.dmarc_alignment",
                alignment,
                Confidence.CONFIRMED,
                result.source_name,
                result.source_url,
                "Режимы выравнивания DKIM/SPF (по умолчанию relaxed).",
                subject=domain,
                exclusive=True,
            )
        )
        reporting = {"rua": _report_uris(tags.get("rua")), "ruf": _report_uris(tags.get("ruf"))}
        if reporting["rua"] or reporting["ruf"]:
            add(
                self.finding(
                    target,
                    "mail.dmarc_reporting",
                    reporting,
                    Confidence.CONFIRMED,
                    result.source_name,
                    result.source_url,
                    "Адреса для агрегированных (rua) и детальных (ruf) отчётов DMARC; "
                    "часто это сервисы аналитики почты.",
                    subject=domain,
                )
            )
        if policy == "none":
            out.limitations.append(
                "Политика p=none не защищает от подделки отправителя: она только собирает отчёты."
            )
        return out

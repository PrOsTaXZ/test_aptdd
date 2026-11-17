"""SPF (RFC 7208): record presence, syntax, policy and the DNS-lookup limit.

The 10-lookup limit (RFC 7208 §4.6.4) is evaluated recursively through ``include`` and
``redirect`` with a hard query budget, so the count is measured, not guessed. ``a``/``mx``/
``exists``/``ptr`` terms are counted without being resolved (that is what the limit counts).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.modules.base import ModuleContext, ModuleOutput
from osint_toolkit.modules.domain._dns_common import DnsModule, is_nxdomain, target_domain
from osint_toolkit.net import DnsClient, DnsStatus

RFC7208_URL = "https://www.rfc-editor.org/rfc/rfc7208"
LOOKUP_LIMIT = 10
MAX_QUERIES = 25  # safety budget for recursive evaluation
MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_MODIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-_.]*=")


@dataclass(slots=True)
class SpfTerm:
    qualifier: str
    kind: str  # mechanism name or modifier name
    value: str | None
    modifier: bool = False


@dataclass(slots=True)
class SpfParse:
    terms: list[SpfTerm] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_term(self) -> SpfTerm | None:
        return next((t for t in self.terms if t.kind == "all"), None)

    @property
    def redirect(self) -> str | None:
        return next((t.value for t in self.terms if t.modifier and t.kind == "redirect"), None)

    def values(self, kind: str) -> list[str]:
        return [t.value for t in self.terms if t.kind == kind and t.value]


def spf_records(txt: tuple[str, ...]) -> list[str]:
    return [r.strip() for r in txt if _SPF_RE.match(r.strip())]


def parse_spf(record: str) -> SpfParse:
    result = SpfParse()
    tokens = record.split()[1:]
    seen_modifiers: set[str] = set()
    for index, token in enumerate(tokens):
        if _MODIFIER_RE.match(token):  # RFC 7208 §4.6.1: name = ALPHA *( ALPHA / DIGIT / - _ . )
            name, _, value = token.partition("=")
            name = name.lower()
            if name in seen_modifiers and name in ("redirect", "exp"):
                result.errors.append(f"модификатор «{name}» указан более одного раза")
            seen_modifiers.add(name)
            if name not in ("redirect", "exp"):
                result.warnings.append(f"неизвестный модификатор «{name}» (игнорируется)")
            result.terms.append(SpfTerm("", name, value or None, modifier=True))
            continue
        qualifier = token[0] if token[0] in QUALIFIERS else "+"
        body = token[1:] if token[0] in QUALIFIERS else token
        kind, sep, value = body.partition(":")
        if "/" in kind and kind.split("/")[0].lower() in ("a", "mx"):
            kind = kind.split("/")[0]
        kind = kind.lower()
        if kind not in MECHANISMS:
            result.errors.append(f"неизвестный механизм «{token}»")
            continue
        if kind in ("include", "exists", "ip4", "ip6") and not value:
            result.errors.append(f"механизм «{kind}» требует значение")
            continue
        if kind == "ptr":
            result.warnings.append("механизм «ptr» не рекомендуется (RFC 7208 §5.5)")
        if kind == "all" and index != len(tokens) - 1:
            later = [t for t in tokens[index + 1 :] if not t.lower().startswith("exp=")]
            if later:
                result.warnings.append("термы после «all» никогда не применяются")
        result.terms.append(SpfTerm(qualifier, kind, value if sep else None))
    if result.all_term and result.redirect:
        result.warnings.append("при наличии «all» модификатор «redirect» игнорируется")
    return result


@dataclass(slots=True)
class LookupCount:
    count: int = 0
    queries: int = 0
    complete: bool = True
    problems: list[str] = field(default_factory=list)


async def count_lookups(dns: DnsClient, domain: str, parsed: SpfParse) -> LookupCount:
    """Recursive DNS-lookup count per RFC 7208 §4.6.4 (include + redirect followed)."""
    state = LookupCount()
    await _walk(dns, domain, parsed, state, {domain.lower()})
    return state


async def _walk(
    dns: DnsClient, domain: str, parsed: SpfParse, state: LookupCount, chain: set[str]
) -> None:
    for term in parsed.terms:
        if term.kind not in LOOKUP_TERMS or (term.modifier and term.kind != "redirect"):
            continue
        if term.kind == "redirect" and parsed.all_term is not None:
            continue
        state.count += 1
        if term.kind not in ("include", "redirect") or not term.value:
            continue
        child = term.value.lower().rstrip(".")
        if "%" in child:
            state.complete = False
            state.problems.append(f"«{term.value}» содержит макросы и не раскрывался")
            continue
        if child in chain:
            state.problems.append(f"циклическая ссылка на {child}")
            continue
        if state.queries >= MAX_QUERIES or state.count > LOOKUP_LIMIT:
            state.complete = False
            continue
        state.queries += 1
        result = await dns.query(child, "TXT")
        if result.status is DnsStatus.ERROR:
            state.complete = False
            state.problems.append(f"{child}: {result.error} — подсчёт неполный")
            continue
        records = spf_records(result.records) if result.status is DnsStatus.OK else []
        if len(records) != 1:
            what = "нет SPF-записи" if not records else "несколько SPF-записей"
            state.problems.append(f"{term.kind}:{child} — {what} (permerror для этой ветки)")
            continue
        await _walk(dns, child, parse_spf(records[0]), state, chain | {child})


class SpfModule(DnsModule):
    name = "mail.spf"
    title = "SPF"
    description = (
        "Наличие и синтаксис SPF, итоговая политика «all», рекурсивный подсчёт DNS-запросов "
        "(лимит 10, RFC 7208)."
    )
    target_types = frozenset({TargetType.EMAIL, TargetType.DOMAIN})

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target_domain(target)
        txt = await ctx.net.dns.query(domain, "TXT")
        if txt.status is DnsStatus.ERROR:
            self.record_error(out, txt)
            return out
        if is_nxdomain(txt):
            self.nxdomain(target, out, txt)
            return out
        add = out.findings.append
        records = spf_records(txt.records) if txt.status is DnsStatus.OK else []
        if not records:
            add(
                self.finding(
                    target,
                    "mail.spf_present",
                    False,
                    Confidence.CONFIRMED,
                    txt.source_name,
                    txt.source_url,
                    "TXT-записи с «v=spf1» не найдено: домен не публикует SPF, "
                    "получатели не могут проверить разрешённых отправителей.",
                    subject=domain,
                    exclusive=True,
                )
            )
            return out
        add(
            self.finding(
                target,
                "mail.spf_present",
                True,
                Confidence.CONFIRMED,
                txt.source_name,
                txt.source_url,
                "Домен публикует SPF.",
                subject=domain,
                exclusive=True,
            )
        )
        if len(records) > 1:
            add(
                self.finding(
                    target,
                    "mail.spf_records",
                    records,
                    Confidence.CONFIRMED,
                    txt.source_name,
                    txt.source_url,
                    "Опубликовано несколько SPF-записей.",
                    subject=domain,
                )
            )
            add(
                self.finding(
                    target,
                    "mail.spf_valid",
                    False,
                    Confidence.CONFIRMED,
                    txt.source_name,
                    txt.source_url,
                    "Несколько записей «v=spf1» — по RFC 7208 §4.5 результат проверки "
                    "permerror, SPF фактически не работает.",
                    subject=domain,
                    exclusive=True,
                )
            )
            return out

        record = records[0]
        parsed = parse_spf(record)
        add(
            self.finding(
                target,
                "mail.spf_record",
                record,
                Confidence.CONFIRMED,
                txt.source_name,
                txt.source_url,
                "SPF-запись домена.",
                subject=domain,
                exclusive=True,
            )
        )
        all_term = parsed.all_term
        if all_term is not None:
            policy = f"{all_term.qualifier}all ({QUALIFIERS[all_term.qualifier]})"
            meaning = {
                "fail": "письма с неуказанных серверов следует отклонять",
                "softfail": "письма с неуказанных серверов помечаются как подозрительные",
                "neutral": "SPF не даёт оценки для неуказанных серверов",
                "pass": "любой сервер в интернете считается разрешённым — SPF не защищает",
            }[QUALIFIERS[all_term.qualifier]]
            add(
                self.finding(
                    target,
                    "mail.spf_all",
                    policy,
                    Confidence.CONFIRMED,
                    txt.source_name,
                    txt.source_url,
                    f"Итоговое правило «{policy}» (RFC 7208): {meaning}.",
                    subject=domain,
                    exclusive=True,
                )
            )
        elif parsed.redirect is None:
            out.limitations.append(
                "В записи нет ни «all», ни «redirect»: для неуказанных серверов результат "
                "neutral (RFC 7208 §4.7)."
            )
        includes = parsed.values("include")
        mechanisms: dict[str, JsonValue] = {
            "include": includes,
            "ip4": parsed.values("ip4"),
            "ip6": parsed.values("ip6"),
            "a": sum(1 for t in parsed.terms if t.kind == "a"),
            "mx": sum(1 for t in parsed.terms if t.kind == "mx"),
        }
        if parsed.redirect:
            mechanisms["redirect"] = parsed.redirect
        add(
            self.finding(
                target,
                "mail.spf_mechanisms",
                mechanisms,
                Confidence.CONFIRMED,
                txt.source_name,
                txt.source_url,
                "Разрешённые источники почты из SPF-записи.",
                subject=domain,
            )
        )

        lookups = await count_lookups(ctx.net.dns, domain, parsed)
        over = lookups.count > LOOKUP_LIMIT
        add(
            self.finding(
                target,
                "mail.spf_dns_lookups",
                {
                    "count": lookups.count,
                    "limit": LOOKUP_LIMIT,
                    "complete": lookups.complete,
                },
                Confidence.CONFIRMED if lookups.complete or over else Confidence.LIKELY,
                f"{txt.source_name}; рекурсивный подсчёт по RFC 7208 §4.6.4",
                txt.source_url,
                f"Механизмов, требующих DNS-запросов: {lookups.count}"
                + (" — превышен лимит 10, результат проверки permerror." if over else ".")
                + ("" if lookups.complete else " Подсчёт неполный (см. ограничения)."),
                subject=domain,
                exclusive=True,
            )
        )
        out.limitations.extend(lookups.problems)

        valid = not parsed.errors and not over
        add(
            self.finding(
                target,
                "mail.spf_valid",
                valid,
                Confidence.CONFIRMED,
                txt.source_name,
                txt.source_url,
                "Синтаксис корректен, лимит запросов не превышен (RFC 7208)."
                if valid
                else "Нарушения RFC 7208: "
                + "; ".join([*parsed.errors, *(["превышен лимит DNS-запросов"] if over else [])])
                + ".",
                subject=domain,
                exclusive=True,
            )
        )
        if parsed.warnings:
            add(
                self.finding(
                    target,
                    "mail.spf_warnings",
                    parsed.warnings,
                    Confidence.CONFIRMED,
                    txt.source_name,
                    txt.source_url,
                    "Замечания к SPF-записи по RFC 7208.",
                    subject=domain,
                )
            )
        return out

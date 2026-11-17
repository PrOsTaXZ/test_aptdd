"""Certificate Transparency names via crt.sh (public CT log search by Sectigo)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any, ClassVar
from urllib.parse import quote

from osint_toolkit.core.models import Confidence, ExternalService, JsonValue, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import NetworkError

CRT_SH = "https://crt.sh/"
MAX_NAMES = 300
MAX_RESPONSE = 25 * 1024 * 1024


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def collect_names(entries: list[dict[str, Any]], domain: str) -> tuple[set[str], set[str]]:
    """(names, wildcards) belonging to ``domain`` from crt.sh entries."""
    names: set[str] = set()
    wildcards: set[str] = set()
    suffix = "." + domain
    for entry in entries:
        raw = f"{entry.get('common_name') or ''}\n{entry.get('name_value') or ''}"
        for item in raw.splitlines():
            name = item.strip().lower().rstrip(".")
            if not name or " " in name or "@" in name:
                continue
            bare = name[2:] if name.startswith("*.") else name
            if bare != domain and not bare.endswith(suffix):
                continue
            (wildcards if name.startswith("*.") else names).add(name)
    return names, wildcards


class CertificateTransparencyModule(BaseModule):
    name = "domain.ct"
    title = "Сертификаты (Certificate Transparency, crt.sh)"
    description = (
        "Имена хостов, встречавшиеся в публичных TLS-сертификатах домена и поддоменов, "
        "издатели и даты (журналы Certificate Transparency через crt.sh)."
    )
    target_types = frozenset({TargetType.DOMAIN})
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(name="crt.sh (Sectigo)", url=CRT_SH, data_sent="доменное имя"),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "Имя из сертификата когда-то существовало в сертификате; оно не обязательно существует "
        "или резолвится сейчас.",
        "crt.sh часто перегружен: таймауты и ошибки 5xx — обычное явление, повторите позже.",
    )
    timeout = 120

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target.normalized
        params = {"q": f"%.{domain}", "output": "json", "deduplicate": "Y"}
        source_url = f"{CRT_SH}?q={quote('%.' + domain)}"
        entries = await ctx.net.http.get_json(
            CRT_SH, params=params, request_timeout=90, max_bytes=MAX_RESPONSE, retries=1
        )
        if not isinstance(entries, list):
            raise NetworkError("crt.sh вернул неожиданный формат ответа")
        entries = [e for e in entries if isinstance(e, dict)]
        if not entries:
            out.findings.append(
                self.finding(
                    target,
                    "domain.ct_certificates",
                    {"total": 0},
                    Confidence.CONFIRMED,
                    "crt.sh",
                    source_url,
                    "В журналах CT через crt.sh сертификатов для домена и поддоменов не найдено.",
                    exclusive=True,
                )
            )
            return out

        now = datetime.now(UTC)
        starts = [t for e in entries if (t := _parse_time(e.get("not_before")))]
        valid = sum(1 for e in entries if (t := _parse_time(e.get("not_after"))) and t > now)
        summary: dict[str, JsonValue] = {"total": len(entries), "currently_valid": valid}
        if starts:
            summary["earliest_not_before"] = min(starts).isoformat()
            summary["latest_not_before"] = max(starts).isoformat()
        add = out.findings.append
        add(
            self.finding(
                target,
                "domain.ct_certificates",
                summary,
                Confidence.CONFIRMED,
                "crt.sh",
                source_url,
                "Число сертификатов в журналах CT (без дубликатов предсертификатов) и "
                "диапазон дат выпуска.",
                exclusive=True,
            )
        )

        names, wildcards = collect_names(entries, domain)
        if names:
            listed = sorted(names)
            add(
                self.finding(
                    target,
                    "domain.ct_names",
                    listed[:MAX_NAMES],
                    Confidence.CONFIRMED,
                    "crt.sh",
                    source_url,
                    f"Имена хостов из сертификатов ({len(listed)} уникальных"
                    + (f", показаны первые {MAX_NAMES}" if len(listed) > MAX_NAMES else "")
                    + ").",
                )
            )
        if wildcards:
            add(
                self.finding(
                    target,
                    "domain.ct_wildcards",
                    sorted(wildcards),
                    Confidence.CONFIRMED,
                    "crt.sh",
                    source_url,
                    "Wildcard-сертификаты (*.домен).",
                )
            )
        issuers = Counter(_issuer_org(e.get("issuer_name")) for e in entries)
        issuers.pop("", None)
        if issuers:
            add(
                self.finding(
                    target,
                    "domain.ct_issuers",
                    [{"issuer": n, "certificates": c} for n, c in issuers.most_common(5)],
                    Confidence.CONFIRMED,
                    "crt.sh",
                    source_url,
                    "Основные центры сертификации, выпускавшие сертификаты.",
                )
            )
        return out


def _issuer_org(issuer: Any) -> str:
    if not isinstance(issuer, str):
        return ""
    for part in issuer.split(","):
        key, _, value = part.strip().partition("=")
        if key == "O":
            return value.strip().strip('"')
    return issuer.strip()[:80]

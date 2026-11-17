"""theHarvester (GPL-2.0, github.com/laramies/theHarvester) — sandboxed adapter.

Collects hostnames, IPs and email addresses for a domain from passive sources. Only keyless
sources from :data:`KEYLESS_SOURCES` are allowed (``OSINT_HARVESTER_SOURCES``); no API keys are
passed into the sandbox. Opt-in module (overlaps with ``domain.ct``); every result is
``unverified`` — passive datasets contain stale and junk entries, and an address seen in a
source is not proof that the mailbox exists or whom it belongs to. People lists (LinkedIn,
Twitter) produced by some sources are never collected.

Execution: the tool's own entry point inside the bwrap sandbox with network, a temporary
``/work`` (its config and cache land there, never in the home directory) and the JSON report
written to ``/work/out.json``.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from osint_toolkit.config import Settings, ensure_private_dir
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    JsonValue,
    ModuleStatus,
    Target,
    TargetType,
)
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import NetworkError, NetworkTimeoutError
from osint_toolkit.sandbox import SandboxError, SandboxPolicy, SandboxTimeoutError, run_sandboxed
from osint_toolkit.tools import THEHARVESTER, tool_status
from osint_toolkit.tools.manager import sandbox_mounts

KEYLESS_SOURCES = frozenset(
    {
        "crtsh",
        "certspotter",
        "hackertarget",
        "otx",
        "rapiddns",
        "urlscan",
        "waybackarchive",
        "robtex",
        "subdomaincenter",
        "thc",
        "commoncrawl",
        "shodanInternetDB",
        "leakix",
        "threatcrowd",
    }
)
MAX_ITEMS = 500
ENTRY = "from theHarvester.theHarvester import main; main()"


def parse_sources(spec: str) -> tuple[list[str], list[str]]:
    """(allowed, rejected) source names."""
    names = [s.strip() for s in spec.split(",") if s.strip()]
    allowed = [s for s in dict.fromkeys(names) if s in KEYLESS_SOURCES]
    rejected = [s for s in names if s not in KEYLESS_SOURCES]
    return allowed, rejected


def parse_report(data: Any, domain: str) -> dict[str, list[str]]:
    """Hosts/IPs/emails/ASNs/URLs belonging to ``domain`` from theHarvester JSON."""
    if not isinstance(data, dict):
        raise ValueError("отчёт theHarvester имеет неожиданный формат")
    suffix = "." + domain

    def strings(key: str) -> list[str]:
        values = data.get(key) or []
        return [str(v).strip() for v in values if isinstance(v, str | int) and str(v).strip()]

    hosts: dict[str, set[str]] = {}
    for entry in strings("hosts"):
        name, _, ip = entry.partition(":")
        name = name.lower().rstrip(".")
        if name == domain or name.endswith(suffix) or name.endswith(f"*{suffix}"):
            hosts.setdefault(name, set()).update(p for p in ip.split(",") if p)
    emails = sorted(
        {
            e.lower()
            for e in strings("emails")
            if e.lower().endswith("@" + domain) or e.lower().endswith(suffix)
        }
    )
    return {
        "hosts": [
            f"{h} ({', '.join(sorted(ips))})" if ips else h for h, ips in sorted(hosts.items())
        ],
        "emails": emails,
        "ips": sorted(set(strings("ips"))),
        "asns": sorted(set(strings("asns"))),
        "urls": sorted(
            {u for u in strings("interesting_urls") if u.startswith(("https://", "http://"))}
        ),
    }


class TheHarvesterModule(BaseModule):
    name = "domain.theharvester"
    title = "Пассивный сбор по домену (theHarvester)"
    description = (
        "Хосты, IP, email-адреса и ASN домена из бесключевых пассивных источников (crt.sh, "
        "CertSpotter, HackerTarget, OTX…). Запуск в песочнице. Включается вручную."
    )
    target_types = frozenset({TargetType.DOMAIN})
    default_enabled = False
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="Пассивные источники theHarvester",
            url="см. список ниже",
            data_sent="доменное имя; источники видят ваш IP",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "Пассивные базы содержат устаревшие и мусорные записи: имя или адрес из источника не "
        "подтверждает, что они существуют сейчас или кому-то принадлежат.",
        "theHarvester (GPL-2.0) работает в песочнице без доступа к домашнему каталогу; "
        "API-ключи в него не передаются.",
    )

    def availability(self, settings: Settings) -> Availability:
        status = tool_status(settings, THEHARVESTER)
        if not status.ready:
            return Availability(False, status.problem)
        allowed, _ = parse_sources(settings.harvester_sources)
        if not allowed:
            return Availability(False, "в OSINT_HARVESTER_SOURCES нет разрешённых источников")
        return Availability(True)

    def effective_timeout(self, settings: Settings) -> float:
        return settings.harvester_total_timeout + 15

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        allowed, rejected = parse_sources(settings.harvester_sources)
        lines = [f"Домен «{target.normalized}» → источники: {', '.join(allowed)}"]
        if rejected:
            lines.append(f"отклонены (нужны ключи или неизвестны): {', '.join(rejected)}")
        return tuple(lines)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        status = tool_status(settings, THEHARVESTER)
        if not status.ready or status.python is None or not ctx.net.enabled:
            out.errors.append(status.problem or "сетевой доступ не разрешён")
            return out
        allowed, rejected = parse_sources(settings.harvester_sources)
        if rejected:
            out.limitations.append(f"Источники отклонены: {', '.join(rejected)}")
        domain = target.normalized
        ensure_private_dir(settings.cache_dir)
        work = Path(tempfile.mkdtemp(prefix="harvester-", dir=settings.cache_dir))
        try:
            policy = SandboxPolicy(
                network=True, read_only=sandbox_mounts(status.path), workdir=work
            )
            argv = [
                str(status.python),
                "-I",
                "-c",
                ENTRY,
                "-d",
                domain,
                "-b",
                ",".join(allowed),
                "-l",
                str(settings.harvester_limit),
                "-q",
                "-f",
                "/work/out",
            ]
            try:
                result = await run_sandboxed(policy, argv, limit_s=settings.harvester_total_timeout)
            except SandboxTimeoutError as exc:
                raise NetworkTimeoutError(str(exc)) from exc
            except SandboxError as exc:
                raise NetworkError(f"Песочница: {exc}") from exc
            if result.returncode != 0:
                raise NetworkError(
                    f"theHarvester завершился с кодом {result.returncode}: "
                    f"{result.stderr_tail(4) or 'без сообщения'}"
                )
            report = await asyncio.to_thread(_load, work / "out.json")
        finally:
            shutil.rmtree(work, ignore_errors=True)
        items = parse_report(report, domain)
        source = f"theHarvester {THEHARVESTER.version} ({', '.join(allowed)})"
        add = out.findings.append
        add(
            self.finding(
                target,
                "domain.harvest_scope",
                {
                    "sources": allowed,
                    "limit": settings.harvester_limit,
                    **{k: len(v) for k, v in items.items()},
                },
                Confidence.CONFIRMED,
                source,
                THEHARVESTER.homepage,
                "Параметры и объём пассивного сбора.",
                exclusive=True,
            )
        )
        labels = {
            "hosts": ("domain.harvested_hosts", "Имена хостов из пассивных источников"),
            "emails": (
                "domain.harvested_emails",
                "Адреса на этом домене, упомянутые в "
                "источниках; существование ящиков не проверялось",
            ),
            "ips": ("domain.harvested_ips", "IP-адреса, связанные с доменом в источниках"),
            "asns": ("domain.harvested_asns", "Автономные системы из источников"),
            "urls": ("domain.harvested_urls", "Интересные URL из источников"),
        }
        for key, (attribute, label) in labels.items():
            values = items[key]
            if values:
                shown: JsonValue = list(values[:MAX_ITEMS])
                add(
                    self.finding(
                        target,
                        attribute,
                        shown,
                        Confidence.UNVERIFIED,
                        source,
                        THEHARVESTER.homepage,
                        f"{label} ({len(values)}"
                        + (f", показаны первые {MAX_ITEMS}" if len(values) > MAX_ITEMS else "")
                        + ").",
                    )
                )
        if not any(items.values()):
            out.status = ModuleStatus.NO_RESULTS
        return out


def _load(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise NetworkError("theHarvester не создал отчёт")
    if path.stat().st_size > 30 * 1024 * 1024:
        raise NetworkError("Отчёт theHarvester слишком большой")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NetworkError(f"Некорректный отчёт theHarvester: {exc}") from exc

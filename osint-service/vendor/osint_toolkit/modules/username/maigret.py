"""Username search with Maigret (MIT, github.com/soxoj/maigret) — sandboxed adapter.

Maigret checks whether a profile page exists for a username on hundreds of sites. A hit means
only that *some* account with this name exists on that site: it may belong to anyone, be stale,
or be a false positive. Every hit is therefore ``unverified`` and the evidence says why it was
reported (the site-specific check rule), never that it belongs to a particular person.

Execution: ``python -I -m maigret`` from an isolated venv inside the bwrap sandbox with network
access but no home directory, no user environment and a temporary ``/work``. Recursive search,
profile data extraction and database auto-update are disabled; request timeout, retries,
concurrency and the number of sites are bounded by settings.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
import time
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
from osint_toolkit.modules.base import (
    Availability,
    BaseModule,
    ModuleContext,
    ModuleOutput,
    ProgressFn,
)
from osint_toolkit.net import NetworkError, NetworkTimeoutError
from osint_toolkit.sandbox import (
    SandboxError,
    SandboxPolicy,
    SandboxTimeoutError,
    run_sandboxed,
)
from osint_toolkit.tools import MAIGRET, tool_status
from osint_toolkit.tools.manager import sandbox_mounts

MAX_REPORT_BYTES = 20 * 1024 * 1024
_TOP_SITES_RE = re.compile(r"search on (?:top )?(\d+) sites")
# one line per checked site (with --print-not-found --print-errors): "[+] Site: url",
# "[-] Site: Not found!", "[?] Site: error"; ANSI erase codes may precede it
_SITE_LINE_RE = re.compile(r"^(?:\x1b\[[0-9;]*[A-Za-z]|\r)*\[(?:\+\+|\+|-|\?)\] [^:\n]{1,160}: ")
PROGRESS_INTERVAL_S = 0.25
CHECK_RULES = {
    "status_code": "страница профиля ответила успешным HTTP-статусом, а для несуществующего "
    "имени этот сайт отвечает ошибкой",
    "message": "в ответе сайта нет текста, которым он помечает несуществующий профиль",
    "response_url": "сайт не перенаправил запрос на страницу «профиль не найден»",
}
DISCLAIMER = (
    "Совпадает только имя пользователя: аккаунт может принадлежать другому человеку, быть "
    "заброшенным или оказаться ложным срабатыванием. Это не доказательство принадлежности."
)


def build_argv(python: Path, settings: Settings, username: str) -> list[str]:
    argv = [
        str(python),
        "-I",
        "-u",  # unbuffered stdout: one line per checked site arrives immediately (progress)
        "-m",
        MAIGRET.module,
        "--no-autoupdate",  # no database download from GitHub
        "--no-recursion",  # do not pivot to usernames found on pages
        "--no-extracting",  # do not scrape personal data from profile pages
        "--no-color",
        "--no-progressbar",
        "--print-not-found",  # a line for every site, so progress can be counted
        "--print-errors",
        "--timeout",
        f"{settings.maigret_timeout:g}",
        "--retries",
        str(settings.maigret_retries),
        "--max-connections",
        str(settings.maigret_max_connections),
        "--top-sites",
        str(settings.maigret_top_sites),
        "--json",
        "simple",
        "--folderoutput",
        "/work",
    ]
    if settings.http_proxy:
        argv += ["--proxy", str(settings.http_proxy)]
    # "--" ends option parsing: a username like "--debug" can never become a flag.
    return [*argv, "--", username]


class ProgressCounter:
    """Counts Maigret's per-site lines and reports "Проверено N из M сайтов"."""

    def __init__(self, report: ProgressFn, expected: int | None) -> None:
        self.report = report
        self.total = expected
        self.done = 0
        self.started = False
        self._last = 0.0

    def __call__(self, line: str) -> None:
        if not self.started:
            found = _TOP_SITES_RE.search(line)
            if found:
                self.started = True
                self.total = int(found.group(1))
                self.report(0, self.total, self.text)
            return
        if self.total is not None and self.done >= self.total:
            return
        if not _SITE_LINE_RE.match(line):
            return
        self.done += 1
        now = time.monotonic()
        if now - self._last >= PROGRESS_INTERVAL_S or self.done == self.total:
            self._last = now
            self.report(self.done, self.total, self.text)

    @property
    def text(self) -> str:
        total = self.total if self.total is not None else "?"
        return f"Проверено {self.done} из {total} сайтов"


def parse_report(data: Any) -> list[dict[str, Any]]:
    """Claimed accounts from a Maigret ``--json simple`` report."""
    if not isinstance(data, dict):
        raise ValueError("отчёт Maigret имеет неожиданный формат")
    hits: list[dict[str, Any]] = []
    for key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        raw_status = entry.get("status")
        status: dict[str, Any] = raw_status if isinstance(raw_status, dict) else {}
        if status.get("status") != "Claimed":
            continue
        url = entry.get("url_user") or status.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        raw_site = entry.get("site")
        site: dict[str, Any] = raw_site if isinstance(raw_site, dict) else {}
        tags = status.get("tags") or site.get("tags") or []
        hits.append(
            {
                "site": str(status.get("site_name") or key),
                "url": url,
                "tags": sorted({str(t) for t in tags if isinstance(t, str)}),
                "check": str(site.get("checkType") or "unknown"),
                "http_status": entry.get("http_status")
                if isinstance(entry.get("http_status"), int)
                else None,
                "similar": bool(entry.get("is_similar")),
                "rank": entry.get("rank") if isinstance(entry.get("rank"), int) else None,
            }
        )
    hits.sort(key=lambda h: (h["rank"] if h["rank"] is not None else 10**12, h["site"].lower()))
    return hits


class MaigretModule(BaseModule):
    name = "username.maigret"
    title = "Поиск профилей по username (Maigret)"
    description = (
        "Проверяет, существует ли профиль с этим именем на популярных сайтах (соцсети, форумы, "
        "сервисы). Запуск в песочнице bwrap; рекурсия и извлечение данных профилей отключены."
    )
    target_types = frozenset({TargetType.USERNAME})
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="Сайты из базы Maigret (соцсети, форумы, сервисы)",
            url="вся база Maigret (~5900 сайтов) или OSINT_MAIGRET_TOP_SITES самых популярных",
            data_sent="username — в адресах запросов к каждому сайту; сайты видят ваш IP",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        DISCLAIMER,
        "Отсутствие сайта в результатах не означает, что аккаунта нет: сайт мог не ответить, "
        "заблокировать запрос или изменить вёрстку.",
        "Maigret (MIT, github.com/soxoj/maigret) работает в песочнице без доступа к домашнему "
        "каталогу и вашему окружению.",
    )

    def availability(self, settings: Settings) -> Availability:
        status = tool_status(settings)
        if not status.ready:
            return Availability(False, status.problem)
        return Availability(True)

    def effective_timeout(self, settings: Settings) -> float:
        return settings.maigret_total_timeout + 15  # inner sandbox limit fires first

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        status = tool_status(settings)
        if not status.ready or status.python is None:
            out.errors.append(status.problem or "Maigret недоступен")
            return out
        if not ctx.net.enabled:  # consent/offline is enforced by the engine; double-check here
            out.errors.append("Сетевой доступ для модуля не разрешён")
            return out
        username = target.normalized
        ensure_private_dir(settings.cache_dir)
        work = Path(tempfile.mkdtemp(prefix="maigret-", dir=settings.cache_dir))
        try:
            policy = SandboxPolicy(
                network=True, read_only=sandbox_mounts(status.path), workdir=work
            )
            counter = ProgressCounter(ctx.progress, settings.maigret_top_sites or None)
            ctx.progress(0, counter.total, "Запуск Maigret…")
            try:
                result = await run_sandboxed(
                    policy,
                    build_argv(status.python, settings, username),
                    limit_s=settings.maigret_total_timeout,
                    on_stdout_line=counter,
                )
            except SandboxTimeoutError as exc:
                raise NetworkTimeoutError(str(exc)) from exc
            except SandboxError as exc:
                raise NetworkError(f"Песочница: {exc}") from exc
            if result.returncode != 0:
                raise NetworkError(
                    f"Maigret завершился с кодом {result.returncode}: "
                    f"{result.stderr_tail(4) or 'без сообщения'}"
                )
            report = await asyncio.to_thread(_load_report, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)

        hits = parse_report(report)
        stdout = result.stdout.decode("utf-8", errors="replace")
        match = _TOP_SITES_RE.search(stdout)
        checked = int(match.group(1)) if match else None
        version = status.version or MAIGRET.version
        scope: dict[str, JsonValue] = {
            "sites_checked": checked,
            "candidates": len(hits),
            "top_sites": settings.maigret_top_sites,
            "request_timeout_s": settings.maigret_timeout,
        }
        out.findings.append(
            self.finding(
                target,
                "username.search_scope",
                scope,
                Confidence.CONFIRMED,
                f"Maigret {version}",
                MAIGRET.homepage,
                f"Проверено сайтов: {checked if checked is not None else 'н/д'}, найдено "
                f"кандидатов: {len(hits)}. Это параметры и итог поиска, а не сведения о человеке.",
                exclusive=True,
            )
        )
        for hit in hits:
            rule = CHECK_RULES.get(hit["check"], f"правило Maigret «{hit['check']}»")
            evidence = f"Maigret счёл, что профиль «{username}» на {hit['site']} существует: {rule}"
            if hit["http_status"]:
                evidence += f" (HTTP {hit['http_status']})"
            evidence += ". "
            if hit["similar"]:
                evidence += "Maigret пометил совпадение как приблизительное. "
            value: dict[str, JsonValue] = {
                "site": hit["site"],
                "url": hit["url"],
                "tags": hit["tags"],
            }
            out.findings.append(
                self.finding(
                    target,
                    "username.profile_candidate",
                    value,
                    Confidence.UNVERIFIED,
                    f"Maigret {version} → {hit['site']}",
                    hit["url"],
                    evidence + DISCLAIMER,
                )
            )
        if result.truncated:
            out.limitations.append("Вывод Maigret был усечён по размеру.")
        if not hits:
            out.status = ModuleStatus.NO_RESULTS  # only the scope summary exists
            out.limitations.append("Профилей с таким именем на проверенных сайтах не найдено.")
        return out


def _load_report(work: Path) -> Any:
    reports = sorted(work.glob("report_*_simple.json"))
    if not reports:
        raise NetworkError("Maigret не создал отчёт (возможно, ни один сайт не ответил)")
    path = reports[0]
    if path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES:
        raise NetworkError("Отчёт Maigret отклонён (символическая ссылка или слишком большой)")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NetworkError(f"Некорректный отчёт Maigret: {exc}") from exc

"""Command-line entry point: ``osint``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from rich import box
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, IntPrompt
from rich.table import Table
from rich.text import Text

from osint_toolkit import __version__
from osint_toolkit.config import (
    Settings,
    default_env_file,
    init_env_file,
    load_settings,
    load_settings_lenient,
)
from osint_toolkit.console import (
    RichConsent,
    render_investigation,
    render_targets,
    status_text,
)
from osint_toolkit.core.detector import UnsupportedInputError, declare_own, detect, parse_as
from osint_toolkit.core.engine import Engine, Plan, PlanError
from osint_toolkit.core.models import (
    Investigation,
    InvestigationStatus,
    ModuleResult,
    Target,
    TargetType,
)
from osint_toolkit.core.privacy import AllowModules, ConsentProvider, PrivacyGate
from osint_toolkit.core.registry import ModuleRegistry, load_registry
from osint_toolkit.logging_setup import setup_logging
from osint_toolkit.modules.base import BaseModule
from osint_toolkit.reports import (
    PdfOptions,
    ReportFormat,
    generate_reports,
    parse_formats,
    purge_reports,
)
from osint_toolkit.reports.generator import REPORT_NAME_RE
from osint_toolkit.storage.db import Storage

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_CANCELLED = 0, 1, 2, 130


@dataclass
class AppContext:
    settings: Settings
    console: Console
    err: Console

    @cached_property
    def registry(self) -> ModuleRegistry:
        return load_registry()

    @cached_property
    def storage(self) -> Storage:
        return Storage(self.settings.db_path, store_targets=self.settings.store_targets)

    @property
    def interactive(self) -> bool:
        return sys.stdin.isatty() and self.console.is_terminal


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint",
        description="Personal OSINT Toolkit — исследование открытых источников, локально.",
    )
    parser.add_argument("--version", action="version", version=f"osint-toolkit {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный лог в stderr")
    sub = parser.add_subparsers(dest="command", metavar="КОМАНДА")

    run = sub.add_parser("run", help="запустить исследование (по умолчанию Full Investigation)")
    run.add_argument("query", nargs="+", help="email, username, телефон, ФИО, домен, IP или путь")
    run.add_argument("-t", "--type", choices=[t.value for t in TargetType], help="задать тип")
    run.add_argument("-m", "--module", action="append", default=[], help="только эти модули")
    run.add_argument("-x", "--exclude", action="append", default=[], help="исключить модуль")
    run.add_argument("--offline", action="store_true", help="запретить все внешние запросы")
    run.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="МОДУЛЬ",
        help="заранее разрешить внешние запросы модуля ('all' — всем); иначе спросит",
    )
    run.add_argument("--region", help="регион для номеров без «+», например RU")
    run.add_argument(
        "--own",
        action="store_true",
        help="это мой собственный email: разрешает самопроверку Gravatar и holehe",
    )
    run.add_argument("--json", action="store_true", help="вывести результат в JSON")
    run.add_argument(
        "-r",
        "--report",
        metavar="ФОРМАТЫ",
        help="форматы отчёта: txt,json,html,md | all | none (по умолчанию OSINT_REPORT_FORMATS)",
    )
    run.add_argument("--no-report", action="store_true", help="не сохранять отчёты")
    run.add_argument("-o", "--output", type=Path, help="каталог для отчётов")

    rep = sub.add_parser(
        "report",
        help="отчёты: построить (в т.ч. PDF) из файла результатов или истории, удалить",
        description="osint report --format pdf --input <файл.json | ID>  — построить отчёт",
    )
    rep.add_argument(
        "-i",
        "--input",
        dest="input_file",
        metavar="ФАЙЛ|ID",
        help="JSON-отчёт программы, вывод osint run --json или ID исследования из истории",
    )
    rep.add_argument(
        "-f", "--format", dest="input_format", metavar="ФОРМАТЫ", help="pdf,html,md,txt,json | all"
    )
    rep.add_argument("-o", "--output", dest="input_output", type=Path, help="каталог для отчёта")
    rsub = rep.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    rb = rsub.add_parser("build", help="построить отчёт по исследованию из истории")
    rb.add_argument("id")
    rb.add_argument("-f", "--format", default="all", help="txt,json,html,md,pdf | all")
    rb.add_argument("-o", "--output", type=Path, help="каталог для отчётов")
    rsub.add_parser("list", help="сохранённые отчёты")
    rp = rsub.add_parser("purge", help="удалить все отчёты, созданные программой")
    rp.add_argument("-y", "--yes", action="store_true", help="без подтверждения")

    sub.add_parser("tui", help="открыть интерактивный интерфейс (по умолчанию без аргументов)")

    det = sub.add_parser("detect", help="определить тип входных данных (без запросов)")
    det.add_argument("query", nargs="+")
    det.add_argument("--region")

    mods = sub.add_parser("modules", help="список модулей и их готовность")
    mods.add_argument("-t", "--type", choices=[t.value for t in TargetType])

    hist = sub.add_parser("history", help="история исследований")
    hsub = hist.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    hl = hsub.add_parser("list", help="последние исследования")
    hl.add_argument("-n", "--limit", type=int, default=20)
    hs = hsub.add_parser("show", help="показать исследование")
    hs.add_argument("id")
    hs.add_argument("--json", action="store_true")
    hd = hsub.add_parser("delete", help="удалить исследование")
    hd.add_argument("id")
    hp = hsub.add_parser("purge", help="удалить всю историю")
    hp.add_argument("-y", "--yes", action="store_true", help="без подтверждения")

    cons = sub.add_parser("consent", help="сохранённые решения о внешних запросах")
    csub = cons.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    csub.add_parser("list", help="показать решения")
    cr = csub.add_parser("revoke", help="отозвать решение")
    cr.add_argument("module", nargs="?", help="модуль; без аргумента — все")

    data = sub.add_parser("data", help="локальные базы данных (DB-IP Lite)")
    dsub = data.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    dsub.add_parser("status", help="установленные базы")
    du = dsub.add_parser("update", help="скачать/обновить DB-IP Lite (Country + ASN)")
    du.add_argument("--city", action="store_true", help="также City-базу (~60 МБ в архиве)")
    du.add_argument("-y", "--yes", action="store_true", help="без подтверждения")

    from osint_toolkit.tools import TOOLS

    tool_names = sorted(TOOLS)
    tools = sub.add_parser(
        "tools", help=f"изолированные внешние инструменты ({', '.join(tool_names)})"
    )
    tsub = tools.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    tsub.add_parser("status", help="состояние инструментов и песочницы")
    ti = tsub.add_parser("install", help="установить закреплённую версию (в песочнице)")
    ti.add_argument("name", choices=tool_names)
    ti.add_argument("-y", "--yes", action="store_true", help="без подтверждения")
    tr = tsub.add_parser("remove", help="удалить инструмент")
    tr.add_argument("name", choices=tool_names)
    tr.add_argument("-y", "--yes", action="store_true", help="без подтверждения")

    plg = sub.add_parser("plugins", help="внешние инструменты-плагины (plugins.toml)")
    psub = plg.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    psub.add_parser("list", help="подключённые плагины и ошибки в описании")
    psub.add_parser("init", help="создать plugins.toml с примером (права 600)")
    psub.add_parser("path", help="где лежит plugins.toml")

    upd = sub.add_parser("update", help="проверить и установить обновление программы")
    upd.add_argument("--check", action="store_true", help="только проверить и показать изменения")
    upd.add_argument(
        "--rollback", action="store_true", help="вернуть версию до последнего обновления"
    )
    upd.add_argument(
        "--data", action="store_true", help="также проверить новые выпуски баз DB-IP Lite"
    )
    upd.add_argument(
        "-y", "--yes", action="store_true", help="согласие на запрос к источнику и установку"
    )

    cfg = sub.add_parser("config", help="настройки")
    gsub = cfg.add_subparsers(dest="action", metavar="ДЕЙСТВИЕ")
    gsub.add_parser("show", help="текущие настройки (ключи скрыты)")
    gsub.add_parser("path", help="пути к файлам")
    gsub.add_parser("init", help="создать ~/.config/osint-toolkit/.env (права 600)")
    return parser


# --------------------------------------------------------------------------- commands
def cmd_detect(ctx: AppContext, args: argparse.Namespace) -> int:
    query = " ".join(args.query)
    try:
        candidates = detect(query, default_region=args.region or ctx.settings.default_region)
    except UnsupportedInputError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_USAGE
    ctx.console.print(render_targets(candidates))
    return EXIT_OK


def cmd_modules(ctx: AppContext, args: argparse.Namespace) -> int:
    registry = ctx.registry
    modules = registry.for_type(TargetType(args.type)) if args.type else registry.all()
    table = Table(box=box.ROUNDED, title=f"Модули ({len(modules)})", title_justify="left")
    table.add_column("Модуль")
    table.add_column("Типы целей")
    table.add_column("Сеть")
    table.add_column("Готов")
    table.add_column("Описание", overflow="fold", style="grey70")
    for m in modules:
        avail = m.availability(ctx.settings)
        network = (
            Text(", ".join(s.name for s in m.external_services), style="yellow")
            if m.is_external
            else Text("офлайн", style="green")
        )
        ready = Text("да", style="green") if avail.available else Text(avail.reason or "нет", "red")
        if avail.available and not m.default_enabled:
            ready = Text("по запросу", style="cyan")
        types = ", ".join(sorted(t.label for t in m.target_types))
        table.add_row(
            Text(f"{m.title}\n") + Text(m.name, "grey50"),
            types,
            network,
            ready,
            Text(m.description),
        )
    ctx.console.print(table)
    for where, error in registry.load_errors.items():
        ctx.err.print(Text(f"Не загружен {where}: {error}", style="red"))
    return EXIT_OK


def short_target(target: Target) -> str:
    """Compact label: file name for images instead of a long absolute path."""
    if target.type is TargetType.IMAGE:
        return str(target.details.get("file_name") or Path(target.normalized).name)
    return target.normalized


class CliProgress:
    """Progress listener rendering a Rich progress bar plus one line per finished module."""

    def __init__(self, console: Console) -> None:
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
            transient=True,
        )
        self.task = self.progress.add_task("Модули", total=None)

    def on_planned(self, plan: Plan) -> None:
        self.progress.update(self.task, total=len(plan.runs))

    def on_module_started(self, module: BaseModule, target: Target) -> None:
        self.progress.update(self.task, description=module.title)

    def on_module_finished(self, result: ModuleResult) -> None:
        line = Text("  ") + status_text(result.status) + Text(f"  {result.module_title}")
        line.append(f" → {short_target(result.target)}", style="grey50")
        self.progress.console.print(line)
        self.progress.advance(self.task)


def _choose_target(ctx: AppContext, candidates: list[Target]) -> Target:
    if len(candidates) == 1 or not ctx.interactive:
        if len(candidates) > 1:
            ctx.err.print(
                Text(
                    f"Неоднозначный ввод, выбран тип «{candidates[0].type.label}». "
                    "Укажите --type, чтобы выбрать другой.",
                    style="yellow",
                )
            )
        return candidates[0]
    ctx.console.print(render_targets(candidates))
    index = IntPrompt.ask(
        "Выберите вариант", choices=[str(i) for i in range(1, len(candidates) + 1)], default=1
    )
    return candidates[index - 1]


def cmd_run(ctx: AppContext, args: argparse.Namespace) -> int:
    query = " ".join(args.query)
    region = args.region or ctx.settings.default_region
    if args.offline:
        ctx.settings = ctx.settings.model_copy(update={"offline": True})
    try:
        if args.type:
            target = parse_as(query, TargetType(args.type), default_region=region)
        else:
            target = _choose_target(ctx, detect(query, default_region=region))
    except UnsupportedInputError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_USAGE
    if args.own:
        if target.type is not TargetType.EMAIL:
            ctx.err.print(Text("--own применим только к email-адресу", style="red"))
            return EXIT_USAGE
        target = declare_own(target)

    output = ctx.err if args.json else ctx.console
    consent: ConsentProvider = (
        AllowModules(args.allow) if args.allow else RichConsent(output, interactive=ctx.interactive)
    )
    listener = CliProgress(output)
    engine = Engine(
        ctx.settings, ctx.registry, consent=consent, storage=ctx.storage, listener=listener
    )
    try:
        if args.module or args.exclude:
            plan = engine.plan_targeted(
                target, args.module or None, exclude=args.exclude, query=query
            )
        else:
            plan = engine.plan_full(target, query)
    except PlanError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_USAGE
    if not plan.runs:
        ctx.err.print(Text("Нет модулей для этой цели.", style="yellow"))
        return EXIT_USAGE

    try:
        formats = parse_formats(
            "none" if args.no_report else (args.report or ctx.settings.report_formats)
        )
    except ValueError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_USAGE

    investigation = asyncio.run(_execute(engine, plan, listener, output))
    if args.json:
        ctx.console.print_json(investigation.model_dump_json())
    else:
        ctx.console.print(render_investigation(investigation))
    if formats:
        _write_reports(ctx, investigation, formats, args.output)
    return EXIT_CANCELLED if investigation.status is InvestigationStatus.CANCELLED else EXIT_OK


async def _execute(
    engine: Engine, plan: Plan, listener: CliProgress, console: Console
) -> Investigation:
    # Consent first, with default Ctrl+C behaviour (aborts the program).
    decisions = await engine.authorize(plan)
    loop = asyncio.get_running_loop()
    presses = 0

    def on_sigint() -> None:
        nonlocal presses
        presses += 1
        if presses == 1:
            console.print(Text("Отмена… (ещё раз Ctrl+C — немедленный выход)", style="magenta"))
            engine.cancel()
        else:
            loop.remove_signal_handler(signal.SIGINT)
            signal.raise_signal(signal.SIGINT)

    loop.add_signal_handler(signal.SIGINT, on_sigint)
    try:
        with listener.progress:
            return await engine.execute(plan, decisions)
    finally:
        loop.remove_signal_handler(signal.SIGINT)


def _write_reports(
    ctx: AppContext, investigation: Investigation, formats: list[ReportFormat], out: Path | None
) -> list[Path]:
    target_dir = out.expanduser() if out else ctx.settings.effective_reports_dir
    try:
        paths = generate_reports(
            investigation,
            formats,
            target_dir,
            private_dir=out is None,
            pdf=PdfOptions.from_settings(ctx.settings),
        )
    except OSError as exc:
        ctx.err.print(Text(f"Не удалось сохранить отчёт: {exc}", style="red"))
        return []
    for path in paths:
        ctx.err.print(
            Text("Отчёт: ", style="grey62") + Text(str(path), style="bold"), soft_wrap=True
        )  # keep the path on one line for copy/paste
    return paths


def _load_results(ctx: AppContext, source: str) -> Investigation | None:
    """A results file (JSON report or `osint run --json` output) or a history ID."""
    from osint_toolkit.reports.renderers import load_json_report

    path = Path(source).expanduser()
    if path.is_file():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            ctx.err.print(Text(f"Не удалось прочитать {path}: {exc}", style="red"))
            return None
        try:
            return load_json_report(text)
        except (ValueError, ValidationError):
            pass
        try:
            return Investigation.model_validate_json(text)
        except ValidationError:
            ctx.err.print(
                Text(
                    f"{path}: это не JSON-отчёт программы и не вывод `osint run --json`",
                    style="red",
                )
            )
            return None
    full = _resolve(ctx, source)
    if full is None:
        return None
    investigation = ctx.storage.get(full)
    if investigation is None:
        ctx.err.print(Text("Для этой записи сохранена только сводка.", style="yellow"))
    return investigation


def cmd_report(ctx: AppContext, args: argparse.Namespace) -> int:
    if args.input_file and args.action is None:
        investigation = _load_results(ctx, args.input_file)
        if investigation is None:
            return EXIT_USAGE
        try:
            formats = parse_formats(args.input_format or "pdf")
        except ValueError as exc:
            ctx.err.print(Text(str(exc), style="red"))
            return EXIT_USAGE
        written = _write_reports(ctx, investigation, formats, args.input_output)
        return EXIT_OK if written else EXIT_ERROR
    action = args.action or "list"
    reports_dir = ctx.settings.effective_reports_dir
    if action == "list":
        files = (
            sorted(p for p in reports_dir.glob("osint-*") if REPORT_NAME_RE.match(p.name))
            if reports_dir.is_dir()
            else []
        )
        if not files:
            ctx.console.print(Text(f"Отчётов нет ({reports_dir}).", style="grey62"))
            return EXIT_OK
        table = Table(box=box.ROUNDED, title=f"Отчёты — {reports_dir}", title_justify="left")
        table.add_column("Файл")
        table.add_column("Размер", justify="right")
        for path in files:
            table.add_row(path.name, f"{path.stat().st_size / 1024:.1f} КБ")
        ctx.console.print(table)
        return EXIT_OK
    if action == "purge":
        if not args.yes and not Confirm.ask(f"Удалить все отчёты в {reports_dir}?", default=False):
            return EXIT_OK
        removed = purge_reports(reports_dir)
        ctx.console.print(Text(f"Удалено отчётов: {removed}", style="green"))
        return EXIT_OK
    full = _resolve(ctx, args.id)
    if full is None:
        return EXIT_USAGE
    investigation = ctx.storage.get(full)
    if investigation is None:
        ctx.err.print(
            Text(
                "Для этой записи сохранена только сводка — отчёт построить нельзя.", style="yellow"
            )
        )
        return EXIT_ERROR
    try:
        formats = parse_formats(args.format)
    except ValueError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_USAGE
    return EXIT_OK if _write_reports(ctx, investigation, formats, args.output) else EXIT_ERROR


def _resolve(ctx: AppContext, raw_id: str) -> str | None:
    full = ctx.storage.resolve_id(raw_id)
    if full is None:
        ctx.err.print(Text(f"Исследование не найдено или префикс неоднозначен: {raw_id}", "red"))
    return full


def cmd_history(ctx: AppContext, args: argparse.Namespace) -> int:
    storage = ctx.storage
    action = args.action or "list"
    if action == "list":
        entries = storage.list(getattr(args, "limit", 20))
        if not entries:
            ctx.console.print(Text("История пуста.", style="grey62"))
            return EXIT_OK
        table = Table(box=box.ROUNDED, title=f"История ({storage.count()})", title_justify="left")
        for col in ("ID", "Дата", "Тип", "Цель", "Режим", "Находок", "Статус"):
            table.add_column(col)
        for e in entries:
            table.add_row(
                Text(e.id[:8], style="grey62"),
                e.created_at.astimezone().strftime("%Y-%m-%d %H:%M"),
                TargetType(e.target_type).label,
                Text(e.target) if e.target else Text("скрыто", style="grey50 italic"),
                e.mode,
                str(e.summary.get("findings", 0)),
                Text(e.status, style="green" if e.status == "completed" else "magenta"),
            )
        ctx.console.print(table)
        return EXIT_OK

    if action == "purge":
        total = storage.count()
        if not args.yes and not Confirm.ask(
            f"Удалить всю историю ({total} записей) без возможности восстановления?", default=False
        ):
            return EXIT_OK
        removed = storage.purge()
        ctx.console.print(Text(f"Удалено записей: {removed}. Файл БД сжат (VACUUM).", "green"))
        ctx.console.print(
            Text("Сохранённые файлы отчётов не удалены: osint report purge", style="grey62")
        )
        return EXIT_OK

    full = _resolve(ctx, args.id)
    if full is None:
        return EXIT_USAGE
    if action == "delete":
        storage.delete(full)
        ctx.console.print(Text(f"Удалено: {full}", style="green"))
        return EXIT_OK
    investigation = storage.get(full)
    if investigation is None:
        ctx.err.print(
            Text(
                "Для этой записи сохранена только сводка (OSINT_STORE_TARGETS=false).",
                style="yellow",
            )
        )
        return EXIT_ERROR
    if args.json:
        ctx.console.print_json(investigation.model_dump_json())
    else:
        ctx.console.print(render_investigation(investigation))
    return EXIT_OK


def cmd_consent(ctx: AppContext, args: argparse.Namespace) -> int:
    if (args.action or "list") == "list":
        consents = ctx.storage.consents()
        if not consents:
            ctx.console.print(
                Text(
                    "Сохранённых решений нет: каждый внешний запрос подтверждается отдельно.",
                    style="grey62",
                )
            )
            return EXIT_OK
        table = Table(box=box.ROUNDED, title="Сохранённые решения")
        table.add_column("Модуль")
        table.add_column("Решение")
        for module, allowed in consents.items():
            table.add_row(
                module,
                Text("всегда разрешать", "yellow") if allowed else Text("всегда запрещать", "cyan"),
            )
        ctx.console.print(table)
        return EXIT_OK
    removed = ctx.storage.revoke_consent(args.module)
    ctx.console.print(Text(f"Отозвано решений: {removed}", style="green"))
    return EXIT_OK


def cmd_data(ctx: AppContext, args: argparse.Namespace) -> int:
    from osint_toolkit.data import dbip

    geo_dir = ctx.settings.geo_dir
    if (args.action or "status") == "status":
        table = Table(box=box.ROUNDED, title=f"Базы DB-IP Lite — {geo_dir}", title_justify="left")
        for col in ("База", "Установлена", "Версия", "Сборка", "Размер"):
            table.add_column(col)
        for kind in dbip.DbipKind:
            st = dbip.status(geo_dir, kind)
            table.add_row(
                kind.value,
                Text("да", "green") if st.present else Text("нет", "yellow"),
                st.version or "—",
                st.build_date or "—",
                f"{st.size / 2**20:.1f} МБ" if st.present else "—",
            )
        ctx.console.print(table)
        ctx.console.print(Text(dbip.ATTRIBUTION, style="grey62"))
        return EXIT_OK
    if ctx.settings.offline:
        ctx.err.print(Text("OSINT_OFFLINE=true: загрузка запрещена.", style="red"))
        return EXIT_USAGE
    if not args.yes and not ctx.interactive:
        ctx.err.print(
            Text("Нужно подтверждение: запустите в терминале или добавьте --yes", style="yellow")
        )
        return EXIT_USAGE
    kinds = [dbip.DbipKind.COUNTRY, dbip.DbipKind.ASN] + ([dbip.DbipKind.CITY] if args.city else [])
    return asyncio.run(_data_update(ctx, kinds, assume_yes=args.yes))


async def _data_update(ctx: AppContext, kinds: list[Any], *, assume_yes: bool) -> int:
    from osint_toolkit.data import dbip
    from osint_toolkit.net import HttpClient, NetworkError

    http = HttpClient(ctx.settings)
    try:
        try:
            remotes = [await dbip.find_remote(http, kind) for kind in kinds]
        except NetworkError as exc:
            ctx.err.print(Text(f"Не удалось проверить файлы на db-ip.com: {exc}", style="red"))
            return EXIT_ERROR
        table = Table(box=box.ROUNDED, title="Будут скачаны", title_justify="left")
        for col in ("Файл", "Размер", "Источник"):
            table.add_column(col)
        for remote in remotes:
            size = f"{remote.size / 2**20:.1f} МБ" if remote.size else "неизвестен"
            table.add_row(remote.url.rsplit("/", 1)[-1], size, "download.db-ip.com")
        ctx.console.print(table)
        ctx.console.print(
            Text(
                "Серверу db-ip.com будет виден только ваш IP-адрес; данные "
                "исследований не передаются. Лицензия: " + dbip.ATTRIBUTION,
                style="grey62",
            )
        )
        if not assume_yes and not Confirm.ask("Скачать?", default=False):
            return EXIT_OK
        for remote in remotes:
            with ctx.console.status(f"Загрузка {remote.kind.value}…"):
                try:
                    st = await dbip.download(http, remote, ctx.settings.geo_dir)
                except NetworkError as exc:
                    ctx.err.print(Text(f"{remote.kind.value}: {exc}", style="red"))
                    return EXIT_ERROR
            ctx.console.print(
                Text(
                    f"✓ {remote.kind.value}: {st.version}, {st.size / 2**20:.1f} МБ → {st.path}",
                    style="green",
                )
            )
        return EXIT_OK
    finally:
        await http.aclose()


def cmd_tools(ctx: AppContext, args: argparse.Namespace) -> int:
    from osint_toolkit.sandbox import SandboxError, sandbox_status
    from osint_toolkit.tools import (
        TOOLS,
        ToolError,
        get_spec,
        install_summary,
        install_tool,
        remove_tool,
        tool_status,
    )

    action = args.action or "status"
    if action == "status":
        sandbox = sandbox_status()
        table = Table(box=box.ROUNDED, title="Инструменты", title_justify="left")
        for col in ("Инструмент", "Версия", "Закреплена", "Лицензия", "Состояние"):
            table.add_column(col)
        for spec in TOOLS.values():
            st = tool_status(ctx.settings, spec)
            style = "red" if not st.sandbox_ok else "green" if st.ready else "yellow"
            state = Text(st.summary, "yellow" if st.outdated else style)
            table.add_row(spec.name, st.version or "—", spec.version, spec.license, state)
        ctx.console.print(table)
        line = (
            Text(f"Песочница: {sandbox.version} — работает", style="green")
            if sandbox.available
            else Text(f"Песочница недоступна: {sandbox.reason}", style="red")
        )
        ctx.console.print(line)
        ctx.console.print(Text(f"Каталог инструментов: {ctx.settings.tools_dir}", style="dim"))
        return EXIT_OK
    spec = get_spec(args.name)
    if action == "remove":
        if not args.yes and not ctx.interactive:
            ctx.err.print(Text("Нужно подтверждение: добавьте --yes", style="yellow"))
            return EXIT_USAGE
        if not args.yes and not Confirm.ask(f"Удалить {spec.name}?", default=False):
            return EXIT_OK
        try:
            removed = remove_tool(ctx.settings, spec)
        except ToolError as exc:
            ctx.err.print(Text(str(exc), style="red"))
            return EXIT_ERROR
        ctx.console.print(Text("Удалено." if removed else "Не был установлен.", style="green"))
        return EXIT_OK
    if ctx.settings.offline:
        ctx.err.print(Text("OSINT_OFFLINE=true: установка запрещена.", style="red"))
        return EXIT_USAGE
    ctx.console.print(
        Text(f"Будет установлен {install_summary(ctx.settings, spec)}", style="grey70")
    )
    if not args.yes and not ctx.interactive:
        ctx.err.print(
            Text("Нужно подтверждение: запустите в терминале или добавьте --yes", style="yellow")
        )
        return EXIT_USAGE
    if not args.yes and not Confirm.ask("Установить?", default=False):
        return EXIT_OK
    try:
        with ctx.console.status("Установка в песочнице… (может занять несколько минут)"):
            st = asyncio.run(install_tool(ctx.settings, spec))
    except (ToolError, SandboxError) as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_ERROR
    ctx.console.print(Text(f"✓ {spec.name} {st.version} установлен: {st.path}", style="green"))
    return EXIT_OK


def cmd_plugins(ctx: AppContext, args: argparse.Namespace) -> int:
    from osint_toolkit.plugins import command_for, init_plugins_file, load_plugins, plugins_file

    action = args.action or "list"
    if action == "path":
        ctx.console.print(str(plugins_file()))
        return EXIT_OK
    if action == "init":
        path, created = init_plugins_file()
        msg = f"Создан {path} (права 600)" if created else f"Уже существует: {path}"
        ctx.console.print(Text(msg, style="green" if created else "yellow"))
        return EXIT_OK
    specs, errors = load_plugins()
    path = plugins_file()
    if not path.exists():
        ctx.console.print(
            Text(f"Плагинов нет: {path} не создан. Шаблон: osint plugins init", style="grey62")
        )
        return EXIT_OK
    table = Table(box=box.ROUNDED, title=f"Плагины — {path}", title_justify="left")
    for col in ("Модуль", "Типы", "Сеть", "В Full", "Команда"):
        table.add_column(col, overflow="fold")
    sample = Target(raw="VALUE", type=TargetType.EMAIL, normalized="<значение>")
    for spec in specs:
        table.add_row(
            Text(f"plugin.{spec.name}\n{spec.title}"),
            ", ".join(t.value for t in spec.types),
            Text("да", "yellow") if spec.network else "нет",
            "да" if spec.default else "нет (-m)",
            Text(" ".join(command_for(spec, sample)), style="grey62"),
        )
    ctx.console.print(table)
    for where, message in errors:
        ctx.err.print(Text(f"✖ {where}: {message}", style="red"))
    return EXIT_ERROR if errors else EXIT_OK


def _gate(ctx: AppContext, assume_yes: bool, module: str) -> PrivacyGate:

    provider: ConsentProvider = (
        AllowModules([module])
        if assume_yes
        else RichConsent(ctx.console, interactive=ctx.interactive)
    )
    return PrivacyGate(provider, storage=ctx.storage, offline=ctx.settings.offline)


def _consent(
    ctx: AppContext,
    assume_yes: bool,
    *,
    module: str,
    title: str,
    host: str,
    url: str,
    data_sent: str,
    details: Sequence[str],
) -> bool:
    """Ask through the PrivacyGate (offline mode, remembered decisions, exact requests)."""
    from osint_toolkit.core.models import ExternalRequest, ExternalService
    from osint_toolkit.core.privacy import request_key

    request = ExternalRequest(
        module=module,
        module_title=title,
        target=Target(raw=url, type=TargetType.DOMAIN, normalized=host),
        services=(ExternalService(name=host, url=url, data_sent=data_sent),),
        details=tuple(details),
    )
    decisions = asyncio.run(_gate(ctx, assume_yes, module).authorize([request]))
    decision = decisions[request_key(request)]
    if not decision.allowed:
        ctx.err.print(Text(f"Запрос к {host} не выполнен: {decision.reason}", style="yellow"))
    return bool(decision.allowed)


def cmd_update(ctx: AppContext, args: argparse.Namespace) -> int:
    from osint_toolkit import update as upd

    try:
        checkout = upd.locate_checkout()
    except upd.UpdateError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_ERROR
    if args.rollback:
        return _update_rollback(ctx, args, checkout)
    source = upd.display_url(checkout.remote_url)
    host = upd.remote_host(checkout.remote_url) if checkout.network else "локальный каталог"
    pypi_line = f"при установке, если изменился uv.lock: uv sync загрузит пакеты с {upd.PYPI_HOSTS}"
    if checkout.network and not _consent(
        ctx,
        args.yes,
        module=upd.UPDATE_MODULE,
        title="Проверка обновлений программы",
        host=host,
        url=source,
        data_sent="запрос git fetch ветки программы; сервер видит ваш IP-адрес, данные "
        "исследований не передаются",
        details=(
            f"git fetch {checkout.remote} {checkout.remote_branch}  ←  {source}",
            pypi_line,
        ),
    ):
        return EXIT_USAGE
    try:
        with ctx.console.status(f"Получение изменений из {source}…"):
            upd.fetch(checkout)
        info = upd.inspect(checkout)
    except upd.UpdateError as exc:
        ctx.err.print(Text(f"Не удалось проверить обновления: {exc}", style="red"))
        return EXIT_ERROR
    _render_update(ctx, checkout, info)
    _render_tool_pins(ctx, info)
    if args.data:
        _dbip_check(ctx, args.yes)
    state = upd.load_state(ctx.settings)
    if state and state.get("status") == "applied" and state.get("target") == info.current:
        ctx.console.print(
            Text(
                f"Откат к версии {state.get('previous_version')} "
                f"({str(state.get('previous'))[:12]}): osint update --rollback",
                style="grey62",
            )
        )
    if not info.available:
        msg = "Установлена последняя версия."
        if info.ahead:
            msg += f" Локальных коммитов, которых нет в источнике: {info.ahead}."
        ctx.console.print(Text(msg, style="green"))
        return EXIT_OK
    if info.blocker:
        ctx.err.print(Text(f"Обновление невозможно: {info.blocker}", style="red"))
        return EXIT_ERROR
    if args.check:
        ctx.console.print(Text("Установить: osint update", style="grey62"))
        return EXIT_OK
    try:
        upd.check_environment(checkout)
    except upd.UpdateError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_ERROR
    offline_sync = ctx.settings.offline
    if info.deps_changed and not offline_sync and not checkout.network:
        offline_sync = not _consent(
            ctx,
            args.yes,
            module=upd.UPDATE_MODULE,
            title="Загрузка зависимостей обновления",
            host="pypi.org",
            url="https://pypi.org",
            data_sent="имена и версии пакетов из uv.lock; сервер видит ваш IP-адрес",
            details=(pypi_line,),
        )
        if offline_sync:
            ctx.console.print(Text("Зависимости будут взяты только из кэша uv.", style="yellow"))
    if not args.yes and not ctx.interactive:
        ctx.err.print(
            Text("Нужно подтверждение: запустите в терминале или добавьте --yes", style="yellow")
        )
        return EXIT_USAGE
    question = f"Установить {info.target_version} ({info.target[:12]})?"
    if not args.yes and not Confirm.ask(question, default=False):
        return EXIT_OK
    try:
        with ctx.console.status("Установка обновления…"):
            result = upd.apply_update(checkout, info, ctx.settings, offline=offline_sync)
    except upd.UpdateError as exc:
        ctx.err.print(Text(f"Обновление не установлено: {exc}", style="red"))
        return EXIT_ERROR
    ctx.console.print(
        Text(
            f"✓ Обновлено до {info.target_version} ({result.current[:12]}); проверка: "
            f"{result.check}. Откат: osint update --rollback",
            style="green",
        )
    )
    if info.tool_pins_changed:
        ctx.console.print(
            Text(
                "Закреплённые версии инструментов изменились: osint tools status, затем "
                "osint tools install <имя> для отмеченных.",
                style="yellow",
            )
        )
    return EXIT_OK


def _render_update(ctx: AppContext, checkout: Any, info: Any) -> None:
    from osint_toolkit.update import display_url

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="grey62")
    grid.add_column()
    grid.add_row("Каталог", str(checkout.root))
    grid.add_row(
        "Источник",
        f"{display_url(checkout.remote_url)} ({checkout.remote}/{checkout.remote_branch})",
    )
    grid.add_row("Установлено", f"{info.current_version} ({info.current[:12]})")
    grid.add_row(
        "Доступно",
        f"{info.target_version} ({info.target[:12]})"
        + (f", новых коммитов: {info.behind}" if info.behind else ""),
    )
    ctx.console.print(grid)
    if info.changelog:
        ctx.console.print(Text("Что нового (CHANGELOG.md):", style="bold"))
        for line in info.changelog[:60]:
            ctx.console.print(Text("  " + line))
    if info.commits:
        table = Table(box=box.SIMPLE, title="Коммиты", title_justify="left")
        for col in ("Дата", "Коммит", "Описание"):
            table.add_column(col)
        for commit in info.commits[:30]:
            table.add_row(commit.date, commit.sha[:9], Text(commit.subject))
        ctx.console.print(table)
        if len(info.commits) > 30:
            ctx.console.print(Text(f"  … и ещё {len(info.commits) - 30}", style="grey62"))
    if info.changes:
        shown = ", ".join(info.changes[:40])
        more = f" … и ещё {len(info.changes) - 40}" if len(info.changes) > 40 else ""
        ctx.console.print(Text(f"Изменённые файлы ({len(info.changes)}): {shown}{more}"))
    if info.deps_changed:
        ctx.console.print(Text("Изменятся зависимости (uv.lock).", "yellow"))
    if info.available and info.downgrade:
        ctx.console.print(
            Text(
                f"Внимание: версия в источнике ({info.target_version}) ниже установленной "
                f"({info.current_version}). Установка вернёт более старую версию.",
                style="bold yellow",
            )
        )


def _render_tool_pins(ctx: AppContext, info: Any) -> None:
    from osint_toolkit.tools import TOOLS, tool_status

    for spec in TOOLS.values():
        st = tool_status(ctx.settings, spec)
        if st.path.exists() and st.outdated:
            ctx.console.print(
                Text(
                    f"{spec.name}: установлена {st.version}, закреплена {spec.version} — "
                    f"osint tools install {spec.name}",
                    style="yellow",
                )
            )
    if info.tool_pins_changed:
        ctx.console.print(
            Text("В обновлении меняются закреплённые версии инструментов.", style="yellow")
        )


def _dbip_check(ctx: AppContext, assume_yes: bool) -> None:
    from osint_toolkit.data import dbip
    from osint_toolkit.net import HttpClient, NetworkError

    kinds = [
        kind
        for kind in dbip.DbipKind
        if dbip.status(ctx.settings.geo_dir, kind).present
        or kind in (dbip.DbipKind.COUNTRY, dbip.DbipKind.ASN)
    ]
    urls = [dbip.file_url(k, v) for k in kinds for v in dbip.candidate_versions()]
    if not _consent(
        ctx,
        assume_yes,
        module="data.dbip",
        title="Проверка новых выпусков DB-IP Lite",
        host="download.db-ip.com",
        url=dbip.BASE_URL,
        data_sent="HEAD-запросы к файлам баз; сервер видит ваш IP-адрес",
        details=tuple(f"HEAD {u}" for u in urls),
    ):
        return

    async def check() -> list[tuple[Any, Any]]:
        http = HttpClient(ctx.settings)
        try:
            return [(k, await dbip.find_remote(http, k)) for k in kinds]
        finally:
            await http.aclose()

    try:
        found = asyncio.run(check())
    except NetworkError as exc:
        ctx.err.print(Text(f"DB-IP: {exc}", style="red"))
        return
    stale = []
    for kind, remote in found:
        st = dbip.status(ctx.settings.geo_dir, kind)
        state = "актуальна" if st.version == remote.version else f"доступна {remote.version}"
        ctx.console.print(Text(f"DB-IP {kind.value}: {st.version or 'не установлена'} — {state}"))
        if st.version != remote.version:
            stale.append(kind)
    if stale:
        city = " --city" if dbip.DbipKind.CITY in stale else ""
        ctx.console.print(Text(f"Обновить базы: osint data update{city}", style="yellow"))


def _update_rollback(ctx: AppContext, args: argparse.Namespace, checkout: Any) -> int:
    from osint_toolkit import update as upd

    state = upd.load_state(ctx.settings)
    if not state or state.get("status") != "applied":
        ctx.err.print(Text("Нет применённого обновления для отката.", style="yellow"))
        return EXIT_ERROR
    ctx.console.print(
        Text(
            f"Будет восстановлена версия {state.get('previous_version')} "
            f"({str(state.get('previous'))[:12]}) вместо {state.get('target_version')} "
            f"({str(state.get('target'))[:12]}), установленной {state.get('applied_at')}. "
            "Зависимости берутся из кэша uv; данные пользователя не меняются."
        )
    )
    try:
        upd.check_environment(checkout)
    except upd.UpdateError as exc:
        ctx.err.print(Text(str(exc), style="red"))
        return EXIT_ERROR
    if not args.yes and not ctx.interactive:
        ctx.err.print(Text("Нужно подтверждение: добавьте --yes", style="yellow"))
        return EXIT_USAGE
    if not args.yes and not Confirm.ask("Откатить?", default=False):
        return EXIT_OK
    try:
        with ctx.console.status("Откат…"):
            result = upd.rollback(checkout, ctx.settings)
    except upd.UpdateError as exc:
        ctx.err.print(Text(f"Откат не выполнен: {exc}", style="red"))
        return EXIT_ERROR
    ctx.console.print(
        Text(f"✓ Восстановлена версия {result.current[:12]} (проверка: {result.check})", "green")
    )
    return EXIT_OK


def cmd_config(ctx: AppContext, args: argparse.Namespace) -> int:
    action = args.action or "show"
    if action == "init":
        path, created = init_env_file()
        msg = f"Создан {path} (права 600)" if created else f"Уже существует: {path}"
        ctx.console.print(Text(msg, style="green" if created else "yellow"))
        return EXIT_OK
    if action == "path":
        s = ctx.settings
        table = Table(box=box.SIMPLE)
        table.add_column("Что")
        table.add_column("Путь")
        for label, path in (
            ("Настройки (.env)", default_env_file()),
            ("История", s.db_path),
            ("Логи", s.log_dir),
            ("Отчёты", s.effective_reports_dir),
        ):
            table.add_row(label, str(path))
        ctx.console.print(table)
        return EXIT_OK
    table = Table(box=box.ROUNDED, title="Настройки")
    table.add_column("Параметр")
    table.add_column("Значение")
    for key, value in ctx.settings.masked().items():
        table.add_row(f"OSINT_{key.upper()}", Text(value))
    ctx.console.print(table)
    return EXIT_OK


def cmd_tui(ctx: AppContext, args: argparse.Namespace) -> int:
    if not ctx.interactive:
        ctx.err.print(
            Text(
                "Интерфейс требует интерактивного терминала. Используйте команды "
                "CLI, например: osint run <запрос>",
                style="yellow",
            )
        )
        return EXIT_USAGE
    from osint_toolkit.tui import run_tui

    return run_tui(ctx.settings)


def cmd_home(ctx: AppContext, parser: argparse.ArgumentParser) -> int:
    if ctx.interactive:
        return cmd_tui(ctx, argparse.Namespace())
    ctx.console.print(Text(f"Personal OSINT Toolkit {__version__}", style="bold bright_blue"))
    ctx.console.print(
        Text("Без аргументов в терминале открывается интерфейс (TUI). Команды:", style="grey62")
    )
    parser.print_help()
    return EXIT_OK


# --------------------------------------------------------------------------- main
COMMANDS = {
    "run": cmd_run,
    "tui": cmd_tui,
    "detect": cmd_detect,
    "modules": cmd_modules,
    "history": cmd_history,
    "consent": cmd_consent,
    "report": cmd_report,
    "data": cmd_data,
    "tools": cmd_tools,
    "config": cmd_config,
    "update": cmd_update,
    "plugins": cmd_plugins,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console, err = Console(), Console(stderr=True)
    try:
        settings = load_settings()
    except ValidationError as exc:
        if args.command != "update":
            err.print(Text(f"Ошибка в настройках ({default_env_file()}):\n{exc}", style="red"))
            return EXIT_USAGE
        # Updating must stay possible when .env already holds values of a newer version.
        settings, invalid = load_settings_lenient()
        err.print(
            Text(
                "Эта версия не принимает настройки "
                + ", ".join(f"OSINT_{name.upper()}" for name in invalid)
                + f" из {default_env_file()}: для обновления взяты значения по умолчанию. "
                "Новая версия прочитает их как обычно.",
                style="yellow",
            )
        )
    if default_env_file().exists():
        from osint_toolkit.config import warn_if_insecure

        if warn_if_insecure(default_env_file()):
            err.print(
                Text(
                    f"Внимание: {default_env_file()} доступен другим пользователям. "
                    f"Выполните: chmod 600 {default_env_file()}",
                    style="yellow",
                )
            )
    setup_logging(settings, console_level=logging.INFO if args.verbose else None)
    ctx = AppContext(settings, console, err)
    if args.command is None:
        return cmd_home(ctx, parser)
    try:
        return COMMANDS[args.command](ctx, args)
    except KeyboardInterrupt:
        err.print(Text("Прервано.", style="magenta"))
        return EXIT_CANCELLED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

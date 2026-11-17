"""Rich rendering for the command-line interface.

All externally sourced strings are wrapped in :class:`rich.text.Text`, never interpolated into
markup, so data such as ``[link=...]`` found on a web page cannot alter terminal output.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from osint_toolkit.core.models import (
    Confidence,
    ExternalRequest,
    Finding,
    Investigation,
    InvestigationStatus,
    JsonValue,
    ModuleStatus,
    Target,
)
from osint_toolkit.core.privacy import ConsentAnswer, request_key
from osint_toolkit.reports.seen import SeenRow, consent_banner, where_seen

STATUS_STYLE: dict[ModuleStatus, str] = {
    ModuleStatus.OK: "bold green",
    ModuleStatus.NO_RESULTS: "grey62",
    ModuleStatus.NOT_CONFIGURED: "yellow",
    ModuleStatus.SKIPPED: "cyan",
    ModuleStatus.TIMEOUT: "dark_orange",
    ModuleStatus.ERROR: "bold red",
    ModuleStatus.CANCELLED: "magenta",
}
CONFIDENCE_STYLE: dict[Confidence, str] = {
    Confidence.CONFIRMED: "green",
    Confidence.LIKELY: "yellow",
    Confidence.UNVERIFIED: "grey62",
}


def status_text(status: ModuleStatus) -> Text:
    return Text(status.label, style=STATUS_STYLE[status])


def format_value(value: JsonValue, *, limit: int = 400) -> str:
    if isinstance(value, list):
        text = "\n".join(format_value(v, limit=limit) for v in value)
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, indent=1)
    elif value is None:
        text = "—"
    else:
        text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_targets(candidates: Sequence[Target]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, title="Варианты интерпретации", title_justify="left")
    table.add_column("#", justify="right", style="bold")
    table.add_column("Тип")
    table.add_column("Нормализовано")
    table.add_column("Детали", style="grey62")
    for i, target in enumerate(candidates, 1):
        details = ", ".join(f"{k}={v}" for k, v in target.details.items())
        table.add_row(str(i), target.type.label, Text(target.normalized), Text(details))
    return table


def render_investigation(inv: Investigation) -> RenderableType:
    parts: list[RenderableType] = [_header(inv)]
    banner = consent_banner(inv)
    if banner:
        parts.append(Panel(Text(banner), title="⚠ Поиск не выполнялся", border_style="yellow"))
    parts.append(_modules_table(inv))
    seen = where_seen(inv)
    if seen:
        parts.append(_seen_table(seen))
    seen_ids = {row.finding.id for row in seen}
    for confidence in Confidence:
        findings = [f for f in inv.findings(confidence) if f.id not in seen_ids]
        if findings:
            parts.append(_findings_table(confidence, findings))
    if not inv.findings():
        parts.append(Text("Находок нет.", style="grey62"))
    helpers = inv.helper_findings()
    if helpers:
        parts.append(_helpers_table(helpers))
    if inv.contradictions:
        lines = Text()
        for c in inv.contradictions:
            lines.append("• ", style="bold red")
            lines.append(c.description + "\n")
        parts.append(Panel(lines, title="Противоречия между источниками", border_style="red"))
    notes = _limitations(inv)
    if notes:
        parts.append(Panel(notes, title="Ошибки и ограничения", border_style="yellow"))
    return Group(*parts)


def _header(inv: Investigation) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="grey62")
    grid.add_column()
    grid.add_row("Запрос", Text(inv.query))
    grid.add_row("Цель", Text(str(inv.target)))
    if inv.related_targets:
        grid.add_row("Связанные", Text(", ".join(str(t) for t in inv.related_targets)))
    mode = "Full Investigation" if inv.mode.value == "full" else "Выборочные модули"
    grid.add_row("Режим", mode + (" · офлайн" if inv.offline else ""))
    grid.add_row("Начато", inv.created_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))
    status = (
        Text("Завершено", style="green")
        if inv.status is InvestigationStatus.COMPLETED
        else Text("Прервано пользователем", style="magenta")
    )
    grid.add_row("Статус", status)
    grid.add_row("ID", Text(inv.id, style="grey62"))
    return Panel(grid, title="Исследование", border_style="bright_blue", expand=False)


def _modules_table(inv: Investigation) -> Table:
    table = Table(box=box.ROUNDED, title="Модули", title_justify="left", expand=True)
    table.add_column("Модуль")
    table.add_column("Цель", overflow="fold")
    table.add_column("Статус")
    table.add_column("Находок", justify="right")
    table.add_column("Время", justify="right")
    table.add_column("Примечание", overflow="fold", style="grey62")
    for r in inv.results:
        duration = f"{r.duration_s:.2f} с" if r.duration_s is not None else "—"
        note = "; ".join(r.errors)
        table.add_row(
            Text(r.module_title + "\n") + Text(r.module, style="grey50"),
            Text(r.target.normalized),
            status_text(r.status),
            str(len(r.findings)),
            duration,
            Text(note),
        )
    return table


def _findings_table(confidence: Confidence, findings: Sequence[Finding]) -> Table:
    style = CONFIDENCE_STYLE[confidence]
    table = Table(
        box=box.ROUNDED,
        title=Text(f"{confidence.label} ({len(findings)})", style=f"bold {style}"),
        title_justify="left",
        border_style=style,
        expand=True,
    )
    table.add_column("Объект", overflow="fold")
    table.add_column("Атрибут")
    table.add_column("Значение", overflow="fold")
    table.add_column("Источник", overflow="fold")
    table.add_column("Что подтверждает", overflow="fold", style="grey70")
    table.add_column("Время (UTC)", style="grey50")
    for f in findings:
        source = Text(f.source_name + "\n") + Text(f.source_url, style="underline grey50")
        table.add_row(
            Text(f.subject),
            Text(f.attribute),
            Text(format_value(f.value)),
            source,
            Text(f.evidence),
            f.observed_at.strftime("%H:%M:%S"),
        )
    return table


def _seen_table(rows: Sequence[SeenRow]) -> Table:
    confirmed = sum(1 for r in rows if r.confirmed)
    table = Table(
        box=box.ROUNDED,
        title=f"Где замечен идентификатор — {len(rows)} страниц, подтверждено на {confirmed}",
        title_justify="left",
        expand=True,
    )
    table.add_column("Тип", style="cyan", max_width=14)
    table.add_column("Ресурс / ссылка", overflow="fold", ratio=2)
    table.add_column("Фрагмент", overflow="fold", ratio=3)
    table.add_column("Проверка", max_width=18)
    for r in rows:
        kind = Text(r.kind_label)
        if r.doc_type:
            kind.append(f"\n{r.doc_type.upper()} {r.location}", style="grey62")
        status = Text(r.status_label, style="green" if r.confirmed else "grey62")
        table.add_row(
            kind,
            Text(r.platform + "\n", style="bold") + Text(r.url, style="underline grey50"),
            Text(r.fragment[:300]),
            status,
        )
    return table


def _helpers_table(helpers: Sequence[Finding]) -> Table:
    table = Table(box=box.SIMPLE, title="Дорки (не находки): выполненные — с числом результатов, "
                  "ссылку можно открыть в браузере", title_justify="left", expand=True)  # fmt: skip
    table.add_column("Группа", style="cyan")
    table.add_column("Запрос / ссылка", overflow="fold")
    table.add_column("Найдено", justify="right")
    for f in helpers:
        v = f.value
        if isinstance(v, dict) and "query" in v:
            table.add_row(
                Text(str(v.get("group", ""))),
                Text(str(v["query"]) + "\n")
                + Text(str(v.get("google", "")), style="underline grey50"),
                str(v.get("hits", "—")),
            )
        else:
            table.add_row(Text("Варианты"), Text(format_value(v)), "")
    return table


def _limitations(inv: Investigation) -> Text:
    text = Text()
    seen: set[str] = set()
    for warning in inv.warnings:
        text.append(f"• {warning}\n", style="red")
    for r in inv.results:
        for item in r.limitations:
            key = f"{r.module}:{item}"
            if key not in seen:
                seen.add(key)
                text.append(f"• [{r.module}] ", style="grey62")
                text.append(item + "\n")
    text.rstrip()
    return text


# --------------------------------------------------------------------------- consent prompt
class RichConsent:
    """Interactive consent in the terminal. Non-interactive sessions deny everything."""

    def __init__(self, console: Console, *, interactive: bool) -> None:
        self.console = console
        self.interactive = interactive

    async def ask(self, requests: Sequence[ExternalRequest]) -> Mapping[str, ConsentAnswer]:
        if not self.interactive:
            self.console.print(
                Text(
                    "Внешние запросы пропущены: сессия неинтерактивна. "
                    "Разрешите модули явно: --allow <модуль>",
                    style="yellow",
                )
            )
            return {}
        answers: dict[str, ConsentAnswer] = {}
        self.console.print(
            Panel(
                Text(
                    "Следующие модули хотят отправить данные внешним сервисам. Эти сервисы "
                    "увидят ваш запрос. Ответ: y — да, n — нет, a — всегда для модуля, "
                    "d — никогда для модуля."
                ),
                title="Согласие на внешние запросы",
                border_style="yellow",
            )
        )
        for request in requests:
            table = Table.grid(padding=(0, 2))
            table.add_column(style="grey62")
            table.add_column()
            table.add_row("Модуль", Text(f"{request.module_title} ({request.module})"))
            table.add_row("Цель", Text(str(request.target)))
            for svc in request.services:
                table.add_row("Сервис", Text(f"{svc.name} — {svc.url}"))
                table.add_row("Данные", Text(svc.data_sent))
            for line in request.details:
                table.add_row("Будет отправлено", Text(line, style="bold"))
            self.console.print(table)
            choice = Prompt.ask("Разрешить?", choices=["y", "n", "a", "d"], default="n")
            answers[request_key(request)] = ConsentAnswer(
                allowed=choice in ("y", "a"), remember=choice in ("a", "d")
            )
        return answers

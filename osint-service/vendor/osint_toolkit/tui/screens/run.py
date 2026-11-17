"""Run screen: live module progress for one investigation (implements ProgressListener)."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, ProgressBar, RichLog, Static

from osint_toolkit.core.engine import Engine, Plan, PlanError
from osint_toolkit.core.models import (
    Confidence,
    Investigation,
    InvestigationStatus,
    ModuleResult,
    Target,
    TargetType,
)
from osint_toolkit.modules.base import BaseModule
from osint_toolkit.reports import PdfOptions, generate_reports, parse_formats
from osint_toolkit.tui.screens.consent import TuiConsent
from osint_toolkit.tui.widgets import SPINNER, ConfirmModal, status_cell

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp

log = logging.getLogger(__name__)


def short_target(target: Target) -> str:
    if target.type is TargetType.IMAGE:
        return str(target.details.get("file_name") or Path(target.normalized).name)
    return target.normalized


class _ScreenListener:
    """Adapter: engine ProgressListener callbacks → RunScreen updates."""

    def __init__(self, screen: RunScreen) -> None:
        self.screen = screen

    def on_planned(self, plan: Plan) -> None:
        self.screen.show_plan(plan)

    def on_module_started(self, module: BaseModule, target: Target) -> None:
        self.screen.module_started(module, target)

    def on_module_finished(self, result: ModuleResult) -> None:
        self.screen.module_finished(result)

    def on_module_progress(
        self, module: BaseModule, target: Target, done: int, total: int | None, text: str
    ) -> None:
        self.screen.module_progress(module, target, done, total, text)


class ModuleProgress(Horizontal):
    """One live bar: «Maigret: Проверено 1500 из 5900 сайтов  ━━━━━━━━  25%»."""

    def __init__(self, title: str, *, id: str | None = None) -> None:
        super().__init__(classes="mod-progress", id=id)
        self.caption = title

    def compose(self) -> ComposeResult:
        yield Label(Text(self.caption, style="bold"))
        yield ProgressBar(total=None, show_eta=True)

    def set(self, done: int, total: int | None, text: str) -> None:
        self.query_one(Label).update(
            Text.assemble((self.caption, "bold cyan"), ("  ", ""), (text, ""))
        )
        bar = self.query_one(ProgressBar)
        if total:
            bar.update(total=total, progress=min(done, total))

    def finish(self, text: str) -> None:
        bar = self.query_one(ProgressBar)
        if bar.total:
            bar.update(progress=bar.total)
        else:
            bar.update(total=1, progress=1)
        self.query_one(Label).update(
            Text.assemble((self.caption, "bold green"), ("  ", ""), (text, "green"))
        )


class RunScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "stop_or_back", "Отменить / назад"),
        Binding("ctrl+r", "results", "Результаты"),
    ]

    def __init__(
        self,
        target: Target,
        *,
        query: str,
        modules: list[str] | None = None,
        offline: bool = False,
        save_reports: bool = True,
    ) -> None:
        super().__init__()
        self.target, self.query_text, self.modules = target, query or target.raw, modules
        self.offline, self.save_reports = offline, save_reports
        self.engine: Engine | None = None
        self.investigation: Investigation | None = None
        self.report_paths: list[Path] = []
        self.running = False
        self.started = time.monotonic()
        self.finished_at: float | None = None
        self._active: set[str] = set()
        self._frame = 0
        self._bars: dict[str, ModuleProgress] = {}

    @property
    def osint(self) -> OsintApp:
        return cast("OsintApp", self.app)

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="run"):
            yield Static(self._title("Подготовка…"), id="run-title")
            with Horizontal(id="run-stats"):
                yield ProgressBar(total=None, show_eta=False, id="progress")
                yield Label("0.0 с", id="elapsed")
            yield Vertical(id="module-progress")
            yield DataTable(id="run-table", cursor_type="row", zebra_stripes=True)
            yield RichLog(id="run-log", wrap=True, markup=False, max_lines=500)
            with Horizontal(id="run-actions"):
                yield Button("Открыть результаты", id="results", variant="success", disabled=True)
                yield Button("Отменить", id="cancel", variant="error")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for key, label in (
            ("status", "Статус"),
            ("module", "Модуль"),
            ("target", "Цель"),
            ("findings", "Находок"),
            ("time", "Время"),
            ("note", "Примечание"),
        ):
            table.add_column(label, key=key)
        self.set_interval(0.1, self._tick)
        self.investigate()

    def _title(self, phase: str) -> Text:
        mode = "Full Investigation" if self.modules is None else "Выбранные модули"
        text = Text.assemble((f"{self.target.type.label}: ", "dim"),
                             (short_target(self.target), "bold"),
                             (f"   {mode}", "dim"))  # fmt: skip
        if self.offline:
            text.append("  · офлайн", style="yellow")
        text.append(f"\n{phase}")
        return text

    def log_line(self, message: str, style: str = "") -> None:
        stamp = time.strftime("%H:%M:%S")
        self.query_one(RichLog).write(Text.assemble((f"{stamp}  ", "dim"), (message, style)))

    # ------------------------------------------------------------------ progress updates
    def show_plan(self, plan: Plan) -> None:
        table = self.query_one(DataTable)
        if table.row_count:
            return
        for run in plan.runs:
            module = Text(run.module.title)
            if run.module.is_external:
                module.append("  🌐", style="yellow")
            table.add_row(
                Text("… ожидает", style="dim"),
                module,
                Text(short_target(run.target)),
                "",
                "",
                "",
                key=run.key,
            )
        self.query_one(ProgressBar).update(total=len(plan.runs), progress=0)

    def module_started(self, module: BaseModule, target: Target) -> None:
        key = f"{module.name}@{target.key}"
        self._active.add(key)
        self.log_line(f"▶ {module.title} → {short_target(target)}")

    def module_progress(
        self, module: BaseModule, target: Target, done: int, total: int | None, text: str
    ) -> None:
        """Live progress of a long module (Maigret sites, pages being checked…)."""
        key = f"{module.name}@{target.key}"
        if key not in self._active:
            return
        bar = self._bars.get(key)
        if bar is None:
            title = module.title.split(" (")[0] if len(module.title) > 40 else module.title
            bar = self._bars[key] = ModuleProgress(
                f"{title} → {short_target(target)}", id=f"mp-{len(self._bars)}"
            )
            self.query_one("#module-progress", Vertical).mount(bar)
            bar.call_after_refresh(bar.set, done, total, text)
            return
        bar.set(done, total, text)

    def _drop_bar(self, key: str) -> None:
        bar = self._bars.pop(key, None)
        if bar is not None:
            bar.remove()

    def module_finished(self, result: ModuleResult) -> None:
        key = f"{result.module}@{result.target.key}"
        self._active.discard(key)
        bar = self._bars.get(key)
        if bar is not None and bar.is_mounted:
            bar.finish(f"{status_cell(result.status).plain} — 100%")
            self.set_timer(4, lambda: self._drop_bar(key))
        table = self.query_one(DataTable)
        if key not in table.rows:
            return
        duration = f"{result.duration_s:.2f} с" if result.duration_s is not None else "—"
        note = "; ".join(result.errors)
        table.update_cell(key, "status", status_cell(result.status), update_width=True)
        table.update_cell(key, "findings", str(len(result.findings)), update_width=True)
        table.update_cell(key, "time", duration, update_width=True)
        table.update_cell(
            key, "note", Text(note[:90] + ("…" if len(note) > 90 else "")), update_width=True
        )
        self.query_one(ProgressBar).advance(1)
        style = {"ok": "green", "error": "red", "timeout": "dark_orange"}.get(
            result.status.value, ""
        )
        self.log_line(
            f"{status_cell(result.status).plain} — {result.module_title}"
            + (f": {note}" if note else ""),
            style,
        )

    def _tick(self) -> None:
        end = self.finished_at or time.monotonic()
        self.query_one("#elapsed", Label).update(f"{end - self.started:.1f} с")
        if not self._active:
            return
        self._frame = (self._frame + 1) % len(SPINNER)
        table = self.query_one(DataTable)
        for key in list(self._active):
            if key in table.rows:
                table.update_cell(
                    key, "status", Text(f"{SPINNER[self._frame]} выполняется", style="bold cyan")
                )

    # ------------------------------------------------------------------ worker
    @work(exclusive=True, exit_on_error=False, group="investigation")
    async def investigate(self) -> None:
        self.running = True
        app = self.osint
        settings = app.settings.model_copy(update={"offline": self.offline})
        try:
            self.engine = app.make_engine(TuiConsent(app), _ScreenListener(self), settings)
            try:
                plan = (
                    self.engine.plan_targeted(self.target, self.modules, query=self.query_text)
                    if self.modules
                    else self.engine.plan_full(self.target, self.query_text)
                )
            except PlanError as exc:
                self._fail(str(exc))
                return
            self.show_plan(plan)
            if plan.external_requests(settings) and not self.offline:
                self._phase("Ожидание вашего решения о внешних запросах…")
            decisions = await self.engine.authorize(plan)
            allowed = sum(1 for d in decisions.values() if d.allowed)
            if decisions:
                self.log_line(f"Внешних запросов разрешено: {allowed} из {len(decisions)}")
            self._phase("Выполнение модулей…")
            self.investigation = await self.engine.execute(plan, decisions)
            if self.save_reports:
                await self._write_reports(self.investigation)
            self._done(self.investigation)
        except Exception as exc:
            log.exception("TUI investigation failed")
            self._fail(f"{type(exc).__name__}: {exc}")
        finally:
            self.running = False
            self._active.clear()

    async def _write_reports(self, inv: Investigation) -> None:
        settings = self.osint.settings
        formats = parse_formats(settings.report_formats) or parse_formats("all")
        try:
            self.report_paths = await asyncio.to_thread(
                generate_reports,
                inv,
                formats,
                settings.effective_reports_dir,
                pdf=PdfOptions.from_settings(settings),
            )
        except OSError as exc:
            self.notify(f"Не удалось сохранить отчёты: {exc}", severity="error", timeout=8)
            return
        self.log_line(f"Отчёты сохранены: {settings.effective_reports_dir}", "green")

    def _phase(self, text: str) -> None:
        self.query_one("#run-title", Static).update(self._title(text))

    def _done(self, inv: Investigation) -> None:
        self.finished_at = time.monotonic()
        counts = {c: len(inv.findings(c)) for c in Confidence}
        summary = (
            f"находок {sum(counts.values())}: подтверждено {counts[Confidence.CONFIRMED]}, "
            f"вероятно {counts[Confidence.LIKELY]}, не проверено "
            f"{counts[Confidence.UNVERIFIED]}; противоречий {len(inv.contradictions)}"
        )
        cancelled = inv.status is InvestigationStatus.CANCELLED
        head = "■ Прервано — частичные результаты" if cancelled else "✔ Готово"
        self._phase(f"{head}: {summary}")
        self.log_line(f"{head}: {summary}", "magenta" if cancelled else "bold green")
        for warning in inv.warnings:
            self.log_line(f"⚠ {warning}", "red")
        results = self.query_one("#results", Button)
        results.disabled = False
        results.focus()
        cancel = self.query_one("#cancel", Button)
        cancel.label = "Назад"
        cancel.variant = "default"
        self.notify(summary, title=head, severity="warning" if cancelled else "information")

    def _fail(self, message: str) -> None:
        self.finished_at = time.monotonic()
        self._phase(f"✖ Ошибка: {message}")
        self.log_line(f"✖ {message}", "bold red")
        self.notify(message, title="Ошибка", severity="error", timeout=10)
        cancel = self.query_one("#cancel", Button)
        cancel.label = "Назад"
        cancel.variant = "default"

    # ------------------------------------------------------------------ actions
    @on(Button.Pressed, "#results")
    def results_pressed(self) -> None:
        self.action_results()

    @on(Button.Pressed, "#cancel")
    def cancel_pressed(self) -> None:
        self.action_stop_or_back()

    def action_results(self) -> None:
        if self.investigation is None:
            return
        from osint_toolkit.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(self.investigation, self.report_paths))

    def action_stop_or_back(self) -> None:
        if not self.running:
            self.app.pop_screen()
            return

        def answer(confirmed: bool | None) -> None:
            if confirmed and self.engine is not None and self.running:
                self.engine.cancel()
                self._phase("Отмена… ожидание остановки модулей")
                self.log_line("Отмена по запросу пользователя", "magenta")

        self.app.push_screen(
            ConfirmModal(
                "Прервать исследование?",
                "Завершённые модули сохранят результаты, остальные будут помечены как отменённые.",
                yes="Прервать",
                no="Продолжить",
                danger=True,
            ),
            answer,
        )

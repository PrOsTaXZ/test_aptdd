"""Results screen: findings by confidence (never mixed), modules, contradictions, limitations."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast
from urllib.parse import urlsplit

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)
from textual.widgets.option_list import Option
from textual.widgets.selection_list import Selection

from osint_toolkit.analysis.dossier import (
    DOSSIER_NOTE,
    SECTIONS,
    DossierItem,
    build_dossier,
    data_types_present,
)
from osint_toolkit.analysis.entities import ENTITY_LABELS, EntityType
from osint_toolkit.console import CONFIDENCE_STYLE
from osint_toolkit.core.models import (
    Confidence,
    Finding,
    Investigation,
    InvestigationStatus,
    ModuleResult,
    ModuleStatus,
)
from osint_toolkit.reports import PdfOptions, ReportFormat, generate_reports
from osint_toolkit.reports.preview import open_in_viewer, render_preview
from osint_toolkit.reports.seen import SeenRow, consent_banner, documents, social, where_seen
from osint_toolkit.reports.view import CONFIDENCE_HELP, DISCLAIMER, is_web_url, links_in
from osint_toolkit.tui.widgets import ClickTable, InfoModal, short, status_cell

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp


def _matches(finding: Finding, needle: str) -> bool:
    if not needle:
        return True
    haystack = " ".join(
        [
            finding.subject,
            finding.attribute,
            json.dumps(finding.value, ensure_ascii=False),
            finding.source_name,
            finding.evidence,
        ]
    ).casefold()
    return all(part in haystack for part in needle.casefold().split())


def _row_matches(row: SeenRow, needle: str, kind: str) -> bool:
    types = row.entity_types
    if kind == "mixed" and len(types) < 2:
        return False
    if kind == "none" and types:
        return False
    if kind not in ("all", "mixed", "none") and EntityType(kind) not in types:
        return False
    if not needle:
        return True
    haystack = " ".join(
        [row.platform, row.url, row.title, row.fragment, row.kind_label, row.data_type]
        + [e.value for e in row.entities]
    ).casefold()
    return all(part in haystack for part in needle.casefold().split())


class ResultsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "back", "Назад"),
        Binding("slash", "focus_filter", "Фильтр"),
        Binding("e", "export", "Экспорт"),
        Binding("v", "view_report", "Просмотр отчёта"),
        Binding("c", "copy_value", "Копировать значение"),
    ]

    def __init__(
        self, investigation: Investigation, report_paths: list[Path] | None = None
    ) -> None:
        super().__init__()
        self.inv = investigation
        self.report_paths = list(report_paths or [])
        self.findings: dict[str, Finding] = {f.id: f for f in investigation.findings()}
        self.helpers: dict[str, Finding] = {f.id: f for f in investigation.helper_findings()}
        self.seen = where_seen(investigation)
        self.seen_ids = {row.finding.id for row in self.seen}
        self.banner = consent_banner(investigation)
        self.dossier = build_dossier(investigation, self.seen)
        self.dossier_items: dict[str, DossierItem] = {
            f"dos:{item.key}": item for item in self.dossier.items()
        }
        self.type_filter: dict[str, str] = {}
        self.results: dict[str, ModuleResult] = {
            f"{r.module}@{r.target.key}": r for r in investigation.results
        }

    @property
    def osint(self) -> OsintApp:
        return cast("OsintApp", self.app)

    def compose(self) -> ComposeResult:
        inv = self.inv
        yield Header()
        with Vertical(id="results"):
            yield Static(self._summary(), id="summary")
            if self.banner:
                yield Static(Text("⚠ " + self.banner, style="bold yellow"), id="consent-banner")
            with Horizontal(id="cards"):
                for confidence in Confidence:
                    card = Static(
                        self._card(
                            len(inv.findings(confidence)),
                            confidence.label,
                            CONFIDENCE_STYLE[confidence],
                        ),
                        classes="card",
                    )
                    yield card
                ok = sum(1 for r in inv.results if r.status is ModuleStatus.OK)
                yield Static(
                    self._card(
                        len(inv.contradictions),
                        "противоречий",
                        "red" if inv.contradictions else "dim",
                    ),
                    classes="card",
                )
                yield Static(
                    self._card(f"{ok}/{len(inv.results)}", "модулей с данными", "cyan"),
                    classes="card",
                )
            with Horizontal(id="result-actions"):
                yield Button(
                    "Просмотр официального отчёта (V)", id="view-report", variant="primary"
                )
                yield Button("Сохранить отчёт… (E)", id="export-report")
                yield Label("", id="report-status")
            yield Input(placeholder="Фильтр по находкам: слова через пробел  ( / )", id="filter")
            with TabbedContent(id="tabs"):
                with (
                    TabPane(f"Досье ({self.dossier.total})", id="pane-dossier"),
                    VerticalScroll(id="dossier"),
                ):
                    yield from self._compose_dossier()
                for pane, title, rows in self._seen_panes():
                    with TabPane(f"{title} ({len(rows)})", id=f"pane-{pane}"):
                        yield Static(
                            Text(
                                "Страницы и документы, где поисковики нашли идентификатор. "
                                "«подтверждено на странице» — он есть в загруженном тексте; "
                                "остальное известно только со слов поисковика. «Тип данных» — "
                                "что распознано на странице (* — только по фрагменту, "
                                "страница целиком не разбиралась). Щелчок или Enter — "
                                "подробности.",
                                style="dim",
                            ),
                            classes="pane-help",
                        )
                        with Horizontal(classes="seen-filter"):
                            yield Label("Тип данных:", classes="seen-filter-label")
                            yield Select(
                                self._type_options(rows),
                                value="all",
                                allow_blank=False,
                                id=f"type-{pane}",
                            )
                        yield ClickTable(id=f"tbl-{pane}", cursor_type="row", zebra_stripes=True)
                for confidence in Confidence:
                    with TabPane(self._tab_label(confidence), id=f"pane-{confidence.value}"):
                        yield Static(
                            Text(CONFIDENCE_HELP[confidence], style="dim"), classes="pane-help"
                        )
                        yield DataTable(
                            id=f"tbl-{confidence.value}", cursor_type="row", zebra_stripes=True
                        )
                if self.helpers:
                    queries = sum(
                        1
                        for f in self.helpers.values()
                        if isinstance(f.value, dict) and "query" in f.value
                    )
                    with TabPane(f"Дорки ({queries})", id="pane-dorks"):
                        yield Static(
                            Text(
                                "Дорки — не находки: выполненные показаны с числом результатов "
                                "(пустые скрыты). Enter — открыть запрос в Google, Яндексе "
                                "или Bing (по вашему выбору).",
                                style="dim",
                            ),
                            classes="pane-help",
                        )
                        yield DataTable(id="tbl-dorks", cursor_type="row", zebra_stripes=True)
                with TabPane(f"Модули ({len(inv.results)})", id="pane-modules"):
                    yield DataTable(id="tbl-modules", cursor_type="row", zebra_stripes=True)
                with (
                    TabPane(f"Противоречия ({len(inv.contradictions)})", id="pane-contra"),
                    VerticalScroll(),
                ):
                    yield Static(self._contradictions(), id="contra")
                with TabPane("Ограничения", id="pane-limits"), VerticalScroll():
                    yield Static(self._limitations(), id="limits")
                with TabPane("Отчёты", id="pane-reports"):
                    yield Static(self._reports_text(), id="reports-list")
        yield Footer()

    def on_mount(self) -> None:
        for confidence in Confidence:
            table = self.query_one(f"#tbl-{confidence.value}", DataTable)
            for key, label in (
                ("subject", "Объект"),
                ("attribute", "Атрибут"),
                ("value", "Значение"),
                ("source", "Источник"),
                ("time", "Время (UTC)"),
            ):
                table.add_column(label, key=key)
        modules = self.query_one("#tbl-modules", DataTable)
        for key, label in (
            ("status", "Статус"),
            ("module", "Модуль"),
            ("target", "Цель"),
            ("findings", "Находок"),
            ("time", "Время"),
            ("note", "Примечание"),
        ):
            modules.add_column(label, key=key)
        for key, r in self.results.items():
            modules.add_row(
                status_cell(r.status),
                Text(r.module_title),
                short(r.target.normalized, 40),
                str(len(r.findings)),
                f"{r.duration_s:.2f} с" if r.duration_s is not None else "—",
                short("; ".join(r.errors), 60),
                key=key,
            )
        if self.helpers:
            dorks = self.query_one("#tbl-dorks", DataTable)
            dorks.add_column("Группа", key="group")
            dorks.add_column("Запрос", key="query")
            dorks.add_column("Найдено", key="hits")
            for key, f in self.helpers.items():
                v = f.value
                if isinstance(v, dict) and "query" in v:
                    dorks.add_row(
                        Text(str(v.get("group", ""))),
                        short(str(v["query"]), 100),
                        str(v.get("hits", "—")),
                        key=key,
                    )
                else:
                    dorks.add_row(
                        Text("Варианты записи", style="bold"), short(f.value, 100), "", key=key
                    )
        for pane, _title, _rows in self._seen_panes():
            table = self.query_one(f"#tbl-{pane}", DataTable)
            for key, label in (
                ("kind", "Тип"),
                ("data", "Тип данных"),
                ("where", "Ресурс / ссылка"),
                ("fragment", "Фрагмент"),
                ("check", "Проверка"),
            ):
                table.add_column(label, key=key)
        self._fill_dossier()
        self._fill()
        first = next(
            (c for c in Confidence if any(f.id not in self.seen_ids for f in self.inv.findings(c))),
            None,
        )
        tabs = self.query_one(TabbedContent)
        if self.dossier.total or self.dossier.documents:
            tabs.active = "pane-dossier"
            focus = next(
                (f"#dos-{n}" for n, _t, _k in SECTIONS if self.dossier.section(n)),
                "#dos-documents",
            )
        elif self.seen:
            tabs.active, focus = "pane-seen", "#tbl-seen"
        else:
            tabs.active = f"pane-{first.value}" if first else "pane-modules"
            focus = f"#tbl-{first.value}" if first else "#tbl-modules"
        cards = self.query_one("#cards")
        cards.styles.opacity = 0.0
        cards.styles.animate("opacity", value=1.0, duration=0.35)
        self.query_one(focus, DataTable).focus()

    def _seen_panes(self) -> list[tuple[str, str, list[SeenRow]]]:
        if not self.seen:
            return []
        panes = [("seen", "Где замечен", self.seen)]
        for pane, title, rows in (
            ("docs", "Документы", documents(self.seen)),
            ("social", "Соцсети", social(self.seen)),
        ):
            if rows:
                panes.append((pane, title, rows))
        return panes

    @staticmethod
    def _type_options(rows: list[SeenRow]) -> list[tuple[str, str]]:
        options = [("Все типы", "all")]
        options += [(ENTITY_LABELS[k], k.value) for k in data_types_present(rows)]
        options += [
            ("Смешанные данные (2+ типа)", "mixed"),
            ("Ничего не распознано", "none"),
        ]
        return options

    def _compose_dossier(self) -> ComposeResult:
        yield Static(
            Text(
                f"Сводка распознанных сущностей по всем страницам, документам и аккаунтам. "
                f"{DOSSIER_NOTE} Щелчок или Enter по строке — полный контекст и источники.",
                style="dim",
            ),
            classes="pane-help",
        )
        for name, title, _kinds in SECTIONS:
            items = self.dossier.section(name)
            yield Label(f"{title} ({len(items)})", classes="section-title")
            if items:
                yield ClickTable(
                    id=f"dos-{name}", cursor_type="row", zebra_stripes=True, classes="dossier-table"
                )
            else:
                yield Static(Text("Не найдено", style="dim italic"), classes="dossier-empty")
        docs = self.dossier.documents
        yield Label(f"Документы ({len(docs)})", classes="section-title")
        if docs:
            yield ClickTable(
                id="dos-documents", cursor_type="row", zebra_stripes=True, classes="dossier-table"
            )
        else:
            yield Static(Text("Не найдено", style="dim italic"), classes="dossier-empty")

    def _fill_dossier(self) -> None:
        for name, _title, kinds in SECTIONS:
            items = self.dossier.section(name)
            if not items:
                continue
            table = self.query_one(f"#dos-{name}", DataTable)
            columns = [("value", "Значение")]
            if len(kinds) > 1 or name == "accounts":
                columns.append(("type", "Тип"))
            columns += [
                ("sources", "Источников"),
                ("status", "Статус"),
                ("where", "Где встретилось"),
            ]
            for key, label in columns:
                table.add_column(label, key=key)
            for item in items:
                value = Text(item.display, style="bold" if item.confirmed else "")
                if item.is_target:
                    value.append("  ◆ искомое", style="cyan")
                cells: list[object] = [value]
                if len(kinds) > 1 or name == "accounts":
                    cells.append(Text(item.platform or item.type.label, style="dim"))
                where = ", ".join(dict.fromkeys(o.title for o in item.occurrences))
                cells += [
                    str(item.sources),
                    Text(item.status_label, style="green" if item.confirmed else "dim"),
                    short(where, 60),
                ]
                table.add_row(*cells, key=f"dos:{item.key}")
        if self.dossier.documents:
            table = self.query_one("#dos-documents", DataTable)
            for key, label in (
                ("doc", "Документ"),
                ("where", "Где найдено"),
                ("data", "Тип данных"),
                ("check", "Проверка"),
            ):
                table.add_column(label, key=key)
            for doc in self.dossier.documents:
                row = doc.row
                title = Text(f"{(row.doc_type or 'DOC').upper()} ", style="bold")
                title.append_text(short(row.title or row.url, 60))
                table.add_row(
                    title,
                    Text(f"{row.platform} {row.location}".strip(), style="dim"),
                    Text(doc.data_type),
                    Text(row.status_label, style="green" if row.confirmed else "dim"),
                    key=row.finding.id,
                )

    def _fill_seen(self, needle: str = "") -> None:
        tabs = self.query_one(TabbedContent)
        for pane, title, rows in self._seen_panes():
            table = self.query_one(f"#tbl-{pane}", DataTable)
            table.clear()
            kind_filter = self.type_filter.get(pane, "all")
            shown = 0
            for row in rows:
                if not _row_matches(row, needle, kind_filter):
                    continue
                shown += 1
                kind = Text(row.kind_label)
                if row.doc_type:
                    kind.append(f" {row.doc_type.upper()} {row.location}", style="dim")
                data = Text(row.data_type, style="bold" if row.entities else "dim")
                if row.entities and row.entities_from != "page":
                    data.append(" *", style="dim")
                table.add_row(
                    kind,
                    data,
                    Text(row.platform, style="bold") + Text(f"  {short(row.url, 60)}", style="dim"),
                    short(row.fragment, 80),
                    Text(row.status_label, style="green" if row.confirmed else "dim"),
                    key=row.finding.id,
                )
            count = f"{shown}/{len(rows)}" if shown != len(rows) else str(len(rows))
            tabs.get_tab(f"pane-{pane}").label = f"{title} ({count})"

    # ------------------------------------------------------------------ rendering
    def _summary(self) -> Text:
        inv = self.inv
        text = Text.assemble(
            ("Запрос  ", "dim"),
            (inv.query, "bold"),
            "\n",
            ("Цель    ", "dim"),
            f"{inv.target.type.label}: {inv.target.normalized}",
        )
        if inv.related_targets:
            text.append("\nСвязанные ", style="dim")
            text.append(", ".join(str(t) for t in inv.related_targets))
        mode = "Full Investigation" if inv.mode.value == "full" else "Выбранные модули"
        status = (
            "прервано (частичные результаты)"
            if inv.status is InvestigationStatus.CANCELLED
            else "завершено"
        )
        text.append(
            f"\nРежим   {mode}{' · офлайн' if inv.offline else ''} · {status} · "
            f"{inv.created_at.astimezone():%Y-%m-%d %H:%M:%S}",
            style="dim",
        )
        text.append(f"\nID      {inv.id}", style="dim")
        text.append(f"\n{DISCLAIMER}", style="italic dim")
        return text

    @staticmethod
    def _card(value: object, label: str, style: str) -> Text:
        return Text.assemble((f"{value}\n", f"bold {style}"), (label, "dim"))

    def _tab_label(self, confidence: Confidence, shown: int | None = None) -> str:
        total = sum(1 for f in self.inv.findings(confidence) if f.id not in self.seen_ids)
        count = f"{shown}/{total}" if shown is not None and shown != total else str(total)
        return f"{confidence.label} ({count})"

    def _fill(self, needle: str = "") -> None:
        self._fill_seen(needle)
        tabs = self.query_one(TabbedContent)
        for confidence in Confidence:
            table = self.query_one(f"#tbl-{confidence.value}", DataTable)
            table.clear()
            shown = 0
            for f in self.inv.findings(confidence):
                if f.id in self.seen_ids or not _matches(f, needle):
                    continue
                shown += 1
                table.add_row(
                    short(f.subject, 32),
                    Text(f.attribute, style="bold"),
                    short(f.value, 60),
                    short(f.source_name, 34),
                    f.observed_at.strftime("%H:%M:%S"),
                    key=f.id,
                )
            tabs.get_tab(f"pane-{confidence.value}").label = self._tab_label(confidence, shown)

    def _contradictions(self) -> Text:
        if not self.inv.contradictions:
            return Text("Противоречий между источниками не обнаружено.", style="dim")
        text = Text()
        for c in self.inv.contradictions:
            text.append(f"● {c.subject} :: {c.attribute}\n", style="bold red")
            for v in c.variants:
                text.append(f"    «{v.value}»", style="bold")
                text.append(
                    f"  — {', '.join(v.sources)} ({v.best_confidence.label.lower()})\n", style="dim"
                )
            text.append(f"  {c.description}\n\n")
        return text

    def _limitations(self) -> Text:
        text = Text()
        for warning in self.inv.warnings:
            text.append(f"⚠ {warning}\n", style="bold red")
        seen: set[tuple[str, str]] = set()
        for r in self.inv.results:
            for error in r.errors:
                text.append(f"✖ [{r.module}] ", style="red")
                text.append(f"{error}\n")
            for item in r.limitations:
                if (r.module, item) not in seen:
                    seen.add((r.module, item))
                    text.append(f"• [{r.module}] ", style="dim")
                    text.append(f"{item}\n")
        return text or Text("Ограничений нет.", style="dim")

    def _reports_text(self) -> Text:
        if not self.report_paths:
            return Text("Отчёты не сохранялись. Нажмите E, чтобы экспортировать.", style="dim")
        text = Text("Сохранённые отчёты:\n", style="bold")
        for path in self.report_paths:
            text.append(f"  {path}\n")
        text.append("\nE — экспортировать заново в другие форматы или каталог.", style="dim")
        return text

    # ------------------------------------------------------------------ interaction
    @on(Input.Changed, "#filter")
    def filter_changed(self, event: Input.Changed) -> None:
        self._fill(event.value.strip())

    @on(Button.Pressed, "#view-report")
    def view_report_pressed(self) -> None:
        self.action_view_report()

    @on(Button.Pressed, "#export-report")
    def export_pressed(self) -> None:
        self.action_export()

    def action_view_report(self) -> None:
        self.view_report()

    @work(exclusive=True, exit_on_error=False, group="preview")
    async def view_report(self) -> None:
        button = self.query_one("#view-report", Button)
        status = self.query_one("#report-status", Label)
        button.disabled = True
        status.update(Text("Формирую официальный отчёт…", style="cyan"))
        try:
            path = await asyncio.to_thread(render_preview, self.inv, self.osint.settings)
        except Exception as exc:  # noqa: BLE001 - shown to the user, the screen stays usable
            status.update("")
            self.notify(f"{type(exc).__name__}: {exc}", title="Отчёт не сформирован",
                        severity="error", timeout=10)  # fmt: skip
            return
        finally:
            button.disabled = False
        if open_in_viewer(path):
            status.update(Text("Отчёт открыт в программе просмотра PDF", style="green"))
            self.notify(
                "Это временная копия для просмотра: в отчёты она не сохраняется. "
                "Чтобы сохранить — «Сохранить отчёт…».",
                title="Официальный отчёт открыт",
            )
        else:
            status.update(Text(f"Отчёт: {path}", style="yellow"))
            self.notify(
                f"Не найдена программа просмотра (xdg-open). Файл: {path}",
                severity="warning",
                timeout=12,
            )

    @on(Select.Changed, ".seen-filter Select")
    def type_filter_changed(self, event: Select.Changed) -> None:
        pane = (event.select.id or "").removeprefix("type-")
        self.type_filter[pane] = str(event.value)
        self._fill_seen(self.query_one("#filter", Input).value.strip())

    @on(DataTable.RowSelected)
    def row_selected(self, event: DataTable.RowSelected) -> None:
        key = event.row_key.value
        if key is None:
            return
        if key in self.dossier_items:
            self.app.push_screen(EntityModal(self.dossier_items[key], self.findings))
        elif key in self.findings:
            self.app.push_screen(FindingModal(self.findings[key]))
        elif key in self.helpers:
            self.app.push_screen(FindingModal(self.helpers[key]))
        elif key in self.results:
            self.app.push_screen(
                InfoModal(
                    f"Модуль {self.results[key].module_title}", _module_details(self.results[key])
                )
            )

    def _current_finding(self) -> Finding | None:
        focused = self.focused
        if isinstance(focused, DataTable) and focused.row_count:
            key = focused.coordinate_to_cell_key(focused.cursor_coordinate).row_key.value
            return self.findings.get(key or "") or self.helpers.get(key or "")
        return None

    def action_copy_value(self) -> None:
        finding = self._current_finding()
        if finding is None:
            return
        value = (
            finding.value
            if isinstance(finding.value, str)
            else json.dumps(finding.value, ensure_ascii=False)
        )
        self.app.copy_to_clipboard(value)
        self.notify("Значение скопировано (если терминал поддерживает OSC 52)")

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_back(self) -> None:
        if self.query_one("#filter", Input).has_focus and self.query_one("#filter", Input).value:
            self.query_one("#filter", Input).value = ""
            return
        self.app.pop_screen()

    def action_export(self) -> None:
        def chosen(result: tuple[list[ReportFormat], Path] | None) -> None:
            if result:
                self.export(*result)

        self.app.push_screen(ExportModal(self.osint.settings.effective_reports_dir), chosen)

    @work(exclusive=True, exit_on_error=False, group="export")
    async def export(self, formats: list[ReportFormat], directory: Path) -> None:
        default = directory == self.osint.settings.effective_reports_dir
        try:
            paths = await asyncio.to_thread(
                generate_reports,
                self.inv,
                formats,
                directory,
                private_dir=default,
                pdf=PdfOptions.from_settings(self.osint.settings),
            )
        except OSError as exc:
            self.notify(f"Не удалось сохранить: {exc}", severity="error", timeout=8)
            return
        self.report_paths.extend(paths)
        self.query_one("#reports-list", Static).update(self._reports_text())
        self.notify("\n".join(p.name for p in paths), title=f"Сохранено в {directory}")


def _module_details(r: ModuleResult) -> Text:
    text = Text.assemble(
        ("Модуль: ", "dim"),
        f"{r.module_title} ({r.module})\n",
        ("Цель: ", "dim"),
        f"{r.target}\n",
        ("Статус: ", "dim"),
    )
    text.append_text(status_cell(r.status))
    text.append(f"\nНаходок: {len(r.findings)}\n")
    if r.external_services:
        text.append("\nВнешние сервисы:\n", style="bold")
        for svc in r.external_services:
            text.append(f"  • {svc.name} ({svc.url}) — {svc.data_sent}\n")
    if r.errors:
        text.append("\nОшибки:\n", style="bold red")
        for error in r.errors:
            text.append(f"  • {error}\n")
    if r.limitations:
        text.append("\nОграничения:\n", style="bold")
        for item in r.limitations:
            text.append(f"  • {item}\n")
    return text


class EntityModal(ModalScreen[None]):
    """Card of one dossier entity: every place it occurred, with context and status."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape,q", "close", "Закрыть"),
        Binding("c", "copy", "Копировать значение"),
    ]

    def __init__(self, item: DossierItem, findings: dict[str, Finding] | None = None) -> None:
        super().__init__()
        self.item = item
        self.findings = findings or {}

    def compose(self) -> ComposeResult:
        item = self.item
        body = Text()
        for label, content, style in (
            ("Тип", item.type.label, "bold"),
            ("Значение", item.display, "bold"),
            ("Статус", item.status_label, "green" if item.confirmed else "yellow"),
            ("Источников", str(item.sources), ""),
        ):
            body.append(f"{label:<12}", style="dim")
            body.append(f"{content}\n", style=style)
        if item.is_target:
            body.append("◆ Это искомый идентификатор.\n", style="cyan")
        body.append(f"\n{DOSSIER_NOTE}\n", style="italic dim")
        for n, occ in enumerate(item.occurrences, 1):
            body.append(f"\n{n}. {occ.title}", style="bold")
            if occ.kind_label:
                body.append(f"  · {occ.kind_label} {occ.location}".rstrip(), style="dim")
            body.append("\n")
            body.append(f"   {occ.url}\n", style="underline")
            body.append("   Проверка: ", style="dim")
            body.append(f"{occ.status_label}\n", style="green" if occ.confirmed else "yellow")
            body.append("   Как распознано: ", style="dim")
            body.append(f"{occ.basis}; {occ.source_label}\n")
            body.append("   Достоверность находки: ", style="dim")
            body.append(f"{occ.confidence.label}\n", style=CONFIDENCE_STYLE[occ.confidence])
            if occ.context:
                body.append(f"   «{' '.join(occ.context.split())}»\n", style="italic")
        self.links = [o.url for o in item.occurrences if is_web_url(o.url)]
        with Vertical(classes="dialog wide"):
            yield Label(f"{item.type.label} · {item.display}", classes="dialog-title")
            with VerticalScroll(classes="dialog-scroll"):
                yield Static(body)
            if self.links:
                yield Label(
                    "Открыть источник в браузере (Enter) — только по вашему выбору",
                    classes="section-title",
                )
                yield OptionList(
                    *[Option(_link_label(u), id=str(i)) for i, u in enumerate(self.links)],
                    id="entity-links",
                )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Копировать значение (C)", id="copy-value")
                if any(o.finding_id in self.findings for o in item.occurrences):
                    yield Button("Находка-источник", id="finding")
                yield Button("Закрыть", id="close", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy-value":
            self.action_copy()
        elif event.button.id == "finding":
            first = next(o for o in self.item.occurrences if o.finding_id in self.findings)
            self.app.push_screen(FindingModal(self.findings[first.finding_id]))
        else:
            self.dismiss(None)

    def action_copy(self) -> None:
        self.app.copy_to_clipboard(self.item.value)
        self.notify("Скопировано (если терминал поддерживает OSC 52)")

    @on(OptionList.OptionSelected, "#entity-links")
    def link_selected(self, event: OptionList.OptionSelected) -> None:
        url = self.links[int(event.option.id or 0)]
        self.app.open_url(url)
        self.notify(f"Открыто в браузере: {urlsplit(url).hostname}")

    def action_close(self) -> None:
        self.dismiss(None)


class FindingModal(ModalScreen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape,q", "close", "Закрыть"),
        Binding("c", "copy('value')", "Копировать значение"),
        Binding("s", "copy('source')", "Копировать источник"),
        Binding("o", "open_source", "Открыть источник"),
    ]

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        f = self.finding
        value = (
            f.value
            if isinstance(f.value, str)
            else json.dumps(f.value, ensure_ascii=False, indent=2)
        )
        body = Text()
        for label, content, style in (
            ("Достоверность", f.confidence.label, CONFIDENCE_STYLE[f.confidence]),
            ("Объект", f.subject, ""),
            ("Атрибут", f.attribute, "bold"),
            ("Источник", f.source_name, ""),
            ("Ссылка", f.source_url, "underline"),
            ("Наблюдалось", f.observed_at.strftime("%Y-%m-%d %H:%M:%S UTC"), ""),
            ("Модуль", f.module, "dim"),
            ("ID", f.id, "dim"),
        ):
            body.append(f"{label:<14}", style="dim")
            body.append(f"{content}\n", style=style)
        body.append("\nЧто подтверждает источник\n", style="bold")
        body.append(f"{f.evidence}\n")
        body.append("\nЗначение\n", style="bold")
        body.append(f"{value}\n")
        self.links = links_in(f.value)
        with Vertical(classes="dialog wide"):
            yield Label(f"Находка · {f.attribute}", classes="dialog-title")
            with VerticalScroll(classes="dialog-scroll"):
                yield Static(body)
            if self.links:
                yield Label(
                    "Открыть в браузере (Enter) — только по вашему выбору", classes="section-title"
                )
                yield OptionList(
                    *[Option(_link_label(u), id=str(i)) for i, u in enumerate(self.links)],
                    id="links",
                )
            with Horizontal(classes="dialog-buttons"):
                yield Button("Копировать значение (C)", id="copy-value")
                if is_web_url(f.source_url):
                    yield Button("Открыть источник (O)", id="open")
                yield Button("Закрыть", id="close", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy-value":
            self.action_copy("value")
        elif event.button.id == "open":
            self.action_open_source()
        else:
            self.dismiss(None)

    def action_copy(self, what: str) -> None:
        f = self.finding
        text = (
            f.source_url
            if what == "source"
            else (f.value if isinstance(f.value, str) else json.dumps(f.value, ensure_ascii=False))
        )
        self.app.copy_to_clipboard(text)
        self.notify("Скопировано (если терминал поддерживает OSC 52)")

    def action_open_source(self) -> None:
        if is_web_url(self.finding.source_url):
            self.app.open_url(self.finding.source_url)
            self.notify("Ссылка открыта в браузере по вашему запросу")
        else:
            self.notify("Источник локальный — ссылки для браузера нет", severity="warning")

    @on(OptionList.OptionSelected, "#links")
    def link_selected(self, event: OptionList.OptionSelected) -> None:
        url = self.links[int(event.option.id or 0)]
        if is_web_url(url):
            self.app.open_url(url)
            self.notify(f"Открыто в браузере: {urlsplit(url).hostname}")

    def action_close(self) -> None:
        self.dismiss(None)


def _link_label(url: str) -> str:
    host = urlsplit(url).hostname or url
    names = {"www.google.com": "Google", "yandex.ru": "Яндекс", "www.bing.com": "Bing"}
    return names.get(host, host) + ("" if host in names else f"  {url[:90]}")


class ExportModal(ModalScreen[tuple[list[ReportFormat], Path] | None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Отмена")]

    def __init__(self, default_dir: Path) -> None:
        super().__init__()
        self.default_dir = default_dir

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label("Экспорт отчёта", classes="dialog-title")
            yield SelectionList[ReportFormat](
                Selection(
                    "PDF — официальный отчёт (гриф, резюме, источники)", ReportFormat.PDF, False
                ),
                Selection("HTML — самодостаточная страница", ReportFormat.HTML, True),
                Selection("Markdown (.md)", ReportFormat.MD, True),
                Selection("JSON — машиночитаемый", ReportFormat.JSON, False),
                Selection("TXT — простой текст", ReportFormat.TXT, False),
                id="formats",
            )
            yield Label("Каталог", classes="section-title")
            yield Input(str(self.default_dir), id="directory")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Сохранить", id="save", variant="primary")
                yield Button("Отмена", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save":
            self.dismiss(None)
            return
        formats = list(self.query_one(SelectionList).selected)
        raw = self.query_one("#directory", Input).value.strip()
        if not formats or not raw:
            self.notify("Выберите хотя бы один формат и каталог", severity="warning")
            return
        self.dismiss((formats, Path(raw).expanduser()))

    def action_cancel(self) -> None:
        self.dismiss(None)

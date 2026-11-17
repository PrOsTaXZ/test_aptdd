"""History screen: browse, open, delete and purge stored investigations."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from osint_toolkit.core.models import TargetType
from osint_toolkit.tui.widgets import ConfirmModal

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp


class HistoryScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "app.pop_screen", "Назад"),
        Binding("enter", "open", "Открыть", show=True),
        Binding("d,delete", "delete", "Удалить"),
        Binding("P", "purge", "Очистить всё"),
        Binding("r", "reload", "Обновить"),
    ]

    @property
    def osint(self) -> OsintApp:
        return cast("OsintApp", self.app)

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="history"):
            yield Static("", id="history-title")
            yield DataTable(id="history-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for key, label in (
            ("date", "Дата"),
            ("type", "Тип"),
            ("target", "Цель"),
            ("mode", "Режим"),
            ("findings", "Находок"),
            ("contra", "Противоречий"),
            ("status", "Статус"),
            ("id", "ID"),
        ):
            table.add_column(label, key=key)
        self.action_reload()
        table.focus()

    def action_reload(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        try:
            entries = self.osint.storage.list(500)
            total = self.osint.storage.count()
        except sqlite3.Error as exc:
            self.notify(f"История недоступна: {exc}", severity="error")
            return
        for e in entries:
            table.add_row(
                e.created_at.astimezone().strftime("%Y-%m-%d %H:%M"),
                TargetType(e.target_type).label,
                Text(e.target) if e.target else Text("скрыто (хеш)", style="dim italic"),
                "Full" if e.mode == "full" else "выборочно",
                str(e.summary.get("findings", 0)),
                str(e.summary.get("contradictions", 0)),
                Text("завершено", "green")
                if e.status == "completed"
                else Text("прервано", "magenta"),
                Text(e.id[:8], style="dim"),
                key=e.id,
            )
        hint = "Enter — открыть · D — удалить · Shift+P — очистить всё"
        title = Text.assemble(("История исследований", "bold"), f"  ({total})\n", (hint, "dim"))
        if not entries:
            title.append("\nИстория пуста.", style="dim")
        self.query_one("#history-title", Static).update(title)

    def _selected(self) -> str | None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return None
        return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

    @on(DataTable.RowSelected)
    def row_selected(self) -> None:
        self.action_open()

    def action_open(self) -> None:
        key = self._selected()
        if key is None:
            return
        try:
            investigation = self.osint.storage.get(key)
        except (sqlite3.Error, ValueError) as exc:
            self.notify(f"Не удалось загрузить запись: {exc}", severity="error")
            return
        if investigation is None:
            self.notify(
                "Для этой записи сохранена только сводка (OSINT_STORE_TARGETS=false)",
                severity="warning",
            )
            return
        from osint_toolkit.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(investigation))

    def action_delete(self) -> None:
        key = self._selected()
        if key is None:
            return

        def answer(ok: bool | None) -> None:
            if ok:
                self.osint.storage.delete(key)
                self.notify("Запись удалена")
                self.action_reload()

        self.app.push_screen(
            ConfirmModal("Удалить запись из истории?", f"ID {key}", yes="Удалить", danger=True),
            answer,
        )

    def action_purge(self) -> None:
        total = self.osint.storage.count()
        if not total:
            self.notify("История уже пуста")
            return

        def answer(ok: bool | None) -> None:
            if ok:
                removed = self.osint.storage.purge()
                self.notify(f"Удалено записей: {removed}. Файлы отчётов не тронуты.")
                self.action_reload()

        self.app.push_screen(
            ConfirmModal(
                f"Удалить всю историю ({total})?",
                "Данные будут перезаписаны, восстановить их нельзя.",
                yes="Удалить всё",
                danger=True,
            ),
            answer,
        )

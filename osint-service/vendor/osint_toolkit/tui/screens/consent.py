"""Consent dialog: the TUI implementation of the core ConsentProvider protocol."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Label, Static

from osint_toolkit.core.models import ExternalRequest
from osint_toolkit.core.privacy import ConsentAnswer, request_key

ALLOW = Text("✔ разрешить", style="bold green")
DENY = Text("✖ запретить", style="bold red")


class ConsentScreen(ModalScreen[dict[str, ConsentAnswer]]):
    """Every request starts denied; the user enables what may be sent."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("space", "toggle_row", "Переключить"),
        Binding("a", "set_all(True)", "Разрешить все"),
        Binding("n", "set_all(False)", "Запретить все"),
        Binding("ctrl+s", "confirm", "Подтвердить"),
        Binding("escape", "deny", "Запретить и продолжить"),
    ]

    def __init__(self, requests: Sequence[ExternalRequest]) -> None:
        super().__init__()
        self.requests = list(requests)
        self.allowed: dict[str, bool] = {request_key(r): False for r in self.requests}
        self._warned = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide", id="consent"):
            yield Label("🌐  Согласие на внешние запросы", classes="dialog-title")
            yield Static(
                Text(
                    "Эти модули отправят данные сторонним сервисам — сервисы увидят ваш запрос. "
                    "Без разрешения поиск в интернете НЕ выполняется: останутся только офлайн-"
                    "проверки. Пробел или Enter — переключить строку, A — разрешить все, "
                    "N — запретить все, Ctrl+S — подтвердить выбор."
                ),
                classes="dialog-body",
            )
            yield DataTable(id="consent-table", cursor_type="row", zebra_stripes=True)
            yield Checkbox(
                "Запомнить решения для этих модулей (можно отозвать в настройках)", id="remember"
            )
            yield Static("", id="consent-warning")
            with Horizontal(classes="dialog-buttons"):
                yield Button("Разрешить всё и начать", id="allow-all", variant="success")
                yield Button("Подтвердить выбор", id="confirm", variant="primary")
                yield Button("Только офлайн", id="deny", variant="error")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("Решение", key="decision", width=14)
        table.add_column("Модуль", key="module")
        table.add_column("Цель", key="target")
        table.add_column("Сервисы → передаваемые данные", key="services")
        for request in self.requests:
            services = Text()
            for i, svc in enumerate(request.services):
                if i:
                    services.append("\n")
                services.append(svc.name, style="bold")
                services.append(f" ({svc.url}) → {svc.data_sent}", style="dim")
            for line in request.details:
                services.append(f"\n  ⇢ {line}", style="yellow")
            table.add_row(
                DENY,
                Text(request.module_title),
                Text(str(request.target)),
                services,
                key=request_key(request),
                height=max(1, len(request.services) + len(request.details)),
            )
        table.focus()

    def _set(self, key: str, value: bool) -> None:
        self.allowed[key] = value
        self.query_one(DataTable).update_cell(key, "decision", ALLOW if value else DENY)

    def action_toggle_row(self) -> None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        if key is not None:
            self._set(key, not self.allowed[key])

    @on(DataTable.RowSelected)
    def row_selected(self) -> None:
        self.action_toggle_row()

    def action_set_all(self, value: bool) -> None:
        for key in self.allowed:
            self._set(key, value)

    def _answers(self) -> dict[str, ConsentAnswer]:
        remember = self.query_one("#remember", Checkbox).value
        return {k: ConsentAnswer(allowed=v, remember=remember) for k, v in self.allowed.items()}

    def action_confirm(self) -> None:
        if not any(self.allowed.values()) and not self._warned:
            self._warned = True  # a silent "nothing allowed" looked like "nothing found"
            self.query_one("#consent-warning", Static).update(
                Text(
                    f"⚠ Ничего не разрешено: {len(self.allowed)} сетевых проверок не будут "
                    "выполнены, поиск в интернете не состоится. Нажмите «Разрешить всё и "
                    "начать» (или A), либо Ctrl+S ещё раз — продолжить только офлайн.",
                    style="bold yellow",
                )
            )
            return
        self.dismiss(self._answers())

    def action_allow_all(self) -> None:
        self.action_set_all(True)
        self.dismiss(self._answers())

    def action_deny(self) -> None:
        self.dismiss({k: ConsentAnswer(False) for k in self.allowed})

    @on(Button.Pressed, "#confirm")
    def confirm_pressed(self) -> None:
        self.action_confirm()

    @on(Button.Pressed, "#allow-all")
    def allow_all_pressed(self) -> None:
        self.action_allow_all()

    @on(Button.Pressed, "#deny")
    def deny_pressed(self) -> None:
        self.action_deny()


class TuiConsent:
    """ConsentProvider that shows :class:`ConsentScreen` (must be awaited from a worker)."""

    def __init__(self, app: App[Any]) -> None:
        self.app = app

    async def ask(self, requests: Sequence[ExternalRequest]) -> Mapping[str, ConsentAnswer]:
        answers = await self.app.push_screen_wait(ConsentScreen(requests))
        return answers or {}

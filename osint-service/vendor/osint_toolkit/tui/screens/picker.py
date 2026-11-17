"""Module picker for targeted investigations."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, SelectionList, Static
from textual.widgets.selection_list import Selection

from osint_toolkit.core.models import Target

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp


class ModulePickerModal(ModalScreen[list[str] | None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Отмена"),
        Binding("ctrl+a", "select_all", "Все"),
        Binding("ctrl+s", "confirm", "Запустить"),
    ]

    def __init__(self, target: Target) -> None:
        super().__init__()
        self.target = target

    def compose(self) -> ComposeResult:
        app = cast("OsintApp", self.app)
        selections = []
        for module in app.registry.for_target(self.target):
            availability = module.availability(app.settings)
            label = Text(module.title, style="bold")
            label.append(f"  {module.name}", style="dim")
            if module.is_external:
                label.append(
                    "  🌐 " + ", ".join(s.name for s in module.external_services), style="yellow"
                )
            if not availability.available:
                label.append(f"  ⚙ {availability.reason}", style="red")
            selections.append(
                Selection(
                    label,
                    module.name,
                    module.enabled_by_default(app.settings) and availability.available,
                )
            )
        with Vertical(classes="dialog wide"):
            yield Label(f"Модули для «{self.target.normalized}»", classes="dialog-title")
            yield Static(
                "Пробел — отметить, Ctrl+A — все, Ctrl+S — запустить. "
                "🌐 — модуль обращается к внешнему сервису (спросит согласие).",
                classes="dialog-body",
            )
            yield SelectionList[str](*selections, id="modules")
            with Horizontal(classes="dialog-buttons"):
                yield Button("▶  Запустить выбранные", id="confirm", variant="primary")
                yield Button("Отмена", id="cancel")

    def on_mount(self) -> None:
        self.query_one(SelectionList).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm":
            self.action_confirm()
        else:
            self.action_cancel()

    def action_select_all(self) -> None:
        self.query_one(SelectionList).select_all()

    def action_confirm(self) -> None:
        selected = list(self.query_one(SelectionList).selected)
        if not selected:
            self.notify("Не выбрано ни одного модуля", severity="warning")
            return
        self.dismiss(selected)

    def action_cancel(self) -> None:
        self.dismiss(None)

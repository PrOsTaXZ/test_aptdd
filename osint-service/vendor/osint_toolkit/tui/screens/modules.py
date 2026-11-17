"""Modules screen: what each module does, what it needs and where it sends data."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from osint_toolkit.modules.base import BaseModule
from osint_toolkit.tui.widgets import InfoModal

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp


class ModulesScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "app.pop_screen", "Назад")]

    @property
    def osint(self) -> OsintApp:
        return cast("OsintApp", self.app)

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="modules-screen"):
            yield Static(
                Text.assemble(
                    ("Модули", "bold"),
                    (
                        "\nEnter — подробности: описание, ограничения, внешние "
                        "сервисы и передаваемые данные.",
                        "dim",
                    ),
                )
            )
            yield DataTable(id="modules-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for key, label in (
            ("module", "Модуль"),
            ("types", "Типы целей"),
            ("net", "Сеть"),
            ("ready", "Готовность"),
        ):
            table.add_column(label, key=key)
        settings = self.osint.settings
        for module in self.osint.registry.all():
            availability = module.availability(settings)
            if not availability.available:
                ready = Text(f"⚙ {availability.reason}", style="yellow")
            elif not module.default_enabled:
                ready = Text("по запросу", style="cyan")
            else:
                ready = Text("✔ готов", style="green")
            net = (
                Text("🌐 " + ", ".join(s.name for s in module.external_services), "yellow")
                if module.is_external
                else Text("офлайн", style="green")
            )
            table.add_row(
                Text.assemble((module.title, "bold"), (f"\n{module.name}", "dim")),
                ", ".join(sorted(t.label for t in module.target_types)),
                net,
                ready,
                key=module.name,
                height=2,
            )
        for where, error in self.osint.registry.load_errors.items():
            self.notify(f"{where}: {error}", title="Модуль не загружен", severity="error")
        table.focus()

    @on(DataTable.RowSelected)
    def row_selected(self, event: DataTable.RowSelected) -> None:
        module = self.osint.registry.get(event.row_key.value or "")
        if module is not None:
            self.app.push_screen(InfoModal(module.title, module_details(module, self.osint)))


def module_details(module: BaseModule, app: OsintApp) -> Text:
    availability = module.availability(app.settings)
    text = Text.assemble(
        ("Имя: ", "dim"),
        f"{module.name}\n",
        ("Типы целей: ", "dim"),
        ", ".join(sorted(t.label for t in module.target_types)) + "\n",
        ("Готовность: ", "dim"),
        ("готов" if availability.available else str(availability.reason)) + "\n\n",
        module.description + "\n",
    )
    if module.external_services:
        text.append("\nВнешние сервисы (только с вашего согласия):\n", style="bold yellow")
        for svc in module.external_services:
            text.append(f"  • {svc.name} — {svc.url}\n    передаётся: {svc.data_sent}\n")
    else:
        text.append("\nРаботает офлайн, сетевые запросы не выполняет.\n", style="green")
    if module.limitations:
        text.append("\nОграничения:\n", style="bold")
        for item in module.limitations:
            text.append(f"  • {item}\n")
    return text

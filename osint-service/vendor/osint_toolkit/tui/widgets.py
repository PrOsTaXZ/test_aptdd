"""Reusable TUI pieces: modals and cell renderers (shared styles with the CLI)."""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Static

from osint_toolkit.console import CONFIDENCE_STYLE, STATUS_STYLE, format_value
from osint_toolkit.core.models import Confidence, JsonValue, ModuleStatus

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
STATUS_ICON = {
    ModuleStatus.OK: "✔",
    ModuleStatus.NO_RESULTS: "○",
    ModuleStatus.NOT_CONFIGURED: "⚙",
    ModuleStatus.SKIPPED: "⤼",
    ModuleStatus.TIMEOUT: "⏱",
    ModuleStatus.ERROR: "✖",
    ModuleStatus.CANCELLED: "■",
}


def status_cell(status: ModuleStatus) -> Text:
    return Text(f"{STATUS_ICON[status]} {status.label}", style=STATUS_STYLE[status])


def confidence_cell(confidence: Confidence) -> Text:
    return Text(f"● {confidence.label}", style=CONFIDENCE_STYLE[confidence])


def short(value: JsonValue | str, limit: int = 70) -> Text:
    """One-line preview; data is wrapped in Text so markup in it is never interpreted."""
    text = format_value(value, limit=10_000) if not isinstance(value, str) else value
    text = " ".join(text.split())
    return Text(text if len(text) <= limit else text[: limit - 1] + "…")


class ClickTable(DataTable[object]):
    """DataTable whose rows open with a single mouse click (Enter works as usual).

    The stock table selects a row only when the click lands on the already highlighted cell;
    moving the cursor on mouse-down makes every click on a row a "highlight click"."""

    def on_mouse_down(self, event: events.MouseDown) -> None:
        meta = event.style.meta
        row, column = meta.get("row"), meta.get("column")
        if (
            self.cursor_type == "row"
            and isinstance(row, int)
            and isinstance(column, int)
            and row >= 0
            and column >= 0
        ):
            self.cursor_coordinate = Coordinate(row, column)


class ConfirmModal(ModalScreen[bool]):
    """Yes/No question. ``y``/Enter confirms, ``n``/Esc cancels."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("y", "answer(True)", "Да", show=False),
        Binding("n,escape", "answer(False)", "Нет", show=False),
    ]

    def __init__(
        self,
        question: str,
        detail: str = "",
        *,
        yes: str = "Да",
        no: str = "Отмена",
        danger: bool = False,
    ) -> None:
        super().__init__()
        self.question, self.detail, self.yes, self.no, self.danger = (
            question,
            detail,
            yes,
            no,
            danger,
        )

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.question, classes="dialog-title")
            if self.detail:
                yield Static(Text(self.detail), classes="dialog-body")
            with Horizontal(classes="dialog-buttons"):
                yield Button(self.yes, id="yes", variant="error" if self.danger else "primary")
                yield Button(self.no, id="no")

    def on_mount(self) -> None:
        self.query_one("#no" if self.danger else "#yes", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)


class InfoModal(ModalScreen[None]):
    """Scrollable read-only details."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape,q", "close", "Закрыть")]

    def __init__(self, title: str, body: Text | str) -> None:
        super().__init__()
        self.title_text = title
        self.body = body if isinstance(body, Text) else Text(body)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Label(self.title_text, classes="dialog-title")
            with VerticalScroll(classes="dialog-scroll"):
                yield Static(self.body)
            with Horizontal(classes="dialog-buttons"):
                yield Button("Закрыть", id="close", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)

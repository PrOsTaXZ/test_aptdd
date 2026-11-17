"""Home screen: main menu with categories and the investigation form."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, OptionList, Static, Switch
from textual.widgets.option_list import Option

from osint_toolkit.core.detector import (
    UnsupportedInputError,
    declare_own,
    detect,
    parse_as,
    related_targets,
)
from osint_toolkit.core.models import Target, TargetType

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp

PLACEHOLDERS = {
    None: "email, username, телефон, ФИО, домен, IP или путь к изображению",
    TargetType.EMAIL: "name@example.org",
    TargetType.USERNAME: "username или @username",
    TargetType.PHONE: "+7 999 123-45-67",
    TargetType.NAME: "Имя Фамилия",
    TargetType.IMAGE: "/путь/к/фото.jpg",
    TargetType.DOMAIN: "example.org или https://example.org/…",
    TargetType.IP: "8.8.8.8 или 2001:db8::1",
}
CATEGORY_ORDER = (
    TargetType.EMAIL,
    TargetType.USERNAME,
    TargetType.PHONE,
    TargetType.NAME,
    TargetType.IMAGE,
    TargetType.DOMAIN,
    TargetType.IP,
)


class HomeScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+l", "focus_query", "К вводу"),
        Binding("ctrl+o", "toggle_offline", "Офлайн"),
        Binding("ctrl+t", "pick_modules", "Выбрать модули"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.forced_type: TargetType | None = None
        self.candidates: list[Target] = []

    @property
    def osint(self) -> OsintApp:
        return cast("OsintApp", self.app)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="home"):
            with Vertical(id="sidebar"):
                yield Label("МЕНЮ", classes="section-title")
                yield OptionList(
                    Option("★  Full Investigation", id="auto"),
                    None,
                    *[Option(f"   {t.label}", id=t.value) for t in CATEGORY_ORDER],
                    None,
                    Option("⏲  История        F2", id="history"),
                    Option("⚙  Модули         F3", id="modules"),
                    Option("☰  Настройки      F4", id="settings"),
                    id="menu",
                )
            with Vertical(id="main"):
                yield Static("Что исследуем?", id="hero")
                yield Static(
                    "Тип определяется автоматически. Перед внешними запросами программа "
                    "покажет, какие данные и куда будут отправлены.",
                    id="hero-hint",
                )
                with Horizontal(id="query-row"):
                    yield Label("АВТО", id="type-badge")
                    yield Input(placeholder=PLACEHOLDERS[None], id="query")
                yield Static("", id="detect-error")
                yield Label("Варианты интерпретации", classes="section-title")
                yield OptionList(id="candidates")
                yield Static("", id="plan-preview")
                with Horizontal(id="options"):
                    yield Switch(value=self.osint.settings.offline, id="offline")
                    yield Label("Офлайн-режим (без сетевых запросов)", classes="switch-label")
                    yield Switch(
                        value=self.osint.settings.report_formats.strip().lower() != "none",
                        id="reports",
                    )
                    yield Label("Сохранять отчёты", classes="switch-label")
                    yield Switch(value=False, id="own-email")
                    yield Label(
                        "Это мой адрес (Gravatar, holehe)",
                        classes="switch-label",
                        id="own-email-label",
                    )
                with Horizontal(id="actions"):
                    yield Button(
                        "▶  Full Investigation", id="run", variant="primary", disabled=True
                    )
                    yield Button("Выбрать модули…", id="pick", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#query", Input).focus()
        self.query_one("#candidates", OptionList).display = False

    # ------------------------------------------------------------------ menu
    @on(OptionList.OptionSelected, "#menu")
    def menu_selected(self, event: OptionList.OptionSelected) -> None:
        option_id = event.option.id or ""
        if option_id in ("history", "modules", "settings"):
            self.osint.action_open(option_id)
            return
        self.forced_type = None if option_id == "auto" else TargetType(option_id)
        badge = self.query_one("#type-badge", Label)
        badge.update("АВТО" if self.forced_type is None else self.forced_type.label.upper())
        badge.set_class(self.forced_type is not None, "forced")
        query = self.query_one("#query", Input)
        query.placeholder = PLACEHOLDERS[self.forced_type]
        query.focus()
        self.refresh_detection()

    # ------------------------------------------------------------------ detection
    @on(Input.Changed, "#query")
    def query_changed(self) -> None:
        self.refresh_detection()

    def refresh_detection(self) -> None:
        raw = self.query_one("#query", Input).value
        error = self.query_one("#detect-error", Static)
        options = self.query_one("#candidates", OptionList)
        options.clear_options()
        self.candidates = []
        if raw.strip():
            region = self.osint.settings.default_region
            try:
                if self.forced_type is not None:
                    self.candidates = [parse_as(raw, self.forced_type, default_region=region)]
                else:
                    self.candidates = detect(raw, default_region=region)
                error.update("")
            except UnsupportedInputError as exc:
                error.update(Text(f"✖ {exc}"))
        else:
            error.update("")
        for index, target in enumerate(self.candidates):
            label = Text.assemble((f"{target.type.label:<12}", "bold"), " ", target.normalized)
            if target.normalized != target.raw.strip():
                label.append(f"   ← {target.raw.strip()}", style="dim")
            options.add_option(Option(label, id=str(index)))
        options.display = bool(self.candidates)
        if self.candidates:
            options.highlighted = 0
        has = bool(self.candidates)
        self.query_one("#run", Button).disabled = not has
        self.query_one("#pick", Button).disabled = not has
        self.update_preview()

    @on(OptionList.OptionHighlighted, "#candidates")
    def candidate_highlighted(self) -> None:
        self.update_preview()

    @on(OptionList.OptionSelected, "#candidates")
    def candidate_selected(self) -> None:
        self.action_run()

    def selected_target(self) -> Target | None:
        if not self.candidates:
            return None
        index = self.query_one("#candidates", OptionList).highlighted or 0
        return self.candidates[min(index, len(self.candidates) - 1)]

    def update_preview(self) -> None:
        preview = self.query_one("#plan-preview", Static)
        target = self.selected_target()
        is_email = target is not None and target.type is TargetType.EMAIL
        self.query_one("#own-email", Switch).display = is_email
        self.query_one("#own-email-label", Label).display = is_email
        if target is None:
            preview.update("")
            return
        registry = self.osint.registry
        targets = [target, *related_targets(target)]
        modules = [
            m
            for t in targets
            for m in registry.for_target(t)
            if m.enabled_by_default(self.osint.settings)
        ]
        external = sum(1 for m in modules if m.is_external)
        offline = self.query_one("#offline", Switch).value
        text = Text("Будет запущено модулей: ", style="dim")
        text.append(str(len(modules)), style="bold")
        if len(targets) > 1:
            text.append(
                f"  · связанные цели: {', '.join(t.normalized for t in targets[1:])}", style="dim"
            )
        if external:
            note = " — пропустятся (офлайн)" if offline else " — только с вашего согласия"
            text.append(f"\nС внешними запросами: {external}{note}", style="yellow")
        preview.update(text)

    @on(Switch.Changed, "#offline")
    def offline_changed(self) -> None:
        self.update_preview()

    # ------------------------------------------------------------------ actions
    def action_focus_query(self) -> None:
        self.query_one("#query", Input).focus()

    def action_toggle_offline(self) -> None:
        switch = self.query_one("#offline", Switch)
        switch.value = not switch.value

    @on(Input.Submitted, "#query")
    def submitted(self) -> None:
        self.action_run()

    @on(Button.Pressed, "#run")
    def run_pressed(self) -> None:
        self.action_run()

    @on(Button.Pressed, "#pick")
    def pick_pressed(self) -> None:
        self.action_pick_modules()

    def action_run(self, modules: list[str] | None = None) -> None:
        target = self.selected_target()
        if target is None:
            self.app.bell()
            return
        from osint_toolkit.tui.screens.run import RunScreen

        own = self.query_one("#own-email", Switch)
        if target.type is TargetType.EMAIL and own.value:
            target = declare_own(target)
        self.app.push_screen(
            RunScreen(
                target,
                query=self.query_one("#query", Input).value.strip(),
                modules=modules,
                offline=self.query_one("#offline", Switch).value,
                save_reports=self.query_one("#reports", Switch).value,
            )
        )

    def action_pick_modules(self) -> None:
        target = self.selected_target()
        if target is None:
            self.app.bell()
            return
        from osint_toolkit.tui.screens.picker import ModulePickerModal

        def chosen(names: list[str] | None) -> None:
            if names:
                self.action_run(modules=names)

        self.app.push_screen(ModulePickerModal(target), chosen)

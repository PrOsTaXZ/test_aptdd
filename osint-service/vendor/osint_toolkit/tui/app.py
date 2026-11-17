"""Main Textual application."""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import ClassVar

from textual.app import App
from textual.binding import Binding, BindingType
from textual.theme import Theme

from osint_toolkit import __version__
from osint_toolkit.config import Settings, default_env_file
from osint_toolkit.core.engine import Engine, ProgressListener
from osint_toolkit.core.privacy import ConsentProvider
from osint_toolkit.core.registry import ModuleRegistry, load_registry
from osint_toolkit.net import NetworkServices
from osint_toolkit.storage.db import Storage

OSINT_DARK = Theme(
    name="osint-dark",
    primary="#4FA3FF",
    secondary="#7C8CF8",
    accent="#38D9C0",
    warning="#E3B341",
    error="#F47067",
    success="#4CC38A",
    foreground="#E3E8F0",
    background="#0B0F16",
    surface="#121821",
    panel="#18202C",
    boost="#1E2836",
    dark=True,
)


class OsintApp(App[int]):
    TITLE = "Personal OSINT Toolkit"
    SUB_TITLE = f"v{__version__}"
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = True
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("f2", "open('history')", "История"),
        Binding("f3", "open('modules')", "Модули"),
        Binding("f4", "open('settings')", "Настройки"),
        Binding("ctrl+q", "quit", "Выход", priority=True),
    ]

    def __init__(
        self,
        settings: Settings,
        *,
        registry: ModuleRegistry | None = None,
        storage: Storage | None = None,
        network_factory: Callable[[Settings], NetworkServices] | None = None,
        env_file: Path | None = None,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.env_file = env_file or default_env_file()  # where F4 saves changed limits
        self._module_registry = registry
        self._history_storage = storage
        self.network_factory = network_factory

    # ------------------------------------------------------------------ shared core objects
    @property
    def registry(self) -> ModuleRegistry:
        if self._module_registry is None:
            self._module_registry = load_registry()
        return self._module_registry

    @cached_property
    def storage(self) -> Storage:
        return self._history_storage or Storage(
            self.settings.db_path, store_targets=self.settings.store_targets
        )

    def make_engine(
        self, consent: ConsentProvider, listener: ProgressListener, settings: Settings | None = None
    ) -> Engine:
        return Engine(
            settings or self.settings,
            self.registry,
            consent=consent,
            storage=self.storage,
            listener=listener,
            network_factory=self.network_factory,
        )

    # ------------------------------------------------------------------ lifecycle
    def on_mount(self) -> None:
        from osint_toolkit.reports.preview import clear_previews

        with contextlib.suppress(OSError):
            clear_previews(self.settings)  # report previews from an earlier session
        self.register_theme(OSINT_DARK)
        self.theme = "osint-dark"
        if self.settings.offline:
            self.sub_title = f"v{__version__} · офлайн-режим"
        from osint_toolkit.tui.screens.home import HomeScreen

        self.push_screen(HomeScreen())

    def action_open(self, name: str) -> None:
        from osint_toolkit.tui.screens.history import HistoryScreen
        from osint_toolkit.tui.screens.modules import ModulesScreen
        from osint_toolkit.tui.screens.settings import SettingsScreen

        screens = {"history": HistoryScreen, "modules": ModulesScreen, "settings": SettingsScreen}
        target = screens[name]
        if isinstance(self.screen, target):
            return
        self.push_screen(target())

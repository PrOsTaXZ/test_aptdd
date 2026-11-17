"""Settings & data screen: masked settings, paths, DB-IP databases, privacy housekeeping."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from pydantic import ValidationError
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    LoadingIndicator,
    Static,
    Switch,
)

from osint_toolkit.config import Settings, update_env_values
from osint_toolkit.data import dbip
from osint_toolkit.net import HttpClient, NetworkError
from osint_toolkit.reports import purge_reports
from osint_toolkit.sandbox import SandboxError, sandbox_status
from osint_toolkit.tools import (
    TOOLS,
    ToolError,
    ToolSpec,
    install_summary,
    install_tool,
    remove_tool,
    tool_status,
)
from osint_toolkit.tui.widgets import ConfirmModal

if TYPE_CHECKING:
    from osint_toolkit.tui.app import OsintApp


class SettingsScreen(Screen[None]):
    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "app.pop_screen", "Назад")]

    @property
    def osint(self) -> OsintApp:
        return cast("OsintApp", self.app)

    def compose(self) -> ComposeResult:
        yield Header()
        settings = self.osint.settings
        with VerticalScroll(id="settings"):
            yield Label("Лимиты поиска и проверки", classes="section-title")
            yield Static(
                Text(
                    "Применяются сразу к следующему исследованию, без перезапуска, и "
                    f"сохраняются в {self.osint.env_file} (меняются только эти строки).",
                    style="dim",
                )
            )
            for field, label, hint in LIMIT_FIELDS:
                with Horizontal(classes="limit-row"):
                    yield Label(label, classes="limit-label")
                    yield Input(
                        str(int(getattr(settings, field))),
                        type="integer",
                        id=f"limit-{field}",
                        classes="limit-input",
                    )
                    yield Label(hint, classes="limit-hint")
            with Horizontal(classes="limit-row"):
                yield Label("Maigret: только топ-1000 сайтов", classes="limit-label")
                yield Switch(settings.maigret_top_sites > 0, id="limit-top1000")
                yield Label(self._top_hint(settings), classes="limit-hint", id="top-hint")
            with Horizontal(classes="button-row"):
                yield Button("Применить и сохранить", id="limits-apply", variant="primary")
                yield Button("Вернуть текущие", id="limits-reset")
            yield Label("Настройки", classes="section-title")
            yield Static(Text(f"Файл: {self.osint.env_file}", style="dim"))
            yield DataTable(id="settings-table", cursor_type="row", show_cursor=False)
            yield Label("Базы DB-IP Lite (офлайн-геолокация и ASN)", classes="section-title")
            yield DataTable(id="dbip-table", cursor_type="row", show_cursor=False)
            yield Static(Text(dbip.ATTRIBUTION, style="dim"))
            with Horizontal(classes="button-row"):
                yield Button(
                    "Скачать / обновить Country + ASN", id="dbip-update", variant="primary"
                )
                yield Button("+ City (~60 МБ)", id="dbip-city")
                yield LoadingIndicator(id="dbip-loading")
            yield Label("Изолированные инструменты", classes="section-title")
            yield DataTable(id="tools-table", cursor_type="row")
            yield Static("", id="tools-info")
            with Horizontal(classes="button-row"):
                yield Button(
                    "Установить выбранный (в песочнице)", id="tool-install", variant="primary"
                )
                yield Button("Удалить выбранный", id="tool-remove")
                yield LoadingIndicator(id="tool-loading")
            yield Label("Приватность", classes="section-title")
            yield Static("", id="privacy-info")
            with Horizontal(classes="button-row"):
                yield Button("Отозвать сохранённые согласия", id="revoke")
                yield Button("Удалить файлы отчётов", id="purge-reports", variant="error")
        yield Footer()

    @staticmethod
    def _top_hint(settings: Settings) -> str:
        top = settings.maigret_top_sites
        if top == 0:
            return "выкл.: вся база (~5900 сайтов, дольше)"
        return f"вкл.: {top} самых популярных сайтов (быстрее)"

    # ------------------------------------------------------------------ limits
    def _limit_values(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for field, label, _hint in LIMIT_FIELDS:
            raw = self.query_one(f"#limit-{field}", Input).value.strip()
            if not raw.lstrip("-").isdigit():
                raise ValueError(f"«{label}»: введите целое число")
            values[field] = int(raw)
        values["maigret_top_sites"] = 1000 if self.query_one("#limit-top1000", Switch).value else 0
        return values

    @on(Button.Pressed, "#limits-apply")
    def apply_limits(self) -> None:
        current = self.osint.settings
        try:
            values = self._limit_values()
            updated = Settings.model_validate({**current.model_dump(), **values})
        except ValueError as exc:
            message = (
                "; ".join(_limit_error(e) for e in exc.errors())
                if isinstance(exc, ValidationError)
                else str(exc)
            )
            self.notify(message, title="Значение не принято", severity="error", timeout=10)
            return
        changed = {k: v for k, v in values.items() if getattr(current, k) != v}
        if not changed:
            self.notify("Значения не изменились")
            return
        self.osint.settings = updated
        try:
            update_env_values(
                {f"OSINT_{k.upper()}": str(v) for k, v in changed.items()}, self.osint.env_file
            )
        except OSError as exc:
            self.notify(
                f"Применено до выхода из программы, но не сохранено: {exc}",
                severity="warning",
                timeout=10,
            )
        else:
            self.notify(
                ", ".join(f"{_LIMIT_LABELS.get(k, k)}: {v}" for k, v in changed.items()),
                title="Лимиты применены и сохранены",
            )
        self.query_one("#top-hint", Label).update(self._top_hint(updated))
        self._fill_settings_table()

    @on(Button.Pressed, "#limits-reset")
    def reset_limits(self) -> None:
        settings = self.osint.settings
        for field, _label, _hint in LIMIT_FIELDS:
            self.query_one(f"#limit-{field}", Input).value = str(int(getattr(settings, field)))
        self.query_one("#limit-top1000", Switch).value = settings.maigret_top_sites > 0

    @on(Switch.Changed, "#limit-top1000")
    def top_switched(self, event: Switch.Changed) -> None:
        preview = self.osint.settings.model_copy(
            update={"maigret_top_sites": 1000 if event.value else 0}
        )
        self.query_one("#top-hint", Label).update(
            self._top_hint(preview) + " — нажмите «Применить»"
        )

    def _fill_settings_table(self) -> None:
        settings = self.osint.settings
        table = self.query_one("#settings-table", DataTable)
        table.clear()
        for name, value in settings.masked().items():
            table.add_row(f"OSINT_{name.upper()}", Text(value))
        for label, path in (
            ("Отчёты", settings.effective_reports_dir),
            ("Базы DB-IP", settings.geo_dir),
            ("Логи", settings.log_dir),
        ):
            table.add_row(Text(label, style="dim"), Text(str(path)))

    def on_mount(self) -> None:
        settings = self.osint.settings
        table = self.query_one("#settings-table", DataTable)
        table.add_column("Параметр", key="name")
        table.add_column("Значение", key="value")
        self._fill_settings_table()
        dbip_table = self.query_one("#dbip-table", DataTable)
        for key, label in (
            ("kind", "База"),
            ("present", "Установлена"),
            ("version", "Версия"),
            ("build", "Сборка"),
            ("size", "Размер"),
        ):
            dbip_table.add_column(label, key=key)
        tools_table = self.query_one("#tools-table", DataTable)
        for key, label in (
            ("name", "Инструмент"),
            ("version", "Версия"),
            ("pinned", "Закреплена"),
            ("license", "Лицензия"),
            ("state", "Состояние"),
        ):
            tools_table.add_column(label, key=key)
        self.query_one("#dbip-loading").display = False
        self.query_one("#tool-loading").display = False
        install = self.query_one("#tool-install", Button)
        install.disabled = settings.offline
        if settings.offline:
            install.tooltip = "Офлайн-режим: загрузка запрещена"
        offline = settings.offline
        for button_id in ("#dbip-update", "#dbip-city"):
            button = self.query_one(button_id, Button)
            button.disabled = offline
            if offline:
                button.tooltip = "Офлайн-режим: загрузка запрещена"
        self.refresh_status()

    def refresh_status(self) -> None:
        table = self.query_one("#dbip-table", DataTable)
        table.clear()
        for kind in dbip.DbipKind:
            st = dbip.status(self.osint.settings.geo_dir, kind)
            table.add_row(
                kind.value,
                Text("да", "green") if st.present else Text("нет", "yellow"),
                st.version or "—",
                st.build_date or "—",
                f"{st.size / 2**20:.1f} МБ" if st.present else "—",
            )
        self.refresh_tools()
        consents = self.osint.storage.consents()
        info = Text(f"Сохранённых решений о внешних запросах: {len(consents)}\n")
        for module, allowed in consents.items():
            info.append(
                f"  • {module}: {'всегда разрешать' if allowed else 'всегда запрещать'}\n",
                style="yellow" if allowed else "cyan",
            )
        info.append(
            f"История: {self.osint.storage.count()} записей (очистка — F2 → Shift+P)", style="dim"
        )
        self.query_one("#privacy-info", Static).update(info)

    def refresh_tools(self) -> None:
        table = self.query_one("#tools-table", DataTable)
        row = table.cursor_row
        table.clear()
        for spec in TOOLS.values():
            st = tool_status(self.osint.settings, spec)
            style = "red" if not st.sandbox_ok else "green" if st.ready else "yellow"
            table.add_row(
                spec.name,
                st.version or "—",
                spec.version,
                spec.license,
                Text(("✔ " if st.ready and not st.outdated else "⚙ ") + st.summary, style),
                key=spec.name,
            )
        table.move_cursor(row=min(row, table.row_count - 1))
        self.update_tool_buttons()

    def selected_tool(self) -> ToolSpec:
        table = self.query_one("#tools-table", DataTable)
        names = list(TOOLS)
        return TOOLS[names[min(max(table.cursor_row, 0), len(names) - 1)]]

    def update_tool_buttons(self) -> None:
        spec = self.selected_tool()
        st = tool_status(self.osint.settings, spec)
        sandbox = sandbox_status()
        info = Text.assemble((f"{spec.name}: ", "bold"), spec.homepage)
        if spec.note:
            info.append(f"\n{spec.note}", style="dim")
        info.append(
            f"\nПесочница: {sandbox.version or 'bwrap'} — "
            + ("работает" if sandbox.available else f"недоступна: {sandbox.reason}"),
            style="dim" if sandbox.available else "red",
        )
        self.query_one("#tools-info", Static).update(info)
        remove = self.query_one("#tool-remove", Button)
        remove.disabled = not st.path.exists()
        remove.label = f"Удалить {spec.name}"
        self.query_one("#tool-install", Button).label = (
            f"Переустановить {spec.name}" if st.installed else f"Установить {spec.name}"
        )

    @on(DataTable.RowHighlighted, "#tools-table")
    def tool_highlighted(self) -> None:
        self.update_tool_buttons()

    # ------------------------------------------------------------------ DB-IP
    @on(Button.Pressed, "#dbip-update")
    def update_pressed(self) -> None:
        self.update_dbip([dbip.DbipKind.COUNTRY, dbip.DbipKind.ASN])

    @on(Button.Pressed, "#dbip-city")
    def city_pressed(self) -> None:
        self.update_dbip([dbip.DbipKind.CITY])

    @work(exclusive=True, exit_on_error=False, group="dbip")
    async def update_dbip(self, kinds: list[dbip.DbipKind]) -> None:
        if self.osint.settings.offline:
            self.notify("Офлайн-режим: загрузка запрещена", severity="warning")
            return
        loading = self.query_one("#dbip-loading")
        loading.display = True
        http = HttpClient(self.osint.settings)
        try:
            remotes = [await dbip.find_remote(http, kind) for kind in kinds]
            detail = "\n".join(
                f"• {r.url.rsplit('/', 1)[-1]} — "
                + (f"{r.size / 2**20:.1f} МБ" if r.size else "размер неизвестен")
                for r in remotes
            )
            detail += (
                "\n\nИсточник: download.db-ip.com. Серверу виден только ваш IP-адрес; "
                "данные исследований не передаются.\n" + dbip.ATTRIBUTION
            )
            loading.display = False
            if not await self.app.push_screen_wait(
                ConfirmModal("Скачать базы DB-IP?", detail, yes="Скачать")
            ):
                return
            loading.display = True
            for remote in remotes:
                st = await dbip.download(http, remote, self.osint.settings.geo_dir)
                self.notify(
                    f"{remote.kind.value}: {st.version}, {st.size / 2**20:.1f} МБ",
                    title="База установлена",
                )
        except NetworkError as exc:
            self.notify(str(exc), title="Ошибка загрузки", severity="error", timeout=10)
        finally:
            await http.aclose()
            loading.display = False
            self.refresh_status()

    # ------------------------------------------------------------------ tools
    @on(Button.Pressed, "#tool-install")
    def tool_install_pressed(self) -> None:
        self.install_selected(self.selected_tool())

    @work(exclusive=True, exit_on_error=False, group="tools")
    async def install_selected(self, spec: ToolSpec) -> None:
        if self.osint.settings.offline:
            self.notify("Офлайн-режим: загрузка запрещена", severity="warning")
            return
        if not await self.app.push_screen_wait(
            ConfirmModal(
                f"Установить {spec.name} {spec.version}?",
                install_summary(self.osint.settings, spec),
                yes="Установить",
            )
        ):
            return
        loading = self.query_one("#tool-loading")
        loading.display = True
        self.query_one("#tool-install", Button).disabled = True
        try:
            status = await install_tool(self.osint.settings, spec)
            self.notify(f"{spec.name} {status.version} установлен", title="Готово")
        except (ToolError, SandboxError) as exc:
            self.notify(str(exc), title="Установка не удалась", severity="error", timeout=12)
        finally:
            loading.display = False
            self.query_one("#tool-install", Button).disabled = self.osint.settings.offline
            self.refresh_tools()

    @on(Button.Pressed, "#tool-remove")
    def tool_remove_pressed(self) -> None:
        spec = self.selected_tool()

        def answer(ok: bool | None) -> None:
            if not ok:
                return
            try:
                remove_tool(self.osint.settings, spec)
                self.notify(f"{spec.name} удалён")
            except ToolError as exc:
                self.notify(str(exc), title="Удаление не удалось", severity="error")
            self.refresh_tools()

        self.app.push_screen(
            ConfirmModal(
                f"Удалить {spec.name}?",
                f"Каталог инструмента будет удалён: {tool_status(self.osint.settings, spec).path}",
                yes="Удалить",
                danger=True,
            ),
            answer,
        )

    # ------------------------------------------------------------------ privacy housekeeping
    @on(Button.Pressed, "#revoke")
    def revoke_pressed(self) -> None:
        def answer(ok: bool | None) -> None:
            if ok:
                removed = self.osint.storage.revoke_consent()
                self.notify(f"Отозвано решений: {removed}")
                self.refresh_status()

        self.app.push_screen(
            ConfirmModal(
                "Отозвать все сохранённые согласия?",
                "Каждый внешний запрос снова будет подтверждаться отдельно.",
                yes="Отозвать",
            ),
            answer,
        )

    @on(Button.Pressed, "#purge-reports")
    def purge_pressed(self) -> None:
        directory = self.osint.settings.effective_reports_dir

        def answer(ok: bool | None) -> None:
            if ok:
                removed = purge_reports(directory)
                self.notify(f"Удалено файлов отчётов: {removed}")

        self.app.push_screen(
            ConfirmModal(
                "Удалить файлы отчётов?",
                f"Будут удалены только отчёты программы в {directory}.",
                yes="Удалить",
                danger=True,
            ),
            answer,
        )


LIMIT_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("verify_pages", "Проверка: обычные страницы", "0–300, 0 — не открывать"),
    ("verify_social", "Проверка: страницы соцсетей", "0–100"),
    ("verify_documents", "Проверка: документы PDF/DOCX", "0–100"),
    ("maigret_total_timeout", "Maigret: общий таймаут, с", "30–7200"),
)
_LIMIT_LABELS = {f: label for f, label, _ in LIMIT_FIELDS} | {
    "maigret_top_sites": "Maigret: сайтов (0 — вся база)"
}


def _limit_error(error: object) -> str:
    if not isinstance(error, dict):
        return str(error)
    loc = error.get("loc") or ("",)
    field = str(loc[0])
    ctx = error.get("ctx") or {}
    bounds = []
    for key, sign in (("ge", "≥"), ("gt", ">"), ("le", "≤"), ("lt", "<")):
        if key in ctx:
            bounds.append(f"{sign} {ctx[key]}")
    return f"{_LIMIT_LABELS.get(field, field)}: допустимо {' и '.join(bounds) or 'другое значение'}"


__all__ = ["SettingsScreen", "Vertical"]

"""External CLI tools as modules, declared in ``plugins.toml`` — no code changes needed.

File: ``~/.config/osint-toolkit/plugins.toml`` (or ``OSINT_PLUGINS_FILE``). Each ``[[plugin]]``
becomes a module ``plugin.<name>`` that runs the tool **inside the bwrap sandbox**:

* the plugin folder (``dir``) and the extra ``read_only`` paths are mounted read-only, a
  throw-away ``/work`` is writable and is the working and home directory; nothing else of $HOME
  (settings, keys, history) is visible;
* network only if ``network = true`` — then the module is "external": the consent dialog shows
  the plugin's declared ``services``, and offline mode skips it;
* the command is an argv list (no shell). Placeholders ``{value}``, ``{type}``, ``{dir}`` are
  replaced with plain strings; the value is also in ``OSINT_TARGET_VALUE`` / ``OSINT_TARGET_TYPE``.
  Put ``"--"`` before ``"{value}"`` if the tool parses options;
* stdout must be JSON (one document) or JSON Lines; ``[plugin.output]`` maps the tool's fields
  (dotted paths). Items with an http(s) ``url`` appear in «Где замечен»; ``verify = true``
  opens those pages and confirms the identifier like the built-in search does.

Safety checks before anything runs: the file and the plugin folder must belong to you and must
not be writable by other users; the executable must lie inside the folder, ``/usr`` or a
declared ``read_only`` path (otherwise it would not exist in the sandbox anyway).
"""

from __future__ import annotations

import asyncio
import grp
import json
import os
import pwd
import re
import shutil
import tempfile
import tomllib
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from osint_toolkit.config import Settings, config_dir, ensure_private_dir
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    Finding,
    JsonValue,
    ModuleStatus,
    Target,
    TargetType,
)
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.sandbox import (
    SandboxError,
    SandboxPolicy,
    SandboxTimeoutError,
    run_sandboxed,
    sandbox_status,
)
from osint_toolkit.search.resources import classify
from osint_toolkit.search.verify import Check, PageVerifier
from osint_toolkit.tools.manager import base_interpreter_prefix

PLUGINS_ENV = "OSINT_PLUGINS_FILE"
PLACEHOLDERS = ("{value}", "{type}", "{dir}")
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")
MAX_ITEMS = 500
MAX_OUTPUT = 8 * 1024 * 1024
MAX_VERIFY = 30
PAGES_SERVICE = ExternalService(
    name="Сайты из результатов плагина",
    url="страницы, которые вернул плагин",
    data_sent="обычный запрос страницы (без JavaScript, с учётом robots.txt); сайты видят ваш IP",
)


class PluginError(ValueError):
    pass


# --------------------------------------------------------------------------- configuration
class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)
    url: str = Field(min_length=1)
    data_sent: str = Field(min_length=1)


class OutputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["json", "jsonl"] = "json"
    items: str = "findings"  # dotted path to the list of results ("" = the document itself)
    url: str = "url"
    title: str = "title"
    text: str = "text"
    value: str = ""  # field to show for items without url ("" = the whole item)
    confidence: Literal["unverified", "likely"] = "unverified"
    verify: bool = False  # open returned URLs and confirm the identifier on the page


class PluginSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,39}$")
    title: str = Field(min_length=1, max_length=120)
    description: str = ""
    types: list[TargetType] = Field(min_length=1)
    dir: Path
    command: list[str] = Field(min_length=1)
    network: bool = False
    services: list[ServiceSpec] = Field(default_factory=list)
    timeout: float = Field(default=120.0, gt=0, le=3600)
    read_only: list[Path] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    default: bool = False  # include in Full Investigation (otherwise only with -m plugin.<name>)
    output: OutputSpec = Field(default_factory=OutputSpec)

    @field_validator("dir", "read_only", mode="before")
    @classmethod
    def _expand(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [Path(str(v)).expanduser() for v in value]
        return Path(str(value)).expanduser()

    @field_validator("command")
    @classmethod
    def _placeholders(cls, value: list[str]) -> list[str]:
        for part in value:
            unknown = [p for p in _PLACEHOLDER_RE.findall(part) if p not in PLACEHOLDERS]
            if unknown:
                raise ValueError(f"неизвестные подстановки {unknown}; доступны {PLACEHOLDERS}")
        return value

    @field_validator("env")
    @classmethod
    def _env_names(cls, value: dict[str, str]) -> dict[str, str]:
        bad = [k for k in value if not re.match(r"^[A-Z_][A-Z0-9_]*$", k) or k.startswith("OSINT_")]
        if bad:
            raise ValueError(f"недопустимые имена переменных: {bad}")
        return value


PLUGINS_TEMPLATE = """\
# Внешние инструменты-плагины osint-toolkit (формат: docs/PLUGINS.md в репозитории).
# Каждый [[plugin]] становится модулем plugin.<name> и запускается в песочнице bwrap.
# Файл и папки плагинов должны принадлежать вам и не быть доступны другим на запись.
#
# [[plugin]]
# name = "links_example"
# title = "Пример: ссылки для ручной проверки"
# description = "Демонстрационный плагин из examples/plugins/links_example"
# types = ["phone", "email", "name", "username"]
# dir = "~/osint-plugins/links_example"
# command = ["/usr/bin/python3", "-I", "{dir}/plugin.py", "{type}", "--", "{value}"]
# network = false        # true — песочница с сетью, нужно согласие; перечислите services
# default = false        # true — запускать в Full Investigation, иначе: -m plugin.links_example
# timeout = 60
#
# [plugin.output]
# format = "json"        # или "jsonl"
# items = "findings"     # путь к списку результатов в JSON ("" — весь документ)
# url = "url"            # поля внутри элемента (через точку: "links.0.href")
# title = "title"
# text = "text"
# confidence = "unverified"
# verify = false         # true — открыть найденные URL и подтвердить идентификатор
"""


def init_plugins_file(path: Path | None = None) -> tuple[Path, bool]:
    """Create plugins.toml from the commented template (mode 0600). Returns (path, created)."""
    target = path or plugins_file()
    if target.exists():
        return target, False
    ensure_private_dir(target.parent)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(PLUGINS_TEMPLATE)
    return target, True


def plugins_file() -> Path:
    custom = os.environ.get(PLUGINS_ENV)
    return Path(custom).expanduser() if custom else config_dir() / "plugins.toml"


def _private_group(gid: int) -> bool:
    """Ubuntu-style user private group: your primary group with no other members."""
    try:
        group = grp.getgrgid(gid)
    except KeyError:
        return False
    return gid == os.getgid() and not [
        m for m in group.gr_mem if m != pwd.getpwuid(os.getuid()).pw_name
    ]


def _private(path: Path, what: str) -> None:
    """Refuse files/folders that another user could modify (they would inject commands)."""
    info = path.stat()
    if info.st_uid != os.getuid():
        raise PluginError(f"{what} {path} принадлежит другому пользователю")
    writable_by_group = bool(info.st_mode & 0o020) and not _private_group(info.st_gid)
    if info.st_mode & 0o002 or writable_by_group:
        raise PluginError(f"{what} {path} доступен для записи другим: chmod go-w {path}")


def command_for(spec: PluginSpec, target: Target) -> list[str]:
    replacements = {
        "{value}": target.normalized,
        "{type}": target.type.value,
        "{dir}": str(spec.dir),
    }
    out = []
    for part in spec.command:
        for key, val in replacements.items():
            part = part.replace(key, val)
        out.append(part)
    return out


def sandbox_mounts_for(spec: PluginSpec) -> tuple[Path, ...]:
    """Plugin folder, declared paths and the base interpreter of a venv inside the folder."""
    mounts = [spec.dir.resolve(), *(p.resolve() for p in spec.read_only)]
    for venv in (spec.dir, spec.dir / ".venv", spec.dir / "venv"):
        prefix = base_interpreter_prefix(venv)
        if prefix is not None and not prefix.is_relative_to("/usr") and prefix not in mounts:
            mounts.append(prefix)
    return tuple(dict.fromkeys(mounts))


def check_spec(spec: PluginSpec) -> None:
    if not spec.dir.is_absolute() or not spec.dir.is_dir():
        raise PluginError(f"папка плагина не найдена: {spec.dir}")
    _private(spec.dir, "Папка плагина")
    for path in spec.read_only:
        if not path.is_absolute() or not path.exists():
            raise PluginError(f"read_only: путь не найден: {path}")
    executable = Path(spec.command[0].replace("{dir}", str(spec.dir)))
    if "{value}" in spec.command[0] or not executable.is_absolute():
        raise PluginError("command[0] должен быть абсолютным путём к программе")
    roots = [Path("/usr"), *sandbox_mounts_for(spec)]
    if not any(executable.resolve().is_relative_to(root) for root in roots):
        raise PluginError(
            f"{executable} вне папки плагина, /usr и read_only — в песочнице его не будет"
        )
    if not executable.exists():
        raise PluginError(f"программа не найдена: {executable}")


def load_plugins(path: Path | None = None) -> tuple[list[PluginSpec], list[tuple[str, str]]]:
    """(valid specs, [(plugin or file, error)]). A missing file means "no plugins"."""
    path = path or plugins_file()
    if not path.is_file():
        return [], []
    try:
        _private(path, "Файл плагинов")
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, PluginError, tomllib.TOMLDecodeError) as exc:
        return [], [(str(path), str(exc))]
    raw = data.get("plugin", [])
    if not isinstance(raw, list):
        return [], [(str(path), "ожидается массив таблиц [[plugin]]")]
    specs: list[PluginSpec] = []
    errors: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw, 1):
        label = str(item.get("name", f"#{index}")) if isinstance(item, dict) else f"#{index}"
        try:
            spec = PluginSpec.model_validate(item)
            check_spec(spec)
            if spec.name in seen:
                raise PluginError("имя уже используется другим плагином")
        except (ValidationError, PluginError, OSError) as exc:
            errors.append((label, " ".join(str(exc).split())[:400]))
            continue
        seen.add(spec.name)
        specs.append(spec)
    return specs, errors


# --------------------------------------------------------------------------- output parsing
def dig(data: Any, path: str) -> Any:
    for key in [p for p in path.split(".") if p]:
        if isinstance(data, dict):
            data = data.get(key)
        elif isinstance(data, list) and key.isdigit() and int(key) < len(data):
            data = data[int(key)]
        else:
            return None
    return data


def parse_items(stdout: bytes, output: OutputSpec) -> list[Any]:
    text = stdout.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        if output.format == "jsonl":
            items: Any = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            items = dig(json.loads(text), output.items) if output.items else json.loads(text)
    except ValueError as exc:
        raise PluginError(f"плагин вернул не JSON: {exc}") from exc
    if items is None:
        return []
    listed: list[Any] = items if isinstance(items, list) else [items]
    return listed[:MAX_ITEMS]


def _json_value(value: Any, depth: int = 0) -> JsonValue:
    """Plugin output → bounded JSON value (strings cut, nesting limited)."""
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth > 4:
        return str(value)[:500]
    if isinstance(value, list):
        return [_json_value(v, depth + 1) for v in value[:100]]
    if isinstance(value, dict):
        return {str(k)[:100]: _json_value(v, depth + 1) for k, v in list(value.items())[:100]}
    return str(value)[:500]


# --------------------------------------------------------------------------- module
class PluginModule(BaseModule):
    """Base of the generated ``plugin.<name>`` modules (never registered itself)."""

    spec: ClassVar[PluginSpec]

    def enabled_by_default(self, settings: Settings) -> bool:
        return self.spec.default

    def availability(self, settings: Settings) -> Availability:
        status = sandbox_status()
        return Availability(True) if status.available else Availability(False, status.reason)

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        lines = ["команда в песочнице: " + " ".join(command_for(self.spec, target))]
        if self.spec.output.verify:
            lines.append(f"до {MAX_VERIFY} найденных страниц будут открыты для проверки")
        return tuple(lines)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        spec = self.spec
        settings = ctx.settings
        ensure_private_dir(settings.cache_dir)
        work = Path(tempfile.mkdtemp(prefix=f"plugin-{spec.name}-", dir=settings.cache_dir))
        try:
            policy = SandboxPolicy(
                network=spec.network,
                read_only=sandbox_mounts_for(spec),
                workdir=work,
                env={
                    **spec.env,
                    "OSINT_TARGET_TYPE": target.type.value,
                    "OSINT_TARGET_VALUE": target.normalized,
                },
            )
            try:
                result = await run_sandboxed(
                    policy, command_for(spec, target), limit_s=spec.timeout, max_output=MAX_OUTPUT
                )
            except SandboxTimeoutError as exc:
                raise TimeoutError(str(exc)) from exc
            except SandboxError as exc:
                out.errors.append(f"Песочница: {exc}")
                out.status = ModuleStatus.ERROR
                return out
        finally:
            await asyncio.to_thread(shutil.rmtree, work, True)
        if result.returncode != 0:
            out.errors.append(
                f"плагин завершился с кодом {result.returncode}: "
                f"{result.stderr_tail(4) or 'без сообщения'}"
            )
            out.status = ModuleStatus.ERROR
            return out
        if result.truncated:
            out.limitations.append(f"Вывод плагина обрезан до {MAX_OUTPUT // 2**20} МБ")
        try:
            items = parse_items(result.stdout, spec.output)
        except PluginError as exc:
            out.errors.append(str(exc))
            out.status = ModuleStatus.ERROR
            return out
        out.findings.extend(await self._findings(target, ctx, items))
        if not out.findings:
            out.status = ModuleStatus.NO_RESULTS
        return out

    async def _findings(
        self, target: Target, ctx: ModuleContext, items: list[Any]
    ) -> list[Finding]:
        spec, output = self.spec, self.spec.output
        confidence = Confidence(output.confidence)
        source = f"Плагин «{spec.title}»"
        urn = f"urn:osint-plugin:{spec.name}"
        pages: dict[str, dict[str, Any]] = {}
        plain: list[Any] = []
        for item in items:
            url = dig(item, output.url) if isinstance(item, dict) else None
            if isinstance(url, str) and url.startswith(("https://", "http://")) and len(url) < 2048:
                pages.setdefault(url, item)
            else:
                plain.append(item)
        checks = {}
        if output.verify and pages and ctx.net.enabled:
            verifier = PageVerifier(ctx.net, ctx.settings)
            urls = list(pages)[:MAX_VERIFY]
            results = await asyncio.gather(*(verifier.verify(target, u) for u in urls))
            checks = dict(zip(urls, results, strict=True))
        findings: list[Finding] = []
        for url, item in pages.items():
            check = checks.get(url)
            status = check.status if check else Check.UNCHECKED
            resource = check.resource if check else classify(url)
            text = dig(item, output.text)
            fragment = check.match.fragment if check and check.match else (text or "")
            value: dict[str, JsonValue] = {
                "url": url,
                "title": str(dig(item, output.title) or url)[:300],
                "site": resource.platform,
                "resource": resource.kind,
                "resource_label": resource.label,
                "platform": resource.platform,
                "doc_type": resource.doc_type,
                "verification": status.value,
                "verification_label": status.label,
                "location": check.location if check else None,
                "fragment": str(fragment)[:600],
                "provider": source,
                "raw": _json_value(item),
            }
            confirmed = status is Check.CONFIRMED and not (
                check and check.match and check.match.weak
            )
            findings.append(
                self.finding(
                    target,
                    f"plugin.{spec.name}",
                    value,
                    Confidence.LIKELY if confirmed else confidence,
                    source,
                    url,
                    f"Страницу вернул плагин «{spec.title}». Проверка: {status.label}"
                    + (f" — {check.detail}" if check and check.detail else "")
                    + ". Совпадение не устанавливает личность.",
                )
            )
        for item in plain:
            shown = dig(item, output.value) if output.value and isinstance(item, dict) else item
            if shown is None or shown == "" or shown == {} or shown == []:
                continue
            findings.append(
                self.finding(
                    target,
                    f"plugin.{spec.name}",
                    _json_value(shown),
                    confidence,
                    source,
                    urn,
                    f"Результат внешнего плагина «{spec.title}» ({spec.dir}); программа не "
                    "проверяла его. Достоверность — как указано в plugins.toml.",
                )
            )
        return findings


def make_module(spec: PluginSpec) -> type[PluginModule]:
    services: tuple[ExternalService, ...] = ()
    if spec.network:
        services = tuple(ExternalService(**s.model_dump()) for s in spec.services) or (
            ExternalService(
                name=f"Сеть плагина {spec.name}",
                url="сервисы не указаны в plugins.toml",
                data_sent="идентификатор передаётся внешней программе, которая может отправить "
                "его куда угодно",
            ),
        )
    if spec.output.verify:
        services = (*services, PAGES_SERVICE)
    attrs: dict[str, Any] = {
        "name": f"plugin.{spec.name}",
        "title": spec.title,
        "description": spec.description or f"Внешний инструмент из {spec.dir}",
        "target_types": frozenset(spec.types),
        "external_services": services,
        "timeout": spec.timeout + 30,
        "default_enabled": spec.default,
        "spec": spec,
        "limitations": (
            "Внешний плагин: его код и достоверность результатов на вашей ответственности; "
            "он работает в песочнице без доступа к домашнему каталогу"
            + (" и без сети." if not spec.network else "."),
        ),
    }
    return type(f"Plugin_{spec.name}", (PluginModule,), attrs)


def plugin_modules(
    path: Path | None = None,
) -> tuple[list[type[PluginModule]], list[tuple[str, str]]]:
    specs, errors = load_plugins(path)
    return [make_module(s) for s in specs], errors


__all__ = [
    "PluginError",
    "PluginSpec",
    "command_for",
    "init_plugins_file",
    "load_plugins",
    "make_module",
    "plugin_modules",
    "plugins_file",
]

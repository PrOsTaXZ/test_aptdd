"""Module discovery.

Built-in modules: every non-abstract :class:`BaseModule` subclass defined in a submodule of
``osint_toolkit.modules``. External modules: entry points in the ``osint_toolkit.modules`` group.
A module that fails to import is recorded in :attr:`ModuleRegistry.load_errors` and skipped — one
broken plugin never prevents the application from starting.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import re
from importlib.metadata import entry_points
from types import ModuleType

from osint_toolkit.core.models import Target, TargetType
from osint_toolkit.modules.base import BaseModule

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "osint_toolkit.modules"
_NAME_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
_REQUIRED_ATTRS = ("name", "title", "description", "target_types")


class RegistryError(ValueError):
    pass


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, BaseModule] = {}
        self.load_errors: dict[str, str] = {}

    # ------------------------------------------------------------------ registration
    def register(self, cls: type[BaseModule]) -> BaseModule:
        if not (inspect.isclass(cls) and issubclass(cls, BaseModule)) or inspect.isabstract(cls):
            raise RegistryError(f"{cls!r} is not a concrete BaseModule subclass")
        missing = [a for a in _REQUIRED_ATTRS if not hasattr(cls, a)]
        if missing:
            raise RegistryError(f"{cls.__name__} lacks required attributes: {missing}")
        if not _NAME_RE.match(cls.name):
            raise RegistryError(f"invalid module name {cls.name!r}")
        if not cls.target_types:
            raise RegistryError(f"{cls.name}: target_types is empty")
        if cls.name in self._modules:
            raise RegistryError(f"duplicate module name {cls.name!r}")
        instance = cls()
        self._modules[cls.name] = instance
        return instance

    def discover_builtin(self, package: str = "osint_toolkit.modules") -> None:
        root = importlib.import_module(package)
        for info in pkgutil.walk_packages(root.__path__, prefix=f"{package}."):
            if info.name.endswith(".base"):
                continue
            try:
                module = importlib.import_module(info.name)
            except Exception as exc:  # noqa: BLE001 - a broken module must not crash discovery
                self._record_error(info.name, exc)
                continue
            for cls in _concrete_modules(module):
                try:
                    self.register(cls)
                except RegistryError as exc:
                    self._record_error(f"{info.name}.{cls.__name__}", exc)

    def discover_entry_points(self) -> None:
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                self.register(ep.load())
            except Exception as exc:  # noqa: BLE001 - third-party code, isolate failures
                self._record_error(f"entry point {ep.name}", exc)

    def discover_plugins(self) -> None:
        """External CLI tools declared in plugins.toml (see :mod:`osint_toolkit.plugins`)."""
        from osint_toolkit.plugins import plugin_modules

        modules, errors = plugin_modules()
        for where, message in errors:
            self.load_errors[f"plugin {where}"] = message
        for cls in modules:
            try:
                self.register(cls)
            except RegistryError as exc:
                self._record_error(f"plugin {cls.name}", exc)

    def _record_error(self, where: str, exc: BaseException) -> None:
        log.warning("module load failed: %s: %s", where, exc)
        self.load_errors[where] = f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ queries
    def all(self) -> list[BaseModule]:
        return sorted(self._modules.values(), key=lambda m: m.name)

    def get(self, name: str) -> BaseModule | None:
        return self._modules.get(name)

    def for_type(self, target_type: TargetType) -> list[BaseModule]:
        return [m for m in self.all() if target_type in m.target_types]

    def for_target(self, target: Target) -> list[BaseModule]:
        return [m for m in self.all() if m.supports(target)]

    def __len__(self) -> int:
        return len(self._modules)


def _concrete_modules(module: ModuleType) -> list[type[BaseModule]]:
    return [
        obj
        for _, obj in inspect.getmembers(module, inspect.isclass)
        if issubclass(obj, BaseModule)
        and obj is not BaseModule
        and obj.__module__ == module.__name__
        and not inspect.isabstract(obj)
    ]


def load_registry(
    *, entry_points_enabled: bool = True, plugins_enabled: bool = True
) -> ModuleRegistry:
    registry = ModuleRegistry()
    registry.discover_builtin()
    if entry_points_enabled:
        registry.discover_entry_points()
    if plugins_enabled:
        registry.discover_plugins()
    return registry

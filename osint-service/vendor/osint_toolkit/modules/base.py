"""Module contract.

A module is a class with metadata (``name``, ``target_types``, ``external_services`` …) and one
coroutine, :meth:`BaseModule.run`. The engine handles timing, timeouts, cancellation, consent and
error capture, so modules contain only lookup logic.

Minimal example::

    class MxModule(BaseModule):
        name = "email.mx"
        title = "MX-записи домена"
        description = "..."
        target_types = frozenset({TargetType.EMAIL})

        async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
            out = ModuleOutput()
            out.findings.append(self.finding(target, "email.mx", [...], Confidence.CONFIRMED,
                                             "DNS", "dns:///example.com?type=MX", "MX-записи ..."))
            return out
"""

from __future__ import annotations

import logging
import shutil
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    Finding,
    JsonValue,
    ModuleStatus,
    Target,
    TargetType,
)
from osint_toolkit.net.services import DISABLED_NETWORK, NetworkServices

# progress(done, total or None, text) — e.g. (1500, 5900, "Проверено 1500 из 5900 сайтов")
ProgressFn = Callable[[int, int | None, str], None]


def _no_progress(done: int, total: int | None, text: str) -> None:
    return None


@dataclass(slots=True)
class ModuleContext:
    settings: Settings
    logger: logging.Logger
    net: NetworkServices = field(default_factory=lambda: DISABLED_NETWORK)
    progress: ProgressFn = _no_progress  # live progress of long modules (shown in the TUI)


@dataclass(slots=True)
class ModuleOutput:
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    status: ModuleStatus | None = None  # None → OK if findings else NO_RESULTS


@dataclass(frozen=True, slots=True)
class Availability:
    available: bool
    reason: str | None = None


class BaseModule(ABC):
    name: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    target_types: ClassVar[frozenset[TargetType]]
    external_services: ClassVar[tuple[ExternalService, ...]] = ()
    required_settings: ClassVar[tuple[str, ...]] = ()
    required_binaries: ClassVar[tuple[str, ...]] = ()
    default_enabled: ClassVar[bool] = True  # False → runs only when explicitly selected
    timeout: ClassVar[float | None] = None  # None → settings.module_timeout
    limitations: ClassVar[tuple[str, ...]] = ()  # always attached to the result

    @property
    def is_external(self) -> bool:
        return bool(self.external_services)

    def availability(self, settings: Settings) -> Availability:
        missing_settings = [s for s in self.required_settings if not settings.has(s)]
        if missing_settings:
            env = ", ".join(f"OSINT_{s.upper()}" for s in missing_settings)
            return Availability(False, f"не задано в .env: {env}")
        missing_bins = [b for b in self.required_binaries if shutil.which(b) is None]
        if missing_bins:
            return Availability(False, f"не установлено: {', '.join(missing_bins)}")
        return Availability(True)

    def supports(self, target: Target) -> bool:
        return target.type in self.target_types

    def services_for(self, settings: Settings) -> tuple[ExternalService, ...]:
        """External services actually contacted with these settings (shown in consent)."""
        return self.external_services

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        """Exact data that will be sent for ``target`` (e.g. search queries), for consent."""
        return ()

    def effective_timeout(self, settings: Settings) -> float:
        """Hard time limit for one run (engine-enforced)."""
        return self.timeout or settings.module_timeout

    def enabled_by_default(self, settings: Settings) -> bool:
        """Whether Full Investigation includes the module (``default_enabled`` unless a module
        decides from settings, e.g. manual links only when no automated search exists)."""
        return self.default_enabled

    def applicability(self, target: Target, settings: Settings) -> str | None:
        """Reason why the module is pointless for this target (e.g. a private IP), else None.
        Inapplicable runs are skipped without asking for consent."""
        return None

    def dedupe_key(self, target: Target) -> str:
        """Runs with equal keys are the same lookup; Full Investigation keeps only the first."""
        return target.key

    def finding(
        self,
        target: Target,
        attribute: str,
        value: JsonValue,
        confidence: Confidence,
        source_name: str,
        source_url: str,
        evidence: str,
        *,
        subject: str | None = None,
        exclusive: bool = False,
    ) -> Finding:
        return Finding(
            module=self.name,
            subject=subject or target.normalized,
            attribute=attribute,
            value=value,
            confidence=confidence,
            source_name=source_name,
            source_url=source_url,
            evidence=evidence,
            exclusive=exclusive,
        )

    @abstractmethod
    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        """Perform the lookup. Raise on failure; the engine records the error."""

"""Core engine: plan → consent → concurrent execution → processing → history.

* **Full Investigation** (:meth:`Engine.plan_full`): every default-enabled module compatible with
  the detected target, plus modules for related targets (e.g. the domain of an email).
* **Targeted** (:meth:`Engine.plan_targeted`): an explicit module subset.

Execution guarantees: per-module timeout, bounded concurrency, cooperative cancellation
(:meth:`Engine.cancel` returns partial results with remaining modules marked ``cancelled``), and
exceptions are captured per module — one failing module never aborts the investigation.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol

from osint_toolkit import __version__
from osint_toolkit.config import Settings
from osint_toolkit.core.detector import related_targets
from osint_toolkit.core.models import (
    ExternalRequest,
    Investigation,
    InvestigationMode,
    InvestigationStatus,
    ModuleResult,
    ModuleStatus,
    Target,
    utcnow,
)
from osint_toolkit.core.privacy import (
    ConsentDecision,
    ConsentProvider,
    PrivacyGate,
    request_key,
)
from osint_toolkit.core.registry import ModuleRegistry
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ProgressFn
from osint_toolkit.net import DISABLED_NETWORK, NetworkError, NetworkServices, NetworkTimeoutError
from osint_toolkit.processing.contradictions import detect_contradictions
from osint_toolkit.storage.db import Storage

log = logging.getLogger(__name__)


class PlanError(ValueError):
    pass


class ProgressListener(Protocol):
    def on_planned(self, plan: Plan) -> None: ...
    def on_module_started(self, module: BaseModule, target: Target) -> None: ...
    def on_module_finished(self, result: ModuleResult) -> None: ...


class NullListener:
    def on_planned(self, plan: Plan) -> None:
        pass

    def on_module_progress(
        self, module: BaseModule, target: Target, done: int, total: int | None, text: str
    ) -> None:
        pass

    def on_module_started(self, module: BaseModule, target: Target) -> None:
        pass

    def on_module_finished(self, result: ModuleResult) -> None:
        pass


@dataclass(slots=True)
class PlannedRun:
    module: BaseModule
    target: Target
    availability: Availability
    skip_reason: str | None = None  # module not applicable to this target (no consent asked)

    @property
    def key(self) -> str:
        return f"{self.module.name}@{self.target.key}"


@dataclass(slots=True)
class Plan:
    mode: InvestigationMode
    query: str
    target: Target
    related: list[Target] = field(default_factory=list)
    runs: list[PlannedRun] = field(default_factory=list)

    def external_requests(self, settings: Settings) -> list[ExternalRequest]:
        return [
            _request_of(run, settings)
            for run in self.runs
            if run.availability.available and run.module.is_external and not run.skip_reason
        ]


class Engine:
    def __init__(
        self,
        settings: Settings,
        registry: ModuleRegistry,
        *,
        consent: ConsentProvider,
        storage: Storage | None = None,
        listener: ProgressListener | None = None,
        network_factory: Callable[[Settings], NetworkServices] | None = None,
    ) -> None:
        self.settings = settings
        self._network_factory = network_factory or NetworkServices
        self.registry = registry
        self.storage = storage
        self.listener: ProgressListener = listener or NullListener()
        self._gate = PrivacyGate(consent, storage=storage, offline=settings.offline)
        self._cancel_requested = False
        self._cancel_event: asyncio.Event | None = None

    # ------------------------------------------------------------------ planning
    def _runs_for(self, target: Target, modules: Sequence[BaseModule]) -> list[PlannedRun]:
        return [
            PlannedRun(
                m, target, m.availability(self.settings), m.applicability(target, self.settings)
            )
            for m in modules
        ]

    def plan_full(self, target: Target, query: str | None = None) -> Plan:
        plan = Plan(InvestigationMode.FULL, query or target.raw, target)
        plan.related = related_targets(target)
        seen: set[tuple[str, str]] = set()
        for tgt in (target, *plan.related):
            modules = []
            for module in self.registry.for_target(tgt):
                # e.g. MX for "a@x.org" and for the related domain "x.org" is the same lookup
                key = (module.name, module.dedupe_key(tgt))
                if module.enabled_by_default(self.settings) and key not in seen:
                    seen.add(key)
                    modules.append(module)
            plan.runs.extend(self._runs_for(tgt, modules))
        return plan

    def plan_targeted(
        self,
        target: Target,
        modules: Sequence[str] | None = None,
        *,
        exclude: Sequence[str] = (),
        query: str | None = None,
    ) -> Plan:
        selected: list[BaseModule] = []
        if modules:
            for name in modules:
                module = self.registry.get(name)
                if module is None:
                    raise PlanError(f"Неизвестный модуль: {name}")
                if not module.supports(target):
                    raise PlanError(f"Модуль {name} не поддерживает тип «{target.type.label}»")
                selected.append(module)
        else:
            selected = [
                m for m in self.registry.for_target(target) if m.enabled_by_default(self.settings)
            ]
        unknown = [n for n in exclude if self.registry.get(n) is None]
        if unknown:
            raise PlanError(f"Неизвестный модуль: {', '.join(unknown)}")
        selected = [m for m in selected if m.name not in exclude]
        plan = Plan(InvestigationMode.TARGETED, query or target.raw, target)
        plan.runs = self._runs_for(target, selected)
        return plan

    # ------------------------------------------------------------------ execution
    def cancel(self) -> None:
        """Request cancellation. Safe to call from a signal handler or another task."""
        self._cancel_requested = True
        if self._cancel_event is not None:
            self._cancel_event.set()

    async def authorize(self, plan: Plan) -> dict[str, ConsentDecision]:
        """Ask for consent for every external request in the plan (no module runs yet)."""
        return await self._gate.authorize(plan.external_requests(self.settings))

    async def execute(
        self, plan: Plan, decisions: dict[str, ConsentDecision] | None = None
    ) -> Investigation:
        """Run the plan. Pass ``decisions`` from :meth:`authorize` to separate the consent step
        (interactive) from execution (cancellable); otherwise consent is requested here."""
        self._cancel_requested = False
        self._cancel_event = asyncio.Event()
        investigation = Investigation(
            mode=plan.mode,
            query=plan.query,
            target=plan.target,
            related_targets=list(plan.related),
            offline=self.settings.offline,
            app_version=__version__,
        )
        self.listener.on_planned(plan)
        log.info("investigation %s started: %d planned runs", investigation.id, len(plan.runs))

        if decisions is None:
            decisions = await self.authorize(plan)
        investigation.consent = {k: d.allowed for k, d in decisions.items()}

        results: dict[str, ModuleResult] = {}
        runnable: list[PlannedRun] = []
        for run in plan.runs:
            if run.skip_reason:
                results[run.key] = self._result(run, ModuleStatus.SKIPPED, errors=[run.skip_reason])
                continue
            if not run.availability.available:
                results[run.key] = self._result(
                    run, ModuleStatus.NOT_CONFIGURED, errors=[run.availability.reason or ""]
                )
                continue
            if run.module.is_external:
                decision = decisions.get(request_key(_request_of(run, self.settings)))
                if decision is None or not decision.allowed:
                    reason = decision.reason if decision else "нет согласия"
                    results[run.key] = self._result(run, ModuleStatus.SKIPPED, errors=[reason])
                    continue
            runnable.append(run)

        for result in results.values():
            self.listener.on_module_finished(result)

        if self._cancel_requested:
            for run in runnable:
                results[run.key] = self._result(run, ModuleStatus.CANCELLED)
                self.listener.on_module_finished(results[run.key])
        else:
            results.update(await self._run_all(runnable))

        investigation.results = [results[run.key] for run in plan.runs]
        investigation.contradictions = detect_contradictions(investigation.findings())
        investigation.finished_at = utcnow()
        if self._cancel_requested:
            investigation.status = InvestigationStatus.CANCELLED
        self._cancel_event = None
        self._save(investigation)
        log.info("investigation %s finished: %s", investigation.id, investigation.status.value)
        return investigation

    async def _run_all(self, runs: list[PlannedRun]) -> dict[str, ModuleResult]:
        if self._cancel_event is None:  # pragma: no cover - guarded by execute()
            raise RuntimeError("_run_all called outside execute()")
        if not runs:
            return {}
        semaphore = asyncio.Semaphore(self.settings.max_concurrency)
        logger = logging.getLogger("osint_toolkit.modules")
        # Network clients exist only if an allowed external module runs; every other module gets
        # a context whose network raises NetworkDisabledError.
        net = (
            self._network_factory(self.settings)
            if not self.settings.offline and any(r.module.is_external for r in runs)
            else None
        )
        offline_ctx = ModuleContext(self.settings, logger, DISABLED_NETWORK)
        online_ctx = ModuleContext(self.settings, logger, net) if net else offline_ctx
        tasks = {
            run.key: asyncio.create_task(
                self._guarded(
                    run, online_ctx if run.module.is_external else offline_ctx, semaphore
                ),
                name=run.key,
            )
            for run in runs
        }
        try:
            return await self._wait_all(runs, tasks)
        finally:
            if net is not None:
                await net.aclose()

    async def _wait_all(
        self, runs: list[PlannedRun], tasks: dict[str, asyncio.Task[ModuleResult]]
    ) -> dict[str, ModuleResult]:
        if self._cancel_event is None:  # pragma: no cover - guarded by execute()
            raise RuntimeError("_wait_all called outside execute()")
        watcher = asyncio.create_task(self._cancel_event.wait())
        pending: set[asyncio.Task[object]] = set(tasks.values())
        try:
            while pending:
                done, _ = await asyncio.wait(
                    pending | {watcher}, return_when=asyncio.FIRST_COMPLETED
                )
                pending -= done
                if watcher in done:
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    break
        except asyncio.CancelledError:
            # The caller (e.g. a UI worker) was cancelled: stop children, then propagate.
            for task in tasks.values():
                task.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)
            raise
        finally:
            watcher.cancel()

        out: dict[str, ModuleResult] = {}
        for run in runs:
            task = tasks[run.key]
            if task.cancelled():
                out[run.key] = self._result(run, ModuleStatus.CANCELLED)
                self.listener.on_module_finished(out[run.key])
            else:
                out[run.key] = task.result()
        return out

    async def _guarded(
        self, run: PlannedRun, ctx: ModuleContext, semaphore: asyncio.Semaphore
    ) -> ModuleResult:
        started: datetime | None = None
        ctx = replace(ctx, progress=self._progress_for(run))
        try:
            async with semaphore:
                started = utcnow()
                self.listener.on_module_started(run.module, run.target)
                timeout = run.module.effective_timeout(self.settings)
                try:
                    async with asyncio.timeout(timeout):
                        output = await run.module.run(run.target, ctx)
                except TimeoutError:
                    result = self._result(
                        run,
                        ModuleStatus.TIMEOUT,
                        started=started,
                        errors=[f"Превышено время ожидания ({timeout:g} с)"],
                    )
                except NetworkTimeoutError as exc:
                    result = self._result(
                        run, ModuleStatus.TIMEOUT, started=started, errors=[str(exc)]
                    )
                except NetworkError as exc:
                    log.warning("module %s network error: %s", run.module.name, type(exc).__name__)
                    result = self._result(
                        run, ModuleStatus.ERROR, started=started, errors=[str(exc)]
                    )
                except Exception as exc:
                    log.error(
                        "module %s failed: %s",
                        run.module.name,
                        type(exc).__name__,
                        exc_info=self.settings.log_level == "DEBUG",
                    )
                    result = self._result(
                        run,
                        ModuleStatus.ERROR,
                        started=started,
                        errors=[f"{type(exc).__name__}: {exc}"],
                    )
                else:
                    status = output.status or (
                        ModuleStatus.OK if output.findings else ModuleStatus.NO_RESULTS
                    )
                    result = self._result(
                        run,
                        status,
                        started=started,
                        errors=output.errors,
                        limitations=output.limitations,
                    )
                    result.findings = list(output.findings)
        except asyncio.CancelledError:
            result = self._result(run, ModuleStatus.CANCELLED, started=started)
        self.listener.on_module_finished(result)
        return result

    def _progress_for(self, run: PlannedRun) -> ProgressFn:
        """Forward a module's live progress to listeners that implement on_module_progress
        (optional: the CLI listener and test listeners may lack it)."""
        callback = getattr(self.listener, "on_module_progress", None)

        def report(done: int, total: int | None, text: str) -> None:
            if callback is None:
                return
            try:
                callback(run.module, run.target, done, total, text)
            except Exception:  # a UI problem must never break a module
                log.debug("progress listener failed", exc_info=True)

        return report

    def _result(
        self,
        run: PlannedRun,
        status: ModuleStatus,
        *,
        started: datetime | None = None,
        errors: Sequence[str] = (),
        limitations: Sequence[str] = (),
    ) -> ModuleResult:
        return ModuleResult(
            module=run.module.name,
            module_title=run.module.title,
            target=run.target,
            status=status,
            started_at=started,
            finished_at=utcnow() if started is not None else None,
            errors=[e for e in errors if e],
            limitations=[*run.module.limitations, *limitations],
            external_services=list(run.module.services_for(self.settings)),
        )

    def _save(self, investigation: Investigation) -> None:
        if self.storage is None:
            return
        try:
            self.storage.save(investigation)
        except (sqlite3.Error, OSError) as exc:
            log.error("history save failed: %s", exc)
            investigation.warnings.append(f"Не удалось сохранить в историю: {exc}")


def _request_of(run: PlannedRun, settings: Settings) -> ExternalRequest:
    return ExternalRequest(
        module=run.module.name,
        module_title=run.module.title,
        target=run.target,
        services=run.module.services_for(settings),
        details=run.module.request_details(run.target, settings),
    )

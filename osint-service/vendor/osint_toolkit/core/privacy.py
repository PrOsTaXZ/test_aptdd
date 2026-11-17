"""Privacy gate: nothing leaves the machine without explicit consent.

Before any module that declares ``external_services`` runs, the gate collects one
:class:`ExternalRequest` per (module, target) and asks a :class:`ConsentProvider` (Rich prompt in
the CLI, a dialog in the TUI). Unanswered requests are denied. A decision may be remembered per
module; remembered decisions live in the history DB and can be revoked (``osint consent revoke``).
Offline mode denies everything without asking.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from osint_toolkit.core.models import ExternalRequest
from osint_toolkit.storage.db import Storage

log = logging.getLogger(__name__)


def request_key(request: ExternalRequest) -> str:
    return f"{request.module}@{request.target.key}"


@dataclass(frozen=True, slots=True)
class ConsentAnswer:
    allowed: bool
    remember: bool = False


@dataclass(frozen=True, slots=True)
class ConsentDecision:
    allowed: bool
    reason: str  # shown in the module result when denied


class ConsentProvider(Protocol):
    async def ask(self, requests: Sequence[ExternalRequest]) -> Mapping[str, ConsentAnswer]:
        """Answers keyed by :func:`request_key`. Missing keys count as denial."""
        ...


class DenyAll:
    """Default provider for non-interactive use: every external request is refused."""

    async def ask(self, requests: Sequence[ExternalRequest]) -> Mapping[str, ConsentAnswer]:
        return {}


class AllowModules:
    """Allows only the modules the user named explicitly (``--allow``); ``"all"`` allows all."""

    def __init__(self, modules: Sequence[str]) -> None:
        self._modules = frozenset(modules)

    async def ask(self, requests: Sequence[ExternalRequest]) -> Mapping[str, ConsentAnswer]:
        return {
            request_key(r): ConsentAnswer(True)
            for r in requests
            if "all" in self._modules or r.module in self._modules
        }


class PrivacyGate:
    def __init__(
        self, provider: ConsentProvider, *, storage: Storage | None = None, offline: bool = False
    ) -> None:
        self._provider = provider
        self._storage = storage
        self._offline = offline

    async def authorize(self, requests: Sequence[ExternalRequest]) -> dict[str, ConsentDecision]:
        decisions: dict[str, ConsentDecision] = {}
        if not requests:
            return decisions
        if self._offline:
            return {
                request_key(r): ConsentDecision(False, "офлайн-режим: внешние запросы запрещены")
                for r in requests
            }

        remembered = self._remembered()
        pending: list[ExternalRequest] = []
        for request in requests:
            if request.module in remembered:
                allowed = remembered[request.module]
                reason = "сохранённое разрешение" if allowed else "запрещено сохранённым решением"
                decisions[request_key(request)] = ConsentDecision(allowed, reason)
            else:
                pending.append(request)

        if pending:
            answers = await self._provider.ask(pending)
            for request in pending:
                answer = answers.get(request_key(request))
                if answer is None or not answer.allowed:
                    decisions[request_key(request)] = ConsentDecision(
                        False, "нет согласия на отправку данных внешнему сервису"
                    )
                else:
                    decisions[request_key(request)] = ConsentDecision(
                        True, "разрешено пользователем"
                    )
                if answer is not None and answer.remember and self._storage is not None:
                    try:
                        self._storage.set_consent(request.module, answer.allowed)
                    except sqlite3.Error as exc:
                        log.error("could not remember consent: %s", exc)
        return decisions

    def _remembered(self) -> dict[str, bool]:
        # An unreadable DB means "nothing remembered": the user is asked, never silently allowed.
        if self._storage is None:
            return {}
        try:
            return self._storage.consents()
        except sqlite3.Error as exc:
            log.error("could not read remembered consents: %s", exc)
            return {}

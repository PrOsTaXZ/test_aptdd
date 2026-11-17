"""Offline disposable (temporary) email domain check.

Data: the community blocklist from github.com/disposable-email-domains (CC0 list, MIT package),
shipped as a Python set — lookups are local. Parent domains are checked too, so
``x.mailinator.com`` matches ``mailinator.com``.
"""

from __future__ import annotations

from functools import cache
from importlib.metadata import version

from disposable_email_domains import blocklist

from osint_toolkit.core.models import Confidence, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput

LIST_URL = "https://github.com/disposable-email-domains/disposable-email-domains"


@cache
def _blocklist() -> frozenset[str]:
    return frozenset(d.strip().lower() for d in blocklist if d.strip())


def find_disposable_match(domain: str) -> str | None:
    """The listed domain matching ``domain`` or one of its parents (never a bare TLD)."""
    labels = domain.lower().rstrip(".").split(".")
    domains = _blocklist()
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in domains:
            return candidate
    return None


class DisposableEmailModule(BaseModule):
    name = "email.disposable"
    title = "Одноразовые почтовые домены"
    description = "Проверка домена по открытому списку сервисов временной почты (офлайн)."
    target_types = frozenset({TargetType.EMAIL})
    limitations = (
        "Список поддерживается сообществом и неполон: отсутствие домена в списке не доказывает, "
        "что сервис не одноразовый.",
    )

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = str(target.details.get("domain") or target.normalized.rpartition("@")[2])
        source = (
            f"disposable-email-domains {version('disposable-email-domains')} "
            f"({len(_blocklist())} доменов)"
        )
        match = find_disposable_match(domain)
        if match is not None:
            via = "" if match == domain else f" (через родительский домен {match})"
            out.findings.append(
                self.finding(
                    target,
                    "email.disposable",
                    True,
                    Confidence.CONFIRMED,
                    source,
                    LIST_URL,
                    f"Домен {domain}{via} присутствует в списке сервисов временной почты.",
                    exclusive=True,
                )
            )
        else:
            out.findings.append(
                self.finding(
                    target,
                    "email.disposable",
                    False,
                    Confidence.UNVERIFIED,
                    source,
                    LIST_URL,
                    f"Домен {domain} не найден в списке сервисов временной почты.",
                    exclusive=True,
                )
            )
        return out

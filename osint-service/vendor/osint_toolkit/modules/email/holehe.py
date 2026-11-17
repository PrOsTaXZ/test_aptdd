"""holehe self-audit (GPL-3.0, github.com/megadose/holehe): on which sites is MY address used?

Strictly limited:

* only for addresses declared your own (``--own``, TUI switch, ``OSINT_OWN_EMAILS``) — for any
  other address the module is skipped without asking for consent;
* opt-in (not part of Full Investigation; select it explicitly);
* runs holehe's site checks via our own runner in the bwrap sandbox: no self-update, no
  password-recovery checks, bounded concurrency and timeouts.

holehe is unmaintained since 2022–2024: site checks can be outdated, so hits are ``likely`` and
"not found" is never reported as a fact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    JsonValue,
    ModuleStatus,
    Target,
    TargetType,
)
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.email.gravatar import is_declared_own
from osint_toolkit.net import NetworkError, NetworkTimeoutError
from osint_toolkit.sandbox import SandboxError, SandboxPolicy, SandboxTimeoutError, run_sandboxed
from osint_toolkit.tools import HOLEHE, tool_status
from osint_toolkit.tools.manager import sandbox_mounts

RUNNER_DEST = "/opt/osint/holehe_runner.py"


def runner_path() -> Path:
    return Path(str(resources.files("osint_toolkit.tools.runners") / "holehe_runner.py"))


@dataclass(frozen=True, slots=True)
class HoleheOutput:
    checked: int
    used: list[dict[str, Any]]
    # holehe sets ``rateLimit`` both for real rate limiting and when a check catches its own
    # error (no network, changed site): either way the result is unknown.
    rate_limited: list[str]
    failed: list[str]  # the check raised: network error or outdated check

    @property
    def unknown(self) -> list[str]:
        return sorted({*self.rate_limited, *self.failed})


def parse_output(data: Any) -> HoleheOutput:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("неожиданный формат вывода holehe")
    used: list[dict[str, Any]] = []
    limited: list[str] = []
    failed: list[str] = []
    for item in data["results"]:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or item.get("name") or "?")
        if item.get("error"):
            failed.append(domain)
        elif item.get("rateLimit"):
            limited.append(domain)
        elif item.get("exists") is True:
            used.append(item)
    checked = data.get("checked")
    return HoleheOutput(
        checked if isinstance(checked, int) else len(data["results"]),
        used,
        sorted(limited),
        sorted(failed),
    )


class HoleheSelfAuditModule(BaseModule):
    name = "email.holehe"
    title = "Где используется мой адрес (holehe)"
    description = (
        "Самопроверка: на каких сайтах зарегистрирован ВАШ адрес (по ответам форм регистрации и "
        "входа ~120 сайтов). Только для вашего адреса, включается вручную, в песочнице."
    )
    target_types = frozenset({TargetType.EMAIL})
    default_enabled = False
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="~120 сайтов из списка holehe",
            url="соцсети, магазины, сервисы",
            data_sent="ваш email в открытом виде — в формы проверки регистрации; "
            "сайты видят ваш IP",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "holehe не обновлялся с 2022 года: проверки части сайтов устарели, возможны пропуски и "
        "ложные срабатывания. «Не найден» не означает, что аккаунта нет.",
        "Проверки через восстановление пароля отключены, чтобы не отправлять письма на адрес.",
    )

    def applicability(self, target: Target, settings: Settings) -> str | None:
        if is_declared_own(target, settings):
            return None
        return (
            "проверяется только для вашего собственного адреса: флаг --own в CLI, "
            "переключатель «Это мой адрес» в TUI или OSINT_OWN_EMAILS"
        )

    def availability(self, settings: Settings) -> Availability:
        status = tool_status(settings, HOLEHE)
        return Availability(True) if status.ready else Availability(False, status.problem)

    def effective_timeout(self, settings: Settings) -> float:
        return settings.holehe_total_timeout + 15

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        return (
            f"Адрес «{target.normalized}» будет отправлен в формы ~120 сайтов "
            f"(не более {settings.holehe_max_connections} одновременно)",
        )

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        reason = self.applicability(target, settings)
        status = tool_status(settings, HOLEHE)
        if reason or not status.ready or status.python is None or not ctx.net.enabled:
            out.errors.append(reason or status.problem or "сетевой доступ не разрешён")
            return out
        policy = SandboxPolicy(
            network=True,
            read_only=sandbox_mounts(status.path),
            mapped_read_only=((runner_path(), RUNNER_DEST),),
        )
        argv = [
            str(status.python),
            "-I",
            RUNNER_DEST,
            "--timeout",
            f"{settings.holehe_timeout:g}",
            "--max-connections",
            str(settings.holehe_max_connections),
            "--",
            target.normalized,
        ]
        try:
            result = await run_sandboxed(policy, argv, limit_s=settings.holehe_total_timeout)
        except SandboxTimeoutError as exc:
            raise NetworkTimeoutError(str(exc)) from exc
        except SandboxError as exc:
            raise NetworkError(f"Песочница: {exc}") from exc
        if result.returncode != 0:
            raise NetworkError(
                f"holehe завершился с кодом {result.returncode}: "
                f"{result.stderr_tail(4) or 'без сообщения'}"
            )
        try:
            parsed = parse_output(json.loads(result.stdout or b"null"))
        except ValueError as exc:
            raise NetworkError(f"Некорректный вывод holehe: {exc}") from exc
        checked, used, unknown = parsed.checked, parsed.used, parsed.unknown
        if checked and not used and len(parsed.rate_limited) + len(parsed.failed) >= checked:
            raise NetworkError(
                f"holehe не смог проверить ни одного из {checked} сайтов (нет сети, ограничение "
                "частоты или проверки устарели)"
            )
        add = out.findings.append
        add(
            self.finding(
                target,
                "email.registration_scope",
                {"sites_checked": checked, "used": len(used), "unknown": len(unknown)},
                Confidence.CONFIRMED,
                f"holehe {HOLEHE.version}",
                HOLEHE.homepage,
                f"Проверено сайтов: {checked}; адрес найден на {len(used)}; результат "
                f"неизвестен для {len(unknown)} (ограничение частоты или ошибка проверки).",
                exclusive=True,
            )
        )
        for item in used:
            domain = str(item.get("domain") or item.get("name"))
            value: dict[str, JsonValue] = {"site": domain, "method": item.get("method")}
            for key, label in (
                ("emailrecovery", "recovery_email_masked"),
                ("phoneNumber", "recovery_phone_masked"),
            ):
                if item.get(key):
                    value[label] = str(item[key])
            add(
                self.finding(
                    target,
                    "email.registered_site",
                    value,
                    Confidence.LIKELY,
                    f"holehe {HOLEHE.version} → {domain}",
                    f"https://{domain}",
                    f"Ответ формы {item.get('method') or 'проверки'} сайта {domain} "
                    "указывает, что адрес зарегистрирован (эвристика holehe; проверки "
                    "могли устареть)."
                    + (
                        " Сайт раскрыл замаскированные контакты восстановления."
                        if len(value) > 2
                        else ""
                    ),
                )
            )
        if unknown:
            out.limitations.append(
                "Результат неизвестен (сайт ограничил частоту запросов или проверка завершилась "
                f"ошибкой): {', '.join(unknown[:20])}"
                + (f" и ещё {len(unknown) - 20}" if len(unknown) > 20 else "")
            )
        if not used:
            out.status = ModuleStatus.NO_RESULTS
        return out

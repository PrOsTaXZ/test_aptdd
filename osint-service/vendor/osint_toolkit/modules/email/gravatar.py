"""Gravatar self-audit: what Gravatar publicly shows for YOUR OWN email address.

Runs only for addresses the user declared as their own (``--own`` / TUI switch, or
``OSINT_OWN_EMAILS``); for any other address the module is skipped without asking for consent.
Uses only public, unauthenticated endpoints:

* avatar existence — ``https://gravatar.com/avatar/<sha256>?d=404`` (404 = no avatar);
* public profile — ``https://api.gravatar.com/v3/profiles/<sha256>`` (404 = no profile;
  unauthenticated limit 100 requests/hour).

The email is never sent in clear text, only its SHA-256 hash (trimmed, lower-cased), as Gravatar
specifies. A hash of a guessable address is not secret, which is why the consent text says so.
"""

from __future__ import annotations

import hashlib
from typing import Any, ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Confidence, ExternalService, JsonValue, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.net import HttpStatusError, NetworkError

AVATAR_URL = "https://gravatar.com/avatar/{hash}?d=404&s=80"
PROFILE_URL = "https://api.gravatar.com/v3/profiles/{hash}"
PUBLIC_FIELDS = {
    "display_name": "Отображаемое имя",
    "location": "Местоположение",
    "description": "Описание",
    "job_title": "Должность",
    "company": "Компания",
    "pronouns": "Местоимения",
    "profile_url": "Страница профиля",
}


def gravatar_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def is_declared_own(target: Target, settings: Settings) -> bool:
    return bool(target.details.get("declared_own")) or settings.is_own_email(target.normalized)


class GravatarSelfAuditModule(BaseModule):
    name = "email.gravatar"
    title = "Gravatar (только для вашего адреса)"
    description = (
        "Проверяет, что Gravatar публично показывает для ВАШЕГО адреса: есть ли аватар и "
        "публичный профиль, какие поля в нём видны всем."
    )
    target_types = frozenset({TargetType.EMAIL})
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="Gravatar (Automattic)",
            url="https://gravatar.com",
            data_sent="SHA-256 хеш вашего адреса (не сам адрес)",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "Профиль Gravatar находится только по основному адресу аккаунта; дополнительные адреса "
        "аккаунта не дают профиля.",
        "Хеш угадываемого адреса не является секретом: любой, кто знает адрес, может выполнить "
        "ту же проверку — поэтому полезно знать, что видно публично.",
    )

    def applicability(self, target: Target, settings: Settings) -> str | None:
        if is_declared_own(target, settings):
            return None
        return (
            "проверяется только для вашего собственного адреса: флаг --own в CLI, "
            "переключатель «Это мой адрес» в TUI или OSINT_OWN_EMAILS"
        )

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        digest = gravatar_hash(target.normalized)
        return (f"GET {AVATAR_URL.format(hash=digest)}", f"GET {PROFILE_URL.format(hash=digest)}")

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        reason = self.applicability(target, ctx.settings)
        if reason is not None:  # defence in depth; the engine already skips such runs
            out.errors.append(f"Gravatar {reason}")
            return out
        digest = gravatar_hash(target.normalized)
        avatar_url = AVATAR_URL.format(hash=digest)
        profile_url = PROFILE_URL.format(hash=digest)
        add = out.findings.append
        try:
            await ctx.net.http.fetch(avatar_url, max_bytes=512 * 1024, retries=1)
            has_avatar = True
        except HttpStatusError as exc:
            if exc.status_code != 404:
                raise
            has_avatar = False
        add(
            self.finding(
                target,
                "gravatar.avatar_public",
                has_avatar,
                Confidence.CONFIRMED,
                "Gravatar avatar",
                avatar_url,
                "Gravatar отдаёт аватар для хеша этого адреса — он виден любому, кто знает адрес."
                if has_avatar
                else "Gravatar ответил 404: публичного аватара для этого адреса нет.",
                exclusive=True,
            )
        )
        try:
            profile = await ctx.net.http.get_json(profile_url, retries=1)
        except HttpStatusError as exc:
            if exc.status_code == 404:
                add(
                    self.finding(
                        target,
                        "gravatar.profile_public",
                        False,
                        Confidence.CONFIRMED,
                        "Gravatar Profiles API v3",
                        profile_url,
                        "API ответил 404: публичного профиля для этого адреса нет.",
                        exclusive=True,
                    )
                )
                return out
            if exc.status_code == 429:
                raise NetworkError(
                    "Gravatar: превышен лимит (100 запросов в час без ключа)"
                ) from exc
            raise
        if not isinstance(profile, dict):
            raise NetworkError("Gravatar вернул неожиданный формат профиля")
        add(
            self.finding(
                target,
                "gravatar.profile_public",
                True,
                Confidence.CONFIRMED,
                "Gravatar Profiles API v3",
                profile_url,
                "Для адреса существует публичный профиль Gravatar.",
                exclusive=True,
            )
        )
        visible = _public_fields(profile)
        if visible:
            add(
                self.finding(
                    target,
                    "gravatar.public_fields",
                    visible,
                    Confidence.CONFIRMED,
                    "Gravatar Profiles API v3",
                    profile_url,
                    "Поля, которые Gravatar показывает любому без авторизации. "
                    "Проверьте, что вы готовы показывать их публично.",
                )
            )
        accounts = [a for a in profile.get("verified_accounts") or [] if isinstance(a, dict)]
        if accounts:
            linked: list[JsonValue] = [
                {
                    "service": str(a.get("service_label") or a.get("service_type") or "?"),
                    "url": str(a.get("url") or ""),
                }
                for a in accounts
            ]
            add(
                self.finding(
                    target,
                    "gravatar.verified_accounts",
                    linked,
                    Confidence.CONFIRMED,
                    "Gravatar Profiles API v3",
                    profile_url,
                    "Аккаунты, которые вы сами подтвердили в Gravatar; они публично "
                    "связывают этот адрес с ними (без ключа API видно не более 4).",
                )
            )
        return out


def _public_fields(profile: dict[str, Any]) -> dict[str, JsonValue]:
    visible: dict[str, JsonValue] = {}
    for key, label in PUBLIC_FIELDS.items():
        value = profile.get(key)
        if isinstance(value, str) and value.strip():
            visible[label] = value.strip()[:300]
    return visible

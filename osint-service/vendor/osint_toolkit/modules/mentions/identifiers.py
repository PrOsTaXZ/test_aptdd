"""Mention modules for email addresses, phone numbers and full names (separate modules)."""

from __future__ import annotations

import re
from typing import ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Target, TargetType
from osint_toolkit.dorks import email_variants, name_variants
from osint_toolkit.modules.mentions._base import MentionModule

LIMIT_NAME = (
    "Совпадение ФИО часто означает однофамильца: без дополнительных независимых признаков "
    "упоминание нельзя связывать с конкретным человеком."
)


class EmailMentionsModule(MentionModule):
    name = "mentions.email"
    title = "Публичные упоминания email"
    description = (
        "Дорки по адресу и его записям вида «user at domain»: точная фраза, соцсети, документы, "
        "paste-сайты, репозитории, форумы."
    )
    target_types = frozenset({TargetType.EMAIL})
    attribute = "mention.email"
    noun = "адрес"
    limitations: ClassVar[tuple[str, ...]] = (
        "Поисковики индексируют не всё: отсутствие упоминаний не означает, что адрес нигде "
        "не публиковался.",
    )

    def snippet_contains(self, target: Target, text: str) -> bool:
        folded = " ".join(text.casefold().split())
        return any(v.casefold() in folded for v in email_variants(target.normalized))


class PhoneMentionsModule(MentionModule):
    name = "mentions.phone"
    title = "Публичные упоминания телефона"
    description = (
        "Дорки по всем распространённым записям номера (слитно, с 8, с кодом страны, со скобками "
        "и дефисами): соцсети, объявления, сайты «кто звонил», документы, paste-сайты."
    )
    target_types = frozenset({TargetType.PHONE})
    attribute = "mention.phone"
    noun = "номер"
    limitations: ClassVar[tuple[str, ...]] = (
        "Номера переназначаются операторами: старое упоминание может относиться к прежнему "
        "владельцу номера.",
    )

    def applicability(self, target: Target, settings: Settings) -> str | None:
        if not target.details.get("region_known"):
            return "страна номера неизвестна — укажите номер с «+» или задайте OSINT_DEFAULT_REGION"
        return None

    def snippet_contains(self, target: Target, text: str) -> bool:
        national = str(target.details.get("national_number") or "")
        if len(national) < 6:
            return False
        digits_runs = re.findall(r"[\d][\d\s().\-]{5,24}\d", text)
        return any(re.sub(r"\D", "", run).endswith(national) for run in digits_runs)


class NameMentionsModule(MentionModule):
    name = "mentions.name"
    title = "Публичные упоминания ФИО"
    description = (
        "Дорки по вариантам ФИО: порядок слов, инициалы, отчество, латиница (ICAO и "
        "распространённая); соцсети, документы, форумы."
    )
    target_types = frozenset({TargetType.NAME})
    attribute = "mention.name"
    noun = "сочетание слов ФИО"
    limitations: ClassVar[tuple[str, ...]] = (LIMIT_NAME,)

    def snippet_contains(self, target: Target, text: str) -> bool:
        folded = " ".join(text.casefold().replace("ё", "е").split())
        variants = [v for v in name_variants(target.normalized) if not v.endswith(".")]
        return any(" ".join(v.casefold().replace("ё", "е").split()) in folded for v in variants)

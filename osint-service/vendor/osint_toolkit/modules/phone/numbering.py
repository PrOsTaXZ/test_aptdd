"""Offline phone number analysis using libphonenumber metadata (``phonenumbers``, Apache-2.0).

Everything comes from the bundled numbering-plan metadata, so results describe the *number range*
(country, type, region, original carrier allocation) — not the subscriber. No network access.
"""

from __future__ import annotations

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from osint_toolkit.core.models import Confidence, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput

LIBPHONENUMBER_URL = "https://github.com/google/libphonenumber"

NUMBER_TYPE_LABELS: dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "стационарный",
    PhoneNumberType.MOBILE: "мобильный",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "стационарный или мобильный",
    PhoneNumberType.TOLL_FREE: "бесплатный (toll-free)",
    PhoneNumberType.PREMIUM_RATE: "платный (premium rate)",
    PhoneNumberType.SHARED_COST: "с разделением стоимости",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "персональный номер",
    PhoneNumberType.PAGER: "пейджер",
    PhoneNumberType.UAN: "единый номер организации (UAN)",
    PhoneNumberType.VOICEMAIL: "голосовая почта",
    PhoneNumberType.UNKNOWN: "неизвестен",
}


def _source() -> str:
    return f"libphonenumber metadata (phonenumbers {phonenumbers.__version__})"


class PhoneNumberingModule(BaseModule):
    name = "phone.numbering"
    title = "Анализ номера телефона"
    description = (
        "Валидность, страна, тип номера, географическая зона, исходный оператор диапазона и "
        "часовые пояса по метаданным libphonenumber (офлайн)."
    )
    target_types = frozenset({TargetType.PHONE})
    limitations = (
        "Оператор указан по исходному выделению номерного диапазона. Из-за переносимости номеров "
        "(MNP) текущий оператор может отличаться.",
        "Данные описывают номерной диапазон, а не владельца номера, и не устанавливают личность.",
    )

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        if not target.details.get("region_known"):
            self._unknown_region(target, out)
            return out
        try:
            number = phonenumbers.parse(target.normalized, None)
        except phonenumbers.NumberParseException as exc:
            out.errors.append(f"Не удалось разобрать номер: {exc}")
            return out
        self._analyse(target, number, out)
        return out

    # ------------------------------------------------------------------ helpers
    def _unknown_region(self, target: Target, out: ModuleOutput) -> None:
        out.limitations.append(
            "Номер записан без «+» и без региона: страну определить нельзя. Укажите номер в "
            "формате +<код страны> или задайте OSINT_DEFAULT_REGION."
        )
        digits = str(target.details.get("digits") or target.normalized)
        try:
            candidate = phonenumbers.parse("+" + digits, None)
        except phonenumbers.NumberParseException:
            return
        if phonenumbers.is_valid_number(candidate):
            e164 = phonenumbers.format_number(candidate, PhoneNumberFormat.E164)
            region = phonenumbers.region_code_for_number(candidate)
            out.findings.append(
                self.finding(
                    target,
                    "phone.possible_international",
                    e164,
                    Confidence.UNVERIFIED,
                    _source(),
                    LIBPHONENUMBER_URL,
                    f"Если цифры — международный номер без «+», он корректен как {e164} "
                    f"(регион {region}). Это лишь одна из возможных интерпретаций.",
                )
            )

    def _analyse(self, target: Target, number: phonenumbers.PhoneNumber, out: ModuleOutput) -> None:
        src = _source()
        add = out.findings.append
        valid = phonenumbers.is_valid_number(number)
        possible = phonenumbers.is_possible_number(number)
        if valid:
            evidence = "Номер попадает в выделенный диапазон плана нумерации своей страны."
        elif possible:
            evidence = (
                "Длина номера допустима, но он не попадает ни в один известный выделенный "
                "диапазон (возможно, опечатка или диапазон ещё не в метаданных)."
            )
        else:
            evidence = "Номер невозможен для плана нумерации этой страны (неверная длина)."
        add(
            self.finding(
                target,
                "phone.valid",
                valid,
                Confidence.CONFIRMED,
                src,
                LIBPHONENUMBER_URL,
                evidence,
                exclusive=True,
            )
        )

        formats = {
            "e164": phonenumbers.format_number(number, PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL),
            "rfc3966": phonenumbers.format_number(number, PhoneNumberFormat.RFC3966),
        }
        add(
            self.finding(
                target,
                "phone.formats",
                formats,
                Confidence.CONFIRMED,
                src,
                LIBPHONENUMBER_URL,
                "Стандартные форматы записи номера.",
                exclusive=True,
            )
        )

        code = number.country_code or 0
        shared = phonenumbers.region_codes_for_country_code(code)
        region = phonenumbers.region_code_for_number(number)
        add(
            self.finding(
                target,
                "phone.country_code",
                f"+{code}",
                Confidence.CONFIRMED,
                src,
                LIBPHONENUMBER_URL,
                f"Код страны +{code}"
                + (f"; используется регионами: {', '.join(shared)}." if len(shared) > 1 else "."),
                exclusive=True,
            )
        )
        if not valid:
            out.limitations.append(
                "Номер не валиден: страна, тип и оператор по неизвестному диапазону "
                "не определяются."
            )
            return

        country = geocoder.country_name_for_number(number, "ru") or region
        add(
            self.finding(
                target,
                "phone.region",
                {"code": region, "name": country},
                Confidence.CONFIRMED,
                src,
                LIBPHONENUMBER_URL,
                f"Диапазон номера относится к плану нумерации региона {region}"
                + (
                    " (код страны общий с другими регионами, регион определён по диапазону)."
                    if len(shared) > 1
                    else "."
                ),
                exclusive=True,
            )
        )

        number_type = phonenumbers.number_type(number)
        add(
            self.finding(
                target,
                "phone.number_type",
                NUMBER_TYPE_LABELS.get(number_type, "неизвестен"),
                Confidence.CONFIRMED,
                src,
                LIBPHONENUMBER_URL,
                "Тип определён по номерному диапазону.",
                exclusive=True,
            )
        )

        area = geocoder.description_for_number(number, "ru")
        if area and area != country:
            add(
                self.finding(
                    target,
                    "phone.geographic_area",
                    area,
                    Confidence.CONFIRMED,
                    src,
                    LIBPHONENUMBER_URL,
                    "Номерной диапазон закреплён за этой географической зоной. Это "
                    "не местоположение абонента.",
                    exclusive=True,
                )
            )

        operator = carrier.name_for_number(number, "ru") or carrier.name_for_number(number, "en")
        if operator:
            add(
                self.finding(
                    target,
                    "phone.allocated_carrier",
                    operator,
                    Confidence.CONFIRMED,
                    src,
                    LIBPHONENUMBER_URL,
                    f"Диапазон был выделен оператору «{operator}». Текущий оператор "
                    "может отличаться из-за переноса номера.",
                    exclusive=True,
                )
            )
        elif number_type in (PhoneNumberType.MOBILE, PhoneNumberType.FIXED_LINE_OR_MOBILE):
            out.limitations.append("Для этого диапазона в метаданных нет данных об операторе.")

        zones = [z for z in timezone.time_zones_for_number(number) if z != "Etc/Unknown"]
        if zones:
            evidence = "Часовые пояса, соответствующие номерному диапазону."
            if len(zones) > 3:
                evidence += (
                    f" Диапазон охватывает {len(zones)} пояса(ов) — значение малоинформативно."
                )
            add(
                self.finding(
                    target,
                    "phone.time_zones",
                    zones,
                    Confidence.CONFIRMED,
                    src,
                    LIBPHONENUMBER_URL,
                    evidence,
                )
            )

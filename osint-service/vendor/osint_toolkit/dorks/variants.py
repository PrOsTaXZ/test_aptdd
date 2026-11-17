"""Spelling variants of one identifier, as people actually write it on the web.

Variants are only alternative spellings of the *same* identifier (``77777777777`` vs
``8 (777) 777-77-77``); nothing here derives a different identifier (an email's local part is
never turned into a username, a phone never into a name).

:func:`search_signature` reduces a variant to what search engines index (word/number tokens),
so ``+7 777 777 77 77`` and ``7-777-777-77-77`` count as one query, while ``77777777777`` and
``8 777 777 77 77`` stay different.
"""

from __future__ import annotations

import re

import phonenumbers
from phonenumbers import PhoneNumberFormat

from osint_toolkit.core.models import Target, TargetType

MAX_PHONE_VARIANTS = 14
MAX_NAME_VARIANTS = 14
_TOKEN_RE = re.compile(r"[\w@.]+", re.UNICODE)
PATRONYMIC_RE = re.compile(
    r"(вич|вна|ична|инична|оглы|кызы|улы|qizi|ovich|evich|ovna|evna)$", re.IGNORECASE
)

# Transliteration: ICAO Doc 9303 (Russian passports since 2014) and the common "popular" style.
_ICAO = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "g",
    "д": "d",
    "е": "e",
    "ё": "e",
    "ж": "zh",
    "з": "z",
    "и": "i",
    "й": "i",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": "kh",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "shch",
    "ъ": "ie",
    "ы": "y",
    "ь": "",
    "э": "e",
    "ю": "iu",
    "я": "ia",
    "і": "i",
    "ї": "i",
    "є": "ie",
    "ґ": "g",
    "қ": "k",
    "ғ": "g",
    "ң": "n",
    "ү": "u",
    "ұ": "u",
    "ө": "o",
    "һ": "h",
    "ә": "a",
}
_POPULAR = {
    **_ICAO,
    "й": "y",
    "х": "h",
    "ю": "yu",
    "я": "ya",
    "ъ": "",
    "ё": "yo",
    "щ": "sch",
    "ц": "c",
    "ы": "y",
}


def search_signature(text: str) -> tuple[str, ...]:
    """Tokens a search engine would match (punctuation, '+', brackets ignored)."""
    return tuple(t.casefold() for t in _TOKEN_RE.findall(text.replace("ё", "е").replace("Ё", "Е")))


def _unique(values: list[str], limit: int) -> list[str]:
    seen: set[tuple[str, ...]] = set()
    out: list[str] = []
    for value in values:
        value = " ".join(value.split())
        signature = search_signature(value)
        if value and signature and signature not in seen:
            seen.add(signature)
            out.append(value)
    return out[:limit]


# --------------------------------------------------------------------------- phone
def phone_variants(e164: str) -> list[str]:
    """Common written forms of a phone number, most canonical first."""
    number = phonenumbers.parse(e164, None)
    cc = str(number.country_code)
    nsn = phonenumbers.national_significant_number(number)
    region = phonenumbers.region_code_for_number(number)
    metadata = phonenumbers.PhoneMetadata.metadata_for_region(region) if region else None
    trunk = metadata.national_prefix if metadata is not None else None
    forms = [
        f"{cc}{nsn}",  # engines ignore "+", so this also covers "+<cc><nsn>"
        phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL),
        phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL),
    ]
    if trunk:
        forms.append(f"{trunk}{nsn}")
    if len(nsn) == 10:
        a, b, rest = nsn[:3], nsn[3:6], nsn[6:]
        c, d = rest[:2], rest[2:]
        leads = [f"+{cc}"] + ([trunk] if trunk else [])
        if cc == "1":  # NANP: 3-3-4
            forms += [f"({a}) {b}-{rest}", f"{a}-{b}-{rest}", f"{a}.{b}.{rest}", f"{a}{b}{rest}"]
        else:  # +7 and similar: 3-3-2-2
            for lead in leads:
                forms += [
                    f"{lead} {a} {b} {c} {d}",
                    f"{lead} ({a}) {b}-{c}-{d}",
                    f"{lead} {a} {b}{c}{d}",
                    f"{lead}({a}){b}{c}{d}",
                ]
            forms += [f"({a}) {b}-{c}-{d}", f"{a} {b} {c} {d}", nsn]
    return _unique(forms, MAX_PHONE_VARIANTS)


# --------------------------------------------------------------------------- name
def transliterate(text: str, table: dict[str, str] | None = None) -> str:
    table = table or _ICAO
    out = []
    for char in text:
        lower = char.lower()
        if lower in table:
            latin = table[lower]
            out.append(latin.capitalize() if char.isupper() and latin else latin)
        else:
            out.append(char)
    return "".join(out)


def _is_cyrillic(text: str) -> bool:
    return any("Ѐ" <= ch <= "ӿ" for ch in text)


def _orders(words: list[str]) -> list[tuple[str, str, str | None]]:
    """Possible (surname, given name, patronymic) readings of the typed words."""
    if len(words) == 2:
        first, second = words
        return [(second, first, None), (first, second, None)]
    if len(words) == 3:
        a, b, c = words
        if PATRONYMIC_RE.search(c):
            return [(a, b, c)]  # Фамилия Имя Отчество
        if PATRONYMIC_RE.search(b):
            return [(c, a, b)]  # Имя Отчество Фамилия
        return [(a, b, c), (c, a, b)]
    return []


def name_variants(name: str) -> list[str]:
    """Word orders, initials and transliterations of a full name."""
    words = name.split()
    forms = [name]
    for surname, given, patronymic in _orders(words):
        i = f"{given[0]}."
        if patronymic:
            io = f"{given[0]}.{patronymic[0]}."
            forms += [
                f"{surname} {given} {patronymic}",
                f"{given} {patronymic} {surname}",
                f"{surname} {io}",
                f"{io} {surname}",
                f"{given} {surname}",
                f"{surname} {given}",
            ]
        else:
            forms += [
                f"{given} {surname}",
                f"{surname} {given}",
                f"{surname} {i}",
                f"{i} {surname}",
            ]
    if _is_cyrillic(name):
        base = [f for f in forms[:3]]
        for form in base:
            forms.append(transliterate(form, _ICAO))
            forms.append(transliterate(form, _POPULAR))
        if "ё" in name.lower():
            forms.append(name.replace("ё", "е").replace("Ё", "Е"))
    return _unique(forms, MAX_NAME_VARIANTS)


# --------------------------------------------------------------------------- email / username
def email_variants(email: str) -> list[str]:
    """The address and its common anti-spam spellings."""
    local, _, domain = email.rpartition("@")
    dotted = domain.replace(".", " dot ")
    forms = [
        email,
        f"{local} at {domain}",
        f"{local} [at] {domain}",
        f"{local}(at){domain}",
        f"{local} at {dotted}",
        f"{local} собака {domain}",
    ]
    seen: set[str] = set()
    out = []
    for form in forms:  # signatures would merge "x at y" forms, so dedupe on exact text here
        key = form.casefold()
        if key not in seen:
            seen.add(key)
            out.append(form)
    return out


def username_variants(username: str) -> list[str]:
    return list(dict.fromkeys([username, f"@{username}"]))


def variants_for(target: Target) -> list[str]:
    match target.type:
        case TargetType.PHONE:
            if not target.details.get("region_known"):
                return [target.normalized]
            return phone_variants(target.normalized)
        case TargetType.NAME:
            return name_variants(target.normalized)
        case TargetType.EMAIL:
            return email_variants(target.normalized)
        case TargetType.USERNAME:
            return username_variants(target.normalized)
        case _:
            return [target.normalized]

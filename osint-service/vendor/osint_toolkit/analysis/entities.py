"""Entity extraction from downloaded text (pages, documents, social posts).

Regular expressions and heuristics — no external models, no network. The extractor recognises:

* **ФИО** — Cyrillic full names with a patronymic (any word order, Kazakh -ұлы/-қызы too),
  surname-plus-initials forms, two-word names with a typical surname suffix, names after a label
  ("ФИО:", "Директор:", "Author:") and Latin names after an honorific or with a middle initial;
* **Email** — plain and bracket-obfuscated ("user [at] mail [dot] kz") addresses;
* **Телефон** — numbers that libphonenumber considers *valid* for the default region (KZ unless
  set otherwise), so +7 7xx, 8 7xx and local formats are all normalised to E.164;
* **Username** — ``@handle`` mentions, profile links of popular networks, "ник:"/"login:" labels;
* **Дата рождения** — a date (or a year) only next to a birth cue ("дата рождения", "г.р.",
  "родился", "born", "DOB", "туған күні");
* **Организация** — legal forms (ООО, ТОО, АО, ИП, LLC, Ltd, JSC…) with the organisation name;
* **Адрес** — a street with a house number or a city ("г. Алматы, ул. Абая, д. 10, кв. 5").

Heuristics produce false positives and miss things; every entity therefore carries the text
around it (``context``) and how it was recognised (``basis``). An entity found on a page says only
that the text contains it — never that it belongs to the person being researched.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import date

import phonenumbers

from osint_toolkit.core.models import JsonValue, Target, TargetType
from osint_toolkit.search.matching import find_identifier, fold, fragment_around

CONTEXT_CHARS = 90
DEFAULT_LIMIT = 40
WINDOW_CHARS = 700  # text taken on each side of an identifier occurrence
MAX_WINDOWS = 12


class EntityType(enum.StrEnum):
    NAME = "name"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    BIRTHDATE = "birthdate"
    ORGANIZATION = "organization"
    ADDRESS = "address"

    @property
    def label(self) -> str:
        return ENTITY_LABELS[self]


ENTITY_LABELS = {
    EntityType.NAME: "ФИО",
    EntityType.EMAIL: "Email",
    EntityType.PHONE: "Телефон",
    EntityType.USERNAME: "Username",
    EntityType.BIRTHDATE: "Дата рождения",
    EntityType.ORGANIZATION: "Организация",
    EntityType.ADDRESS: "Адрес",
}
ORDER = tuple(EntityType)


@dataclass(frozen=True, slots=True)
class Entity:
    type: EntityType
    value: str  # canonical form: lower-case email, E.164 phone, ISO date, cleaned text
    context: str  # text around the entity
    basis: str  # how it was recognised
    platform: str | None = None  # username: network the profile link points to
    url: str | None = None  # username: profile link
    is_target: bool = False  # the researched identifier itself

    @property
    def key(self) -> str:
        return f"{self.type.value}:{entity_key(self.type, self.value, self.platform)}"

    @property
    def display(self) -> str:
        return display_value(self.type, self.value, self.platform)

    def to_json(self) -> dict[str, JsonValue]:
        data: dict[str, JsonValue] = {
            "type": self.type.value,
            "value": self.value,
            "context": self.context,
            "basis": self.basis,
        }
        if self.platform:
            data["platform"] = self.platform
        if self.url:
            data["url"] = self.url
        if self.is_target:
            data["is_target"] = True
        return data


def entity_key(kind: EntityType, value: str, platform: str | None = None) -> str:
    folded = fold(" ".join(value.split()))
    if kind is EntityType.NAME:
        return " ".join(sorted(re.sub(r"[.,]", " ", folded).split()))
    if kind in (EntityType.ORGANIZATION, EntityType.ADDRESS):
        return " ".join(re.sub(r"[«»\"“”„',.]", " ", folded).split())
    if kind is EntityType.USERNAME:
        return folded.lstrip("@")
    return folded


def display_value(kind: EntityType, value: str, platform: str | None = None) -> str:
    if kind is EntityType.PHONE:
        try:
            number = phonenumbers.parse(value, None)
        except phonenumbers.NumberParseException:
            return value
        return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    if kind is EntityType.BIRTHDATE and len(value) == 10:
        year, month, day = value.split("-")
        return f"{day}.{month}.{year}"
    if kind is EntityType.BIRTHDATE:
        return f"{value} г."
    if kind is EntityType.USERNAME:
        return f"@{value}" + (f" ({platform})" if platform else "")
    return value


def entities_to_json(entities: Iterable[Entity]) -> list[JsonValue]:
    return [e.to_json() for e in entities]


def entities_from_json(data: object) -> list[Entity]:
    """Tolerant reader for entities stored in a finding value (unknown items are skipped)."""
    if not isinstance(data, list):
        return []
    out: list[Entity] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            kind = EntityType(str(item.get("type")))
        except ValueError:
            continue
        value = item.get("value")
        if not isinstance(value, str) or not value:
            continue
        platform, url = item.get("platform"), item.get("url")
        out.append(
            Entity(
                kind,
                value,
                str(item.get("context") or ""),
                str(item.get("basis") or ""),
                platform if isinstance(platform, str) else None,
                url if isinstance(url, str) else None,
                bool(item.get("is_target")),
            )
        )
    return out


def data_type_label(kinds: Iterable[EntityType]) -> str:
    """«Тип данных» for a page: one type, «Смешанные данные (…)» or «—»."""
    present = [k for k in ORDER if k in set(kinds)]
    if not present:
        return "—"
    if len(present) == 1:
        return present[0].label
    return "Смешанные данные (" + ", ".join(k.label for k in present) + ")"


# --------------------------------------------------------------------------- patterns
def _words(*chunks: str) -> list[str]:
    return "".join(chunks).split()


_UP = "А-ЯЁӘҒҚҢӨҰҮҺІ"
_LO = "а-яёәғқңөұүһі"
_CAP = rf"[{_UP}][{_LO}]+(?:-[{_UP}][{_LO}]+)?"
_PATR = rf"[{_UP}][{_LO}]+(?:ович|евич|ьич|ична|инична|овна|евна|улы|ұлы|кызы|қызы)"
_INIT = rf"[{_UP}]\.\s?[{_UP}]\.?"
_UPPER_SURNAME = rf"[{_UP}]{{3,}}(?:-[{_UP}]{{3,}})?"  # "ИВАНОВ Иван Иванович" in documents
_LCAP = r"[A-Z][a-z]+(?:[-'][A-Z][a-z]+)?"

_NAME_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(rf"(?<!\w)({_CAP}\s+{_CAP}\s+{_PATR})(?!\w)"), "фамилия, имя, отчество"),
    (re.compile(rf"(?<!\w)({_CAP}\s+{_PATR}\s+{_CAP})(?!\w)"), "имя, отчество, фамилия"),
    (
        re.compile(rf"(?<!\w)({_UPPER_SURNAME}\s+{_CAP}\s+{_PATR})(?!\w)"),
        "ФАМИЛИЯ, имя, отчество",
    ),
    (re.compile(rf"(?<!\w)({_CAP}\s+{_PATR})(?!\w)"), "имя и отчество"),
    (re.compile(rf"(?<!\w)({_CAP}\s+{_INIT})(?!\w)"), "фамилия и инициалы"),
    (re.compile(rf"(?<![\w.])({_INIT}\s?{_CAP})(?!\w)"), "инициалы и фамилия"),
    (
        re.compile(
            r"(?<![\w.])(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+("
            + _LCAP
            + r"(?:\s+"
            + _LCAP
            + r"){0,2})(?!\w)"
        ),
        "обращение (Mr/Dr…)",
    ),
    (re.compile(rf"(?<!\w)({_LCAP}\s+[A-Z]\.\s+{_LCAP})(?!\w)"), "имя, инициал, фамилия"),
)
_LABEL_NAME = re.compile(
    r"(?:ФИО|Ф\.\s?И\.\s?О\.|Автор|Директор|Генеральный\s+директор|Руководитель|Контактное\s+"
    r"лицо|Учредитель|Name|Full\s+name|Author|Contact\s+person|CEO|Director|Founder)"
    rf"\s*[:\-–—]\s*((?:{_CAP}|{_LCAP})(?:\s+(?:{_CAP}|{_LCAP})){{1,2}})(?!\w)"
)
_SURNAME_SUFFIX = re.compile(
    rf"[{_LO}](?:ов|ова|ев|ева|ёв|ёва|ин|ина|ын|ына|енко|ук|юк|ян|янц|дзе|швили|ский|ская|цкий|"
    r"цкая|бек|беков|бекова|баев|баева|ұлы|улы)$"
)
_ADJECTIVE = re.compile(r"(?:ый|ий|ой|ая|яя|ое|ее|ые|ие)$")
_TWO_WORDS = re.compile(rf"(?<!\w)({_CAP})\s+({_CAP})(?!\w)")
_STOP_WORDS = frozenset(
    fold(w)
    for w in _words(
        "Республика Казахстан Россия Российская Федерация Москва Алматы Астана Шымкент "
        "Караганда Министерство Министр Государственный Государственная Университет "
        "Академия Компания Банк Область Район Город Улица Проспект Главная Новости "
        "Контакты Политика Пользователь Комментарии Ответить Читать Подробнее Регистрация "
        "Войти Поиск Каталог Отзывы Цена Купить Январь Февраль Март Апрель Май Июнь Июль "
        "Август Сентябрь Октябрь Ноябрь Декабрь Понедельник Вторник Среда Четверг Пятница "
        "Суббота Воскресенье Сегодня Вчера Telegram Президент Правительство Парламент "
        "Мажилис Сенат Аким Акимат Суд Прокуратура Полиция Европа Америка Азия Китай "
        "Украина Беларусь Узбекистан Кыргызстан "
    )
)

_EMAIL = re.compile(
    r"(?<![\w.%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9а-яё](?:[A-Za-z0-9а-яё-]"
    r"{0,61}[A-Za-z0-9а-яё])?\.)+[A-Za-zа-яё]{2,24})(?![\w-])",
    re.IGNORECASE,
)
_EMAIL_OBFUSCATED = re.compile(
    r"(?<![\w.])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})\s*[\[({]\s*(?:at|собака)\s*[\])}]\s*"
    r"([A-Za-z0-9-]+(?:\s*[\[({]\s*(?:dot|точка)\s*[\])}]\s*[A-Za-z0-9-]+)+)",
    re.IGNORECASE,
)
_DOT = re.compile(r"\s*[\[({]\s*(?:dot|точка)\s*[\])}]\s*", re.IGNORECASE)
_FILE_TLDS = frozenset({"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "ico", "bmp"})

_HANDLE = re.compile(r"(?<![\w@./])@([A-Za-z][A-Za-z0-9_.]{2,31})")
_HANDLE_LABEL = re.compile(
    r"(?:ник(?:нейм)?|логин|username|user\s?name|login)\s*[:\-–]\s*@?([A-Za-z0-9_.]{3,32})",
    re.IGNORECASE,
)
_PROFILE_HOSTS = {
    "vk.com": "VK",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "twitter.com": "X (Twitter)",
    "x.com": "X (Twitter)",
    "tiktok.com": "TikTok",
    "github.com": "GitHub",
    "ok.ru": "Одноклассники",
    "youtube.com": "YouTube",
    "linkedin.com": "LinkedIn",
    "threads.net": "Threads",
    "reddit.com": "Reddit",
    "medium.com": "Medium",
}
_PROFILE = re.compile(
    r"(?:https?://)?(?:www\.|m\.|mobile\.)?("
    + "|".join(re.escape(h) for h in _PROFILE_HOSTS)
    + r")/((?:in/|user/|u/|@)?[A-Za-z0-9_.\-]{2,64})",
    re.IGNORECASE,
)
_RESERVED_PATHS = frozenset(
    _words(
        "share sharer sharer.php login signup register search explore hashtag hashtags intent "
        "home about help privacy policy terms settings watch feed groups group pages events p "
        "reel reels stories tv s joinchat addstickers addemoji iv c proxy wall photo video "
        "videos away.php login.php dialog i status results channel playlist topics legal jobs "
        "company school r messages notifications discover tags tag shorts embed plugins oauth "
        "apps app download public club market audio music id post posts story feed.php "
        "profile.php index.php features pricing marketplace orgs sponsors trending topic dir "
        "directory "
    )
)

_MONTHS_RU = {
    m: i + 1
    for i, m in enumerate(
        _words("января февраля марта апреля мая июня июля августа сентября октября ноября декабря ")
    )
}
_MONTHS_EN = {
    m: i + 1
    for i, m in enumerate(
        _words(
            "january february march april may june july august september october november december "
        )
    )
}
_BIRTH_CUE = re.compile(
    r"(?:дата\s+рождения|д\.\s?р\.|\(\s*род\.|день\s+рождения|родил(?:ся|ась)|date\s+of\s+birth|"
    r"(?<!\w)dob(?!\w)|(?<!\w)born(?!\w)|туған\s+күні)\s*[:\-–—]?\s*(?:в\s+|in\s+|on\s+)?",
    re.IGNORECASE,
)
_DATE_FORMS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(\d{1,2})[./-](\d{1,2})[./-](\d{4})(?!\d)"),
    re.compile(r"(\d{4})-(\d{2})-(\d{2})(?!\d)"),
    re.compile(r"(\d{1,2})\s+(" + "|".join(_MONTHS_RU) + r")\s+(\d{4})", re.IGNORECASE),
    re.compile(r"(" + "|".join(_MONTHS_EN) + r")\s+(\d{1,2}),?\s+(\d{4})", re.IGNORECASE),
    re.compile(r"(\d{1,2})\s+(" + "|".join(_MONTHS_EN) + r")\s+(\d{4})", re.IGNORECASE),
    re.compile(r"(\d{4})(?:\s*(?:г\.?|года?))?(?!\d)"),
)
_BIRTH_AFTER = re.compile(
    r"(?<![\d.])((?:\d{1,2}[./]\d{1,2}[./])?\d{4})\s*(?:г\.?\s?р\.?|года\s+рождения|г\.\s+рождения)",
    re.IGNORECASE,
)

_ORG_FORMS_RU = r"ООО|ОАО|ЗАО|ПАО|НАО|АО|ТОО|ИП|ЧП|РГП|ГКП|КГП|ГККП|НКО|АНО|КФХ|К/Х|КХ|ФХ|ОФ"
_ORG_FORMS_EN = r"LLC|LLP|Ltd\.?|Limited|Inc\.?|JSC|PLC|GmbH|Corp\.?"
_QUOTED = r"[«\"“„]([^»\"”“\n]{2,80})[»\"”“]"
_ORG_RULES: tuple[tuple[re.Pattern[str], int, int], ...] = (  # (pattern, form group, name group)
    (re.compile(rf"(?<![\w«\"])({_ORG_FORMS_RU}|{_ORG_FORMS_EN})\s*{_QUOTED}"), 1, 2),
    (re.compile(rf"{_QUOTED}\s*,?\s*({_ORG_FORMS_RU}|{_ORG_FORMS_EN})(?![\w])"), 2, 1),
    (
        re.compile(rf"(?<!\w)(ИП)\s+({_CAP}(?:\s+{_CAP}){{1,2}}|{_CAP}\s+{_INIT})(?!\w)"),
        1,
        2,
    ),
    (
        re.compile(
            rf"(?<!\w)(ООО|ТОО|АО|ПАО|ОАО|ЗАО)\s+([A-Z{_UP}][\w&\-]+(?:\s+[A-Z{_UP}][\w&\-]+)"
            r"{0,2})(?!\w)"
        ),
        1,
        2,
    ),
    (
        re.compile(
            r"(?<![\w&])([A-Z][\w&.\-]*(?:\s+[A-Z][\w&.\-]*){0,4}),?\s+(LLC|LLP|Ltd\.?|Limited|"
            r"Inc\.?|JSC|PLC|GmbH|Corp\.?)(?![\w])"
        ),
        2,
        1,
    ),
)

_CITY = rf"(?i:г\.|гор\.|город)\s*[{_UP}A-Z][\w\-]+(?:[\s\-][{_UP}][\w\-]+)?"
_STREET_KW = (  # keywords in any case; names keep their capital letter
    r"(?i:ул\.|улица|пр\.|просп\.|проспект|пр-т|пер\.|переулок|б-р|бульвар|шоссе|наб\.|набережная"
    r"|пл\.|площадь|мкр\.?|микрорайон|мкрн\.?|ж\.\s?м\.|жилой\s+массив)"
)
_STREET = rf"{_STREET_KW}\s*[«\"]?[{_UP}A-Z0-9][\w\-\.]*(?:\s+[{_UP}A-Z][\w\-]+){{0,2}}[»\"]?"
_STREET_KZ = rf"[{_UP}][\w\-]+(?:\s+[{_LO}]+)?\s+(?i:көшесі|даңғылы|шағын\s+ауданы)"
_HOUSE = (
    r"(?:,?\s*(?i:д\.\s*|дом\s+|үй\s+)?\d{1,4}[а-яА-Яa-zA-Z]?(?:/\d{1,4})?(?!\d|\.\d)"
    r"(?:\s*,?\s*(?:корп\.|к\.|стр\.)\s*\d+)?)"
)
_FLAT = r"(?:,?\s*(?i:кв\.|квартира|оф\.|офис|п\.)\s*\d{1,4})"
_ADDRESS = re.compile(
    rf"(?<!\w)((?:\d{{6}},?\s*)?(?:(?:Республика\s+Казахстан|Казахстан|Россия|РФ|РК),?\s*)?"
    rf"(?:({_CITY}),?\s*)?(?:{_STREET}|{_STREET_KZ})({_HOUSE})?{_FLAT}?)"
)
_ADDRESS_EN = re.compile(
    r"(?<!\w)(\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St\.|Avenue|Ave\.?|Road|Rd\.|Boulevard|"
    r"Blvd\.?|Lane|Ln\.|Drive|Dr\.)(?:,\s*(?:Apt|Suite)\.?\s*\d+)?(?:,\s*[A-Z][a-z]+){0,2})"
)


# --------------------------------------------------------------------------- extractors
def _ctx(text: str, start: int, end: int) -> str:
    return fragment_around(text, start, end, CONTEXT_CHARS)


def _emails(text: str) -> Iterator[tuple[int, Entity]]:
    for m in _EMAIL.finditer(text):
        domain = m.group(2).rstrip(".").lower()
        if domain.rsplit(".", 1)[-1] in _FILE_TLDS:
            continue
        address = f"{m.group(1).lower()}@{domain}"
        yield m.start(), Entity(EntityType.EMAIL, address, _ctx(text, *m.span()), "адрес email")
    for m in _EMAIL_OBFUSCATED.finditer(text):
        domain = _DOT.sub(".", m.group(2)).lower()
        address = f"{m.group(1).lower()}@{domain}"
        yield (
            m.start(),
            Entity(EntityType.EMAIL, address, _ctx(text, *m.span()), "email, записанный «[at]»"),
        )


def _phones(text: str, region: str) -> Iterator[tuple[int, Entity]]:
    matcher = phonenumbers.PhoneNumberMatcher(
        text, region, leniency=phonenumbers.Leniency.VALID, max_tries=500
    )
    for m in matcher:
        if sum(ch.isdigit() for ch in m.raw_string) < 9:
            continue
        e164 = phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164)
        where = phonenumbers.region_code_for_number(m.number) or "?"
        yield (
            m.start,
            Entity(EntityType.PHONE, e164, _ctx(text, m.start, m.end), f"номер телефона ({where})"),
        )


def _usernames(text: str) -> Iterator[tuple[int, Entity]]:
    for m in _PROFILE.finditer(text):
        host = m.group(1).lower()
        path = m.group(2)
        handle = re.sub(r"^(?:in/|user/|u/|@)", "", path, flags=re.IGNORECASE).strip(".-")
        if len(handle) < 2 or handle.lower() in _RESERVED_PATHS or handle.isdigit():
            continue
        platform = _PROFILE_HOSTS[host]
        url = f"https://{host}/{path}"
        yield (
            m.start(),
            Entity(
                EntityType.USERNAME,
                handle.lower(),
                _ctx(text, *m.span()),
                f"ссылка на профиль {platform}",
                platform,
                url,
            ),
        )
    for m in _HANDLE.finditer(text):
        handle = m.group(1).rstrip(".")
        yield (
            m.start(),
            Entity(EntityType.USERNAME, handle.lower(), _ctx(text, *m.span()), "упоминание @ник"),
        )
    for m in _HANDLE_LABEL.finditer(text):
        handle = m.group(1).rstrip(".")
        if handle.isdigit():
            continue
        yield (
            m.start(),
            Entity(
                EntityType.USERNAME, handle.lower(), _ctx(text, *m.span()), "подпись «ник/логин»"
            ),
        )


def _make_date(year: int, month: int | None, day: int | None) -> str | None:
    if not 1900 <= year <= date.today().year - 3:
        return None
    if month is None or day is None:
        return f"{year:04d}"
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def _date_at(text: str, pos: int) -> tuple[str, int] | None:
    """Parse a date starting exactly at ``pos``; returns (ISO value, end offset)."""
    for index, pattern in enumerate(_DATE_FORMS):
        m = pattern.match(text, pos)
        if not m:
            continue
        g = m.groups()
        if index == 0:
            value = _make_date(int(g[2]), int(g[1]), int(g[0]))
        elif index == 1:
            value = _make_date(int(g[0]), int(g[1]), int(g[2]))
        elif index == 2:
            value = _make_date(int(g[2]), _MONTHS_RU[g[1].lower()], int(g[0]))
        elif index == 3:
            value = _make_date(int(g[2]), _MONTHS_EN[g[0].lower()], int(g[1]))
        elif index == 4:
            value = _make_date(int(g[2]), _MONTHS_EN[g[1].lower()], int(g[0]))
        else:
            value = _make_date(int(g[0]), None, None)
        if value:
            return value, m.end()
    return None


def _birthdates(text: str) -> Iterator[tuple[int, Entity]]:
    for m in _BIRTH_CUE.finditer(text):
        parsed = _date_at(text, m.end())
        if parsed:
            value, end = parsed
            yield (
                m.start(),
                Entity(
                    EntityType.BIRTHDATE,
                    value,
                    _ctx(text, m.start(), end),
                    "рядом с «дата рождения»",
                ),
            )
    for m in _BIRTH_AFTER.finditer(text):
        parsed = _date_at(text, m.start(1))
        if parsed:
            yield (
                m.start(),
                Entity(EntityType.BIRTHDATE, parsed[0], _ctx(text, *m.span()), "отметка «г.р.»"),
            )


def _clean_name(text: str) -> str:
    cleaned = " ".join(text.split()).strip(" ,;:")
    if cleaned.endswith(".") and not re.search(r"(?:^|[\s.])\w\.$", cleaned):
        cleaned = cleaned.rstrip(".")  # sentence end, not an initial
    return cleaned


def _organizations(text: str) -> Iterator[tuple[int, Entity]]:
    for pattern, form_group, name_group in _ORG_RULES:
        for m in pattern.finditer(text):
            form = m.group(form_group).rstrip(".")
            name = _clean_name(m.group(name_group))
            if not name or fold(name) in _STOP_WORDS:
                continue
            if form == "ИП":
                value = f"ИП {name}"  # sole proprietor: the name is a person's
            elif form in _ORG_FORMS_RU.split("|"):
                value = f"{form} «{name}»"
            else:
                value = f"{name} {form}"
            yield (
                m.start(),
                Entity(
                    EntityType.ORGANIZATION, value, _ctx(text, *m.span()), f"правовая форма {form}"
                ),
            )


def _addresses(text: str) -> Iterator[tuple[int, Entity]]:
    for m in _ADDRESS.finditer(text):
        has_city, has_house = bool(m.group(2)), bool(m.group(3))
        if not (has_city or has_house):
            continue  # a bare "ул. Абая" is too vague (and "пр." is often "прочее")
        value = _clean_name(m.group(1))
        yield (
            m.start(),
            Entity(EntityType.ADDRESS, value, _ctx(text, *m.span()), "улица и дом/город"),
        )
    for m in _ADDRESS_EN.finditer(text):
        value = _clean_name(m.group(1))
        yield m.start(), Entity(EntityType.ADDRESS, value, _ctx(text, *m.span()), "street address")


def _plausible_name(words: list[str]) -> bool:
    return not any(fold(w) in _STOP_WORDS for w in words)


def _names(text: str) -> Iterator[tuple[int, Entity]]:
    taken: list[tuple[int, int]] = []

    def free(start: int, end: int) -> bool:
        return all(end <= a or start >= b for a, b in taken)

    for m in _LABEL_NAME.finditer(text):
        name = _clean_name(m.group(1))
        if _plausible_name(name.split()):
            taken.append(m.span(1))
            yield (
                m.start(1),
                Entity(EntityType.NAME, name, _ctx(text, *m.span(1)), "после подписи «ФИО/Автор»"),
            )
    for pattern, basis in _NAME_RULES:
        for m in pattern.finditer(text):
            start, end = m.span(1)
            name = _clean_name(m.group(1))
            if not free(start, end) or not _plausible_name(re.split(r"[\s.]+", name)):
                continue
            taken.append((start, end))
            yield start, Entity(EntityType.NAME, name, _ctx(text, start, end), basis)
    for m in _TWO_WORDS.finditer(text):
        start, end = m.span()
        first, second = m.group(1), m.group(2)
        if not free(start, end) or not _plausible_name([first, second]):
            continue
        surname = [w for w in (first, second) if _SURNAME_SUFFIX.search(w)]
        if len(surname) != 1:
            continue
        other = second if surname[0] == first else first
        if _ADJECTIVE.search(other):
            continue
        if surname[0].endswith(("ский", "ская", "цкий", "цкая")) and other.endswith(
            ("ия", "ость", "ство", "ние", "ка")
        ):
            continue  # "Казахская Республика"-like adjective + noun
        taken.append((start, end))
        yield start, Entity(EntityType.NAME, _clean_name(m.group(0)), _ctx(text, start, end),
                            "имя и фамилия (по окончанию фамилии)")  # fmt: skip


def extract_entities(
    text: str, *, region: str | None = None, limit: int = DEFAULT_LIMIT
) -> list[Entity]:
    """All entities in ``text``, in order of appearance, one per distinct value."""
    if not text or not text.strip():
        return []
    region = (region or "KZ").upper()
    found: list[tuple[int, Entity]] = [
        *_emails(text),
        *_phones(text, region),
        *_usernames(text),
        *_birthdates(text),
        *_organizations(text),
        *_addresses(text),
        *_names(text),
    ]
    emails = {e.value for _, e in found if e.type is EntityType.EMAIL}
    out: dict[str, Entity] = {}
    for _, entity in sorted(found, key=lambda item: item[0]):
        if (
            entity.type is EntityType.USERNAME
            and entity.url is None
            and any(
                address.startswith(f"{entity.value}@") or address.endswith(f".{entity.value}")
                for address in emails
            )
        ):
            continue  # "@mail" taken from an email address
        out.setdefault(entity.key, entity)
        if len(out) >= limit:
            break
    return list(out.values())


# --------------------------------------------------------------------------- near the identifier
def _windows(text: str, needle: str) -> str:
    """Text around every occurrence of ``needle`` (merged), or the start of the text."""
    folded = fold(text)
    spans: list[tuple[int, int]] = []
    if needle:
        for m in re.finditer(re.escape(fold(needle)), folded):
            spans.append((max(0, m.start() - WINDOW_CHARS), min(len(text), m.end() + WINDOW_CHARS)))
            if len(spans) >= MAX_WINDOWS:
                break
    if not spans:
        return text[: WINDOW_CHARS * 4]
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return "\n…\n".join(text[a:b] for a, b in merged)


def _is_target(entity: Entity, target: Target) -> bool:
    norm = target.normalized
    if target.type is TargetType.EMAIL:
        return entity.type is EntityType.EMAIL and entity.value == norm.lower()
    if target.type is TargetType.PHONE:
        return entity.type is EntityType.PHONE and entity.value == norm
    if target.type is TargetType.USERNAME:
        return entity.type is EntityType.USERNAME and entity.value == norm.lower().lstrip("@")
    if target.type is TargetType.NAME and entity.type is EntityType.NAME:
        wanted = set(fold(norm).split())
        got = set(re.sub(r"[.,]", " ", fold(entity.value)).split())
        return bool(wanted) and (wanted <= got or (got <= wanted and len(got) >= 2))
    return False


def extract_near(
    target: Target,
    text: str,
    *,
    region: str | None = None,
    limit: int = DEFAULT_LIMIT,
    whole: bool = False,
) -> list[Entity]:
    """Entities in the parts of ``text`` around the identifier (the whole text if ``whole``).

    The identifier itself is always listed first (``is_target``), so a page that contains only
    the researched name is still typed as «ФИО».
    """
    if not text:
        return []
    match = find_identifier(target, text)
    scope = text if whole else _windows(text, match.variant if match else "")
    region = region or (str(target.details.get("region")) if target.details.get("region") else None)
    entities = extract_entities(scope, region=region, limit=limit)
    flagged = [
        Entity(e.type, e.value, e.context, e.basis, e.platform, e.url, True)
        if _is_target(e, target)
        else e
        for e in entities
    ]
    if match and not any(e.is_target for e in flagged):
        own = _target_entity(target, match.variant, match.fragment)
        if own is not None:
            flagged.insert(0, own)
    flagged.sort(key=lambda e: not e.is_target)
    return flagged[:limit]


def _target_entity(target: Target, variant: str, fragment: str) -> Entity | None:
    kind = {
        TargetType.NAME: EntityType.NAME,
        TargetType.EMAIL: EntityType.EMAIL,
        TargetType.PHONE: EntityType.PHONE,
        TargetType.USERNAME: EntityType.USERNAME,
    }.get(target.type)
    if kind is None:
        return None
    value = {
        EntityType.NAME: _clean_name(variant),
        EntityType.EMAIL: target.normalized.lower(),
        EntityType.PHONE: target.normalized,
        EntityType.USERNAME: target.normalized.lower().lstrip("@"),
    }[kind]
    return Entity(kind, value, fragment, "искомый идентификатор", is_target=True)

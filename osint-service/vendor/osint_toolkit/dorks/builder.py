"""Dork builder: identifier variants × site/file filters → search queries and manual links.

* Variants of one identifier are combined with ``OR`` (exact phrases) in as few queries as the
  engine's limits allow (Google: 32 words; we also cap characters).
* Each :class:`DorkGroup` narrows the search (social networks, classifieds, "who called" phone
  directories, documents, paste sites, code hosting, forums). Region-specific groups follow the
  phone's country or ``OSINT_DEFAULT_REGION`` (RU/KZ), otherwise both.
* :func:`manual_links` turns a query into Google/Bing/Yandex URLs; they are opened only by the
  user's click, so the search engine sees the query from the user's own browser.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote_plus

import phonenumbers

from osint_toolkit.core.models import Target, TargetType
from osint_toolkit.dorks.variants import variants_for

MAX_WORDS = 32  # Google ignores words after the 32nd
MAX_CHARS = 380
T = TargetType


@dataclass(frozen=True, slots=True)
class DorkGroup:
    key: str
    title: str
    filters: tuple[str, ...]
    types: frozenset[TargetType]
    regions: frozenset[str] | None = None  # None = any region


GROUPS: tuple[DorkGroup, ...] = (
    DorkGroup("exact", "Точное совпадение", (), frozenset(T)),
    DorkGroup(
        "social",
        "Соцсети и мессенджеры",
        (
            "site:vk.com",
            "site:ok.ru",
            "site:t.me",
            "site:facebook.com",
            "site:instagram.com",
            "site:linkedin.com",
        ),
        frozenset({T.PHONE, T.NAME, T.EMAIL, T.USERNAME}),
    ),
    DorkGroup(
        "classifieds_ru",
        "Объявления (Россия)",
        ("site:avito.ru", "site:youla.ru", "site:drom.ru", "site:auto.ru", "site:cian.ru"),
        frozenset({T.PHONE, T.EMAIL}),
        frozenset({"RU"}),
    ),
    DorkGroup(
        "classifieds_kz",
        "Объявления (Казахстан)",
        ("site:olx.kz", "site:krisha.kz", "site:kolesa.kz", "site:market.kz"),
        frozenset({T.PHONE, T.EMAIL}),
        frozenset({"KZ"}),
    ),
    DorkGroup(
        "phonebooks",
        "Сайты «кто звонил»",
        ("site:neberitrubku.ru", "site:zvonili.com", "site:tellows.ru"),
        frozenset({T.PHONE}),
    ),
    DorkGroup(
        "documents",
        "Документы",
        (
            "filetype:pdf",
            "filetype:doc",
            "filetype:docx",
            "filetype:xls",
            "filetype:xlsx",
            "filetype:csv",
        ),
        frozenset({T.PHONE, T.NAME, T.EMAIL}),
    ),
    DorkGroup(
        "paste",
        "Paste-сайты",
        ("site:pastebin.com", "site:paste.ee", "site:rentry.co"),
        frozenset({T.PHONE, T.EMAIL, T.USERNAME}),
    ),
    DorkGroup(
        "code",
        "Репозитории кода",
        ("site:github.com", "site:gitlab.com"),
        frozenset({T.EMAIL, T.USERNAME}),
    ),
    DorkGroup(
        "forums",
        "Форумы",
        ("inurl:forum", "inurl:viewtopic", "inurl:thread"),
        frozenset({T.NAME, T.EMAIL, T.USERNAME}),
    ),
)
GROUP_KEYS = frozenset(g.key for g in GROUPS)


@dataclass(frozen=True, slots=True)
class Dork:
    group: str
    title: str
    query: str
    variants: tuple[str, ...]


def target_region(target: Target, default_region: str | None) -> str | None:
    if target.type is T.PHONE and target.details.get("region_known"):
        try:
            region = phonenumbers.region_code_for_number(
                phonenumbers.parse(target.normalized, None)
            )
        except phonenumbers.NumberParseException:
            region = None
        if region:
            return str(region)
    return default_region


def groups_for(
    target: Target, region: str | None, enabled: frozenset[str] | None = None
) -> list[DorkGroup]:
    chosen = []
    for group in GROUPS:
        if target.type not in group.types:
            continue
        if enabled is not None and group.key not in enabled:
            continue
        if group.regions is not None and region is not None and region not in group.regions:
            continue
        chosen.append(group)
    return chosen


def _quote(variant: str) -> str:
    return '"' + variant.replace('"', "") + '"'


def _fits(query: str) -> bool:
    return len(query) <= MAX_CHARS and len(query.split()) <= MAX_WORDS


def _compose(phrases: list[str], filters: tuple[str, ...]) -> str:
    variant_part = " OR ".join(phrases)
    if len(phrases) > 1:
        variant_part = f"({variant_part})"
    if not filters:
        return variant_part
    filter_part = " OR ".join(filters)
    return f"{variant_part} ({filter_part})" if len(filters) > 1 else f"{variant_part} {filters[0]}"


def _chunks(variants: list[str], filters: tuple[str, ...]) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    for variant in variants:
        candidate = [*current, _quote(variant)]
        if current and not _fits(_compose(candidate, filters)):
            chunks.append(current)
            current = [_quote(variant)]
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def build_dorks(
    target: Target,
    *,
    supports_or: bool = True,
    default_region: str | None = None,
    enabled_groups: frozenset[str] | None = None,
) -> list[Dork]:
    """All dorks for ``target``, ordered for budget-limited runs: every "exact" query (all
    spelling variants) first, then the other groups round-robin."""
    variants = variants_for(target)
    region = target_region(target, default_region)
    per_group: list[list[Dork]] = []
    for group in groups_for(target, region, enabled_groups):
        dorks: list[Dork] = []
        if supports_or:
            for chunk in _chunks(variants, group.filters):
                query = _compose(chunk, group.filters)
                plain = tuple(p.strip('"') for p in chunk)
                dorks.append(Dork(group.key, group.title, query, plain))
        else:  # engines without OR: one variant and one filter per query
            for variant in variants:
                for flt in group.filters or ("",):
                    query = f"{_quote(variant)} {flt}".strip()
                    dorks.append(Dork(group.key, group.title, query, (variant,)))
        per_group.append(dorks)
    # Every spelling variant matters most: all "exact" queries first, then the narrower groups
    # round-robin, so a small budget still covers each variant and each kind of site.
    exact = [d for dorks in per_group for d in dorks if d.group == "exact"]
    rest = [dorks for dorks in per_group if dorks and dorks[0].group != "exact"]
    ordered: list[Dork] = list(exact)
    depth = max((len(d) for d in rest), default=0)
    for i in range(depth):
        ordered += [dorks[i] for dorks in rest if i < len(dorks)]
    return ordered


def simple_dorks(
    target: Target,
    *,
    default_region: str | None = None,
    enabled_groups: frozenset[str] | None = None,
    exact_variants: int = 4,
) -> list[Dork]:
    """Engine-friendly dorks for automated search: one spelling and at most one filter per
    query (no long OR chains — many engines behind SearXNG return nothing for them).

    The most specific spellings come first (initials-only name forms are left to the manual
    links), then every filter of every group with the main spelling, round-robin by group.
    """
    variants = [v for v in variants_for(target) if not is_initials_form(target, v)]
    if not variants:
        return []
    region = target_region(target, default_region)
    groups = groups_for(target, region, enabled_groups)
    out: list[Dork] = []
    if any(g.key == "exact" for g in groups):
        exact = next(g for g in groups if g.key == "exact")
        for variant in variants[:exact_variants]:
            out.append(Dork(exact.key, exact.title, _quote(variant), (variant,)))
    main = variants[0]
    per_group = [
        [Dork(g.key, g.title, f"{_quote(main)} {flt}", (main,)) for flt in g.filters]
        for g in groups
        if g.key != "exact"
    ]
    depth = max((len(d) for d in per_group), default=0)
    for i in range(depth):
        out += [dorks[i] for dorks in per_group if i < len(dorks)]
    return list({d.query: d for d in out}.values())


def is_initials_form(target: Target, variant: str) -> bool:
    return target.type is T.NAME and any(len(w) == 2 and w.endswith(".") for w in variant.split())


def manual_links(query: str) -> dict[str, str]:
    """Search-engine URLs for opening the dork in a browser (never fetched by the app)."""
    yandex = query.replace(" OR ", " | ").replace("filetype:", "mime:")
    return {
        "google": f"https://www.google.com/search?q={quote_plus(query)}",
        "yandex": f"https://yandex.ru/search/?text={quote_plus(yandex)}",
        "bing": f"https://www.bing.com/search?q={quote_plus(query)}",
    }

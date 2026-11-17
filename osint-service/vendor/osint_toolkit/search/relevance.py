"""Drop search hits that cannot belong to the dork: engines do not always honour operators.

Checked on 2026-11-16: Bing and Mojeek behind SearXNG ignored ``site:``/``filetype:`` and the
quotes of Cyrillic phrases — ``"Илон Маск" site:vk.com`` returned chess clubs and help pages.
Opening such pages wastes the verification budget, and counting them made dork counts lie.

A hit is kept only if
* it satisfies the dork's own filters: ``site:`` (host or subdomain), ``filetype:`` (document of
  that type by URL), ``inurl:`` (substring of the URL); and
* its title, snippet or URL mentions the identifier at all: a distinctive word of a spelling
  variant (names, usernames, emails) or the last 7 digits of the number (phones).
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

import phonenumbers

from osint_toolkit.core.models import Target, TargetType
from osint_toolkit.dorks import Dork, variants_for
from osint_toolkit.integrations.search import SearchHit
from osint_toolkit.search.matching import fold
from osint_toolkit.search.resources import DOCUMENT_EXTENSIONS

_OPERATOR = re.compile(r"\b(site|filetype|inurl):(\S+)", re.IGNORECASE)
_WORD = re.compile(r"\w{3,}")


def dork_filters(query: str) -> dict[str, str]:
    return {name.lower(): value.lower() for name, value in _OPERATOR.findall(query)}


def _host_matches(url: str, domain: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host == domain or host.endswith("." + domain)


def _filetype_matches(url: str, ext: str) -> bool:
    path = unquote(urlsplit(url).path).lower()
    if path.endswith("." + ext):
        return True
    # some repositories serve files from paths without extension ("/download?id="): allow
    # those only when the URL still names the type somewhere
    return DOCUMENT_EXTENSIONS.get("." + ext) is not None and ext in url.lower()


def markers_for(target: Target) -> tuple[str, ...]:
    """Short strings any relevant hit should contain (folded)."""
    if target.type is TargetType.PHONE:
        try:
            nsn = phonenumbers.national_significant_number(
                phonenumbers.parse(target.normalized, None)
            )
        except phonenumbers.NumberParseException:
            return ()
        return (nsn[-7:],) if len(nsn) >= 7 else ()
    if target.type is TargetType.EMAIL:
        local = target.normalized.rpartition("@")[0]
        return (fold(local),) if len(local) >= 3 else (fold(target.normalized),)
    words: set[str] = set()
    for variant in variants_for(target):
        candidates = [w for w in _WORD.findall(fold(variant)) if not w.isdigit()]
        if candidates:
            words.add(max(candidates, key=len))  # the most distinctive word of each spelling
    return tuple(sorted(words))


def mentions_identifier(kind: TargetType, markers: tuple[str, ...], hit: SearchHit) -> bool:
    if not markers:
        return True
    text = fold(f"{hit.title} {hit.snippet} {unquote(hit.url)}")
    if kind is TargetType.PHONE:
        digits = re.sub(r"\D", "", text)
        return any(m in digits for m in markers)
    return any(m in text for m in markers)


def relevant(kind: TargetType, markers: tuple[str, ...], dork: Dork, hit: SearchHit) -> bool:
    """Keep the hit? (``markers`` from :func:`markers_for`, computed once per target)"""
    filters = dork_filters(dork.query)
    if "site" in filters and not _host_matches(hit.url, filters["site"]):
        return False
    if "filetype" in filters and not _filetype_matches(hit.url, filters["filetype"]):
        return False
    if "inurl" in filters and filters["inurl"] not in hit.url.lower():
        return False
    return mentions_identifier(kind, markers, hit)

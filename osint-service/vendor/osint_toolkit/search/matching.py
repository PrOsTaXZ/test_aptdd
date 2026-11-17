"""Does a page text really contain the identifier? (used after downloading a search hit)

A search engine's snippet is not proof: the engine may match stemmed words, other spellings or
text that is no longer on the page. :func:`find_identifier` checks the *downloaded* text for the
identifier in any accepted spelling and returns the matched form plus a fragment around it.

* phone — the national significant number with any separators (spaces, dashes, dots,
  brackets), optionally preceded by the country code or the trunk prefix; never inside a longer
  digit run (so a 10-digit number does not match inside an account number);
* email — the address (case-insensitive) or its anti-spam spellings ("user at domain"…);
* name — full-name spellings (word orders, transliterations, ё/е), whole words only.
  Initial-only forms ("Маск И.") are accepted too but reported as ``weak``;
* username — the name as a whole token or ``@name``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

import phonenumbers

from osint_toolkit.core.models import Target, TargetType
from osint_toolkit.dorks.variants import variants_for

FRAGMENT_CHARS = 140
_SEP = r"[\s\-\.\(\)  ‑]{0,3}"
_INITIAL_RE = re.compile(r"(^|\s)\w\.")


@dataclass(frozen=True, slots=True)
class Match:
    variant: str  # spelling that matched
    fragment: str  # text around the match
    weak: bool = False  # initials only, or similar low-specificity form


def fold(text: str) -> str:
    """Case and ё/е folding that keeps string length (offsets stay valid)."""
    return text.lower().replace("ё", "е")


def fragment_around(text: str, start: int, end: int, width: int = FRAGMENT_CHARS) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    piece = " ".join(text[left:right].split())
    return ("…" if left else "") + piece + ("…" if right < len(text) else "")


@lru_cache(maxsize=256)
def _phone_pattern(e164: str) -> re.Pattern[str] | None:
    try:
        number = phonenumbers.parse(e164, None)
    except phonenumbers.NumberParseException:
        return None
    nsn = phonenumbers.national_significant_number(number)
    if len(nsn) < 6:
        return None
    region = phonenumbers.region_code_for_number(number)
    metadata = phonenumbers.PhoneMetadata.metadata_for_region(region) if region else None
    prefixes = [re.escape(f"+{number.country_code}"), re.escape(str(number.country_code))]
    if metadata is not None and metadata.national_prefix:
        prefixes.append(re.escape(metadata.national_prefix))
    body = _SEP.join(re.escape(d) for d in nsn)
    return re.compile(rf"(?<![\d+])(?:(?:{'|'.join(prefixes)}){_SEP})?{body}(?!\d)")


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    words = [re.escape(fold(w)) for w in phrase.split()]
    return re.compile(r"(?<!\w)" + r"[\s ]+".join(words) + r"(?!\w)")


def find_identifier(target: Target, text: str) -> Match | None:
    """First occurrence of the identifier in ``text`` (any accepted spelling) or None."""
    if not text:
        return None
    if target.type is TargetType.PHONE:
        pattern = _phone_pattern(target.normalized)
        found = pattern.search(text) if pattern else None
        if found:
            return Match(found.group(0).strip(), fragment_around(text, *found.span()))
        return None
    folded = fold(text)
    if target.type is TargetType.EMAIL:
        candidates = variants_for(target)
    elif target.type is TargetType.USERNAME:
        candidates = [target.normalized]
    elif target.type is TargetType.NAME:
        candidates = variants_for(target)
    else:
        candidates = [target.normalized]
    weak_hit: Match | None = None
    for variant in candidates:
        found = _phrase_pattern(variant).search(folded)
        if not found:
            continue
        weak = target.type is TargetType.NAME and bool(_INITIAL_RE.search(variant))
        hit = Match(text[found.start() : found.end()], fragment_around(text, *found.span()), weak)
        if not weak:
            return hit
        weak_hit = weak_hit or hit
    return weak_hit

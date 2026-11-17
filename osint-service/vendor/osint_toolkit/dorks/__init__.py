"""Search-query variants and dork building (no network access here)."""

from osint_toolkit.dorks.builder import Dork, DorkGroup, build_dorks, manual_links, simple_dorks
from osint_toolkit.dorks.variants import (
    email_variants,
    name_variants,
    phone_variants,
    search_signature,
    transliterate,
    username_variants,
    variants_for,
)

__all__ = [
    "Dork",
    "DorkGroup",
    "build_dorks",
    "email_variants",
    "manual_links",
    "name_variants",
    "phone_variants",
    "search_signature",
    "simple_dorks",
    "transliterate",
    "username_variants",
    "variants_for",
]

"""Target type detection and normalisation.

:func:`detect` returns every plausible interpretation of an input, best first, so ambiguous inputs
(``john.doe`` — domain or username? ``89161234567`` — phone or username?) can be resolved by the
user instead of guessed silently. Detection is purely local: no DNS or network lookups, and for
image paths only ``stat`` is used — file contents are not read here.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

import phonenumbers

from osint_toolkit.core.models import JsonValue, Target, TargetType

IMAGE_EXTENSIONS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".jpe",
        ".jfif",
        ".png",
        ".tif",
        ".tiff",
        ".webp",
        ".heic",
        ".heif",
        ".avif",
        ".gif",
        ".bmp",
        ".mpo",
    }
)

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_PHONE_CHARS_RE = re.compile(r"^\+?[\d\s().\-]{6,24}$")
_USERNAME_RE = re.compile(r"^[\w.\-]{1,64}$")
_NAME_WORD_RE = re.compile(r"^[^\W\d_]+(?:[-'’.][^\W\d_]+)*\.?$")


_UNAMBIGUOUS = frozenset({TargetType.IP, TargetType.EMAIL, TargetType.IMAGE})


class UnsupportedInputError(ValueError):
    """The input does not look like any supported identifier."""


def detect(raw: str, *, default_region: str | None = None) -> list[Target]:
    """All plausible targets for ``raw``, most likely first. Raises UnsupportedInputError."""
    text = raw.strip()
    if not text:
        raise UnsupportedInputError("Пустой ввод")
    if len(text) > 512:
        raise UnsupportedInputError("Слишком длинный ввод (максимум 512 символов)")

    candidates: list[Target] = []

    def add(target: Target | None) -> None:
        if target is not None and all(c.key != target.key for c in candidates):
            candidates.append(target)

    if text.lower().startswith(("http://", "https://")):
        host = urlsplit(text).hostname or ""
        add(_as_ip(host, raw) or _as_domain(host, raw))
    else:
        add(_as_image(text, raw))
        add(_as_ip(text, raw))
        add(_as_email(text, raw))
        add(_as_phone(text, raw, default_region))
        add(_as_domain(text, raw))
        add(_as_name(text, raw))
        add(_as_username(text, raw))

    if not candidates:
        raise UnsupportedInputError(f"Не удалось определить тип данных: {text!r}")
    # An IP literal, an email address or an existing image file is unambiguous: do not offer
    # weaker readings such as "username 10.1.2.3".
    strong = [c for c in candidates if c.type in _UNAMBIGUOUS]
    return strong or candidates


def parse_as(raw: str, target_type: TargetType, *, default_region: str | None = None) -> Target:
    """Interpret ``raw`` as a specific type. Raises UnsupportedInputError if it does not fit."""
    text = raw.strip()
    parsers = {
        TargetType.IMAGE: lambda: _as_image(text, raw),
        TargetType.IP: lambda: _as_ip(text.strip("[]"), raw),
        TargetType.EMAIL: lambda: _as_email(text, raw),
        TargetType.PHONE: lambda: _as_phone(text, raw, default_region),
        TargetType.DOMAIN: lambda: _as_domain(
            urlsplit(text).hostname or "" if "://" in text else text, raw
        ),
        TargetType.NAME: lambda: _as_name(text, raw, min_words=1),
        TargetType.USERNAME: lambda: _as_username(text, raw),
    }
    target = parsers[target_type]()
    if target is None:
        raise UnsupportedInputError(f"{text!r} не похоже на {target_type.label}")
    return target


def declare_own(target: Target) -> Target:
    """Mark an email target as the user's own address (enables self-audit modules)."""
    if target.type is not TargetType.EMAIL:
        raise UnsupportedInputError("Только email можно объявить своим адресом")
    return target.model_copy(update={"details": {**target.details, "declared_own": True}})


def related_targets(target: Target) -> list[Target]:
    """Targets worth investigating alongside ``target`` in Full Investigation mode."""
    related: list[Target] = []
    if target.type is TargetType.EMAIL:
        domain = target.details.get("domain")
        if isinstance(domain, str):
            derived = _as_domain(domain, domain)
            if derived is not None:
                related.append(derived.model_copy(update={"derived_from": target.normalized}))
    return related


# --------------------------------------------------------------------------- parsers
def _as_ip(text: str, raw: str) -> Target | None:
    try:
        address = ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None
    details: dict[str, JsonValue] = {
        "version": address.version,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
        "is_link_local": address.is_link_local,
    }
    return Target(raw=raw, type=TargetType.IP, normalized=address.compressed, details=details)


def normalize_domain(text: str) -> tuple[str, str] | None:
    """(ascii/punycode, unicode) form of a hostname, or None if it is not a valid FQDN."""
    host = text.strip().rstrip(".").lower()
    if not host or len(host) > 253 or "." not in host:
        return None
    try:
        ascii_host = host.encode("idna").decode("ascii")
        unicode_host = ascii_host.encode("ascii").decode("idna")
    except UnicodeError:
        return None
    labels = ascii_host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels) or not _TLD_RE.match(labels[-1]):
        return None
    return ascii_host, unicode_host


def _as_domain(text: str, raw: str) -> Target | None:
    normalized = normalize_domain(text)
    if normalized is None:
        return None
    ascii_host, unicode_host = normalized
    details: dict[str, JsonValue] = {
        "unicode": unicode_host,
        "tld": ascii_host.rsplit(".", 1)[-1],
        "labels": ascii_host.count(".") + 1,
    }
    return Target(raw=raw, type=TargetType.DOMAIN, normalized=ascii_host, details=details)


def _as_email(text: str, raw: str) -> Target | None:
    if not _EMAIL_RE.match(text):
        return None
    local, _, domain_part = text.rpartition("@")
    normalized = normalize_domain(domain_part)
    if normalized is None or not local:
        return None
    ascii_domain, unicode_domain = normalized
    details: dict[str, JsonValue] = {
        "local_part": local,
        "domain": ascii_domain,
        "domain_unicode": unicode_domain,
    }
    return Target(
        raw=raw, type=TargetType.EMAIL, normalized=f"{local}@{ascii_domain}", details=details
    )


def _as_phone(text: str, raw: str, default_region: str | None) -> Target | None:
    if not _PHONE_CHARS_RE.match(text):
        return None
    digits = re.sub(r"\D", "", text)
    if not 7 <= len(digits) <= 15:
        return None
    region = None if text.startswith("+") else default_region
    if region is None and not text.startswith("+"):
        # Without "+" or a configured region the country is unknown: keep the digits, let the
        # phone module (or the user) decide. It is still a plausible phone candidate.
        return Target(
            raw=raw,
            type=TargetType.PHONE,
            normalized=digits,
            details={"region_known": False, "digits": digits},
        )
    try:
        number = phonenumbers.parse(text, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(number):
        return None
    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    return Target(
        raw=raw,
        type=TargetType.PHONE,
        normalized=e164,
        details={
            "region_known": True,
            "country_code": number.country_code,
            "national_number": str(number.national_number),
        },
    )


def _as_image(text: str, raw: str) -> Target | None:
    if not (
        text.startswith(("/", "~", "./", "../")) or Path(text).suffix.lower() in IMAGE_EXTENSIONS
    ):
        return None
    path = Path(text).expanduser()
    if path.suffix.lower() not in IMAGE_EXTENSIONS:
        return None
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            return None
        size = resolved.stat().st_size
    except OSError:
        return None
    return Target(
        raw=raw,
        type=TargetType.IMAGE,
        normalized=str(resolved),
        details={"file_name": resolved.name, "size_bytes": size},
    )


def _as_name(text: str, raw: str, *, min_words: int = 2) -> Target | None:
    words = text.split()
    if not min_words <= len(words) <= 6:
        return None
    if not all(_NAME_WORD_RE.match(w) for w in words):
        return None
    normalized = " ".join(words)  # case kept as typed: "van", "de", "оглы" are lowercase
    return Target(
        raw=raw, type=TargetType.NAME, normalized=normalized, details={"words": len(words)}
    )


def _as_username(text: str, raw: str) -> Target | None:
    candidate = text[1:] if text.startswith("@") else text
    if not _USERNAME_RE.match(candidate):
        return None
    return Target(raw=raw, type=TargetType.USERNAME, normalized=candidate, details={})

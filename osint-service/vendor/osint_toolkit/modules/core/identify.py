"""Offline identification of the target: canonical form and structural properties.

Everything here is derived locally from the identifier itself using standards-based parsing, so
findings are ``confirmed`` with respect to *format* — they say nothing about whether the identifier
exists or who uses it.
"""

from __future__ import annotations

from pathlib import Path

from osint_toolkit.core.models import Confidence, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput

_IANA_V4 = "https://www.iana.org/assignments/iana-ipv4-special-registry/"
_IANA_V6 = "https://www.iana.org/assignments/iana-ipv6-special-registry/"
_RFC_IDNA = "https://www.rfc-editor.org/rfc/rfc5891"
_RFC_EMAIL = "https://www.rfc-editor.org/rfc/rfc5322"
_E164 = "https://www.itu.int/rec/T-REC-E.164"


class IdentifyModule(BaseModule):
    name = "core.identify"
    title = "Идентификация цели"
    description = "Нормализованная форма и структурные свойства идентификатора (офлайн)."
    target_types = frozenset(TargetType)
    limitations = ("Проверяется только формат идентификатора, а не его существование.",)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        add = out.findings.append
        d = target.details
        match target.type:
            case TargetType.IP:
                registry = _IANA_V4 if d.get("version") == 4 else _IANA_V6
                scope = _ip_scope(target)
                add(
                    self.finding(
                        target,
                        "ip.version",
                        d.get("version"),
                        Confidence.CONFIRMED,
                        "Python ipaddress",
                        registry,
                        f"Адрес синтаксически корректен как IPv{d.get('version')}.",
                        exclusive=True,
                    )
                )
                add(
                    self.finding(
                        target,
                        "ip.scope",
                        scope,
                        Confidence.CONFIRMED,
                        "IANA Special-Purpose Address Registry",
                        registry,
                        f"По реестру IANA адрес относится к категории «{scope}».",
                        exclusive=True,
                    )
                )
            case TargetType.DOMAIN:
                add(
                    self.finding(
                        target,
                        "domain.ascii",
                        target.normalized,
                        Confidence.CONFIRMED,
                        "IDNA (RFC 5891)",
                        _RFC_IDNA,
                        "Каноническая ASCII-форма (punycode) имени домена.",
                        exclusive=True,
                    )
                )
                if d.get("unicode") != target.normalized:
                    add(
                        self.finding(
                            target,
                            "domain.unicode",
                            d.get("unicode"),
                            Confidence.CONFIRMED,
                            "IDNA (RFC 5891)",
                            _RFC_IDNA,
                            "Unicode-представление интернационализированного домена.",
                            exclusive=True,
                        )
                    )
                add(
                    self.finding(
                        target,
                        "domain.tld",
                        d.get("tld"),
                        Confidence.CONFIRMED,
                        "IDNA (RFC 5891)",
                        _RFC_IDNA,
                        "Последняя метка имени (домен верхнего уровня).",
                        exclusive=True,
                    )
                )
            case TargetType.EMAIL:
                add(
                    self.finding(
                        target,
                        "email.domain",
                        d.get("domain"),
                        Confidence.CONFIRMED,
                        "RFC 5322 address syntax",
                        _RFC_EMAIL,
                        "Доменная часть адреса после последнего «@».",
                        exclusive=True,
                    )
                )
                add(
                    self.finding(
                        target,
                        "email.local_part",
                        d.get("local_part"),
                        Confidence.CONFIRMED,
                        "RFC 5322 address syntax",
                        _RFC_EMAIL,
                        "Локальная часть адреса до «@».",
                        exclusive=True,
                    )
                )
            case TargetType.PHONE:
                if d.get("region_known"):
                    add(
                        self.finding(
                            target,
                            "phone.e164",
                            target.normalized,
                            Confidence.CONFIRMED,
                            "libphonenumber (offline metadata)",
                            _E164,
                            "Номер приведён к международному формату E.164.",
                            exclusive=True,
                        )
                    )
                else:
                    out.limitations.append(
                        "Страна номера неизвестна: укажите номер с «+» или задайте "
                        "OSINT_DEFAULT_REGION."
                    )
            case TargetType.IMAGE:
                add(
                    self.finding(
                        target,
                        "image.file_size",
                        d.get("size_bytes"),
                        Confidence.CONFIRMED,
                        "Файловая система",
                        Path(target.normalized).as_uri(),
                        "Размер файла в байтах по данным файловой системы.",
                        exclusive=True,
                    )
                )
            case TargetType.USERNAME | TargetType.NAME:
                pass
        return out


def _ip_scope(target: Target) -> str:
    d = target.details
    if d.get("is_loopback"):
        return "loopback"
    if d.get("is_link_local"):
        return "link-local"
    if d.get("is_multicast"):
        return "multicast"
    if d.get("is_private"):
        return "private"
    if d.get("is_reserved"):
        return "reserved"
    return "global" if d.get("is_global") else "special-purpose"

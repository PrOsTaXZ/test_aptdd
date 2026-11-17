"""Offline IP geolocation and ASN from local DB-IP Lite databases (no network access)."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.data.dbip import ATTRIBUTION, LICENSE_URL, DbipKind, db_path, lookup, status
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.ip.rdap import non_global_reason


def _name(node: Any, lang: str = "ru") -> str | None:
    if not isinstance(node, dict):
        return None
    names = node.get("names")
    if isinstance(names, dict):
        value = names.get(lang) or names.get("en")
        return str(value) if value else None
    return None


def _network(ip: str, prefix: int | None) -> str | None:
    if prefix is None:
        return None
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _source(settings: Settings, kind: DbipKind) -> tuple[str, str]:
    st = status(settings.geo_dir, kind)
    version = st.version or st.build_date or "неизвестная версия"
    return f"DB-IP {kind.value.capitalize()} Lite {version} (локально)", db_path(
        settings.geo_dir, kind
    ).as_uri()


class GeoOfflineModule(BaseModule):
    name = "ip.geo"
    title = "Геолокация IP (DB-IP Lite, офлайн)"
    description = (
        "Страна и, при наличии City-базы, регион/город по локальной базе DB-IP Lite. "
        "Без сетевых запросов."
    )
    target_types = frozenset({TargetType.IP})
    limitations: ClassVar[tuple[str, ...]] = (
        "Геолокация по базе — оценка: точность на уровне города низкая, для мобильных сетей, VPN "
        "и облаков возможны ошибки. Координаты — центр населённого пункта, не местоположение "
        "устройства или человека.",
        ATTRIBUTION,
    )

    def _kind(self, settings: Settings) -> DbipKind | None:
        for kind in (DbipKind.CITY, DbipKind.COUNTRY):
            if db_path(settings.geo_dir, kind).is_file():
                return kind
        return None

    def availability(self, settings: Settings) -> Availability:
        if self._kind(settings) is None:
            return Availability(False, "нет базы DB-IP: выполните «osint data update»")
        return Availability(True)

    def applicability(self, target: Target, settings: Settings) -> str | None:
        return non_global_reason(target)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        kind = self._kind(ctx.settings)
        if kind is None:  # pragma: no cover - guarded by availability()
            out.errors.append("База DB-IP не найдена")
            return out
        record, prefix = await asyncio.to_thread(
            lookup, db_path(ctx.settings.geo_dir, kind), target.normalized
        )
        src, url = _source(ctx.settings, kind)
        if not record:
            out.limitations.append("Адрес отсутствует в базе DB-IP — геолокация не определена.")
            return out
        network = _network(target.normalized, prefix)
        suffix = f" Диапазон базы: {network}." if network else ""
        country = record.get("country")
        if isinstance(country, dict) and country.get("iso_code"):
            out.findings.append(
                self.finding(
                    target,
                    "ip.geo_country",
                    {"code": country["iso_code"], "name": _name(country)},
                    Confidence.LIKELY,
                    src,
                    url,
                    "Страна по базе геолокации DB-IP (оценка, не регистрационные данные)." + suffix,
                    exclusive=True,
                )
            )
        city = _name(record.get("city"))
        subdivisions = record.get("subdivisions")
        region = _name(subdivisions[0]) if isinstance(subdivisions, list) and subdivisions else None
        raw_location = record.get("location")
        location: dict[str, Any] = raw_location if isinstance(raw_location, dict) else {}
        if city or region:
            value: dict[str, JsonValue] = {"region": region, "city": city}
            lat, lon = location.get("latitude"), location.get("longitude")
            if isinstance(lat, int | float) and isinstance(lon, int | float):
                value["approx_latitude"] = round(float(lat), 3)
                value["approx_longitude"] = round(float(lon), 3)
            out.findings.append(
                self.finding(
                    target,
                    "ip.geo_city",
                    value,
                    Confidence.UNVERIFIED,
                    src,
                    url,
                    "Регион и город по базе DB-IP City Lite — низкая точность; не использовать как "
                    "местоположение человека." + suffix,
                    exclusive=True,
                )
            )
        if kind is DbipKind.COUNTRY:
            out.limitations.append(
                "Установлена только Country-база: город не определяется (osint data update --city)."
            )
        return out


class AsnOfflineModule(BaseModule):
    name = "ip.asn"
    title = "Автономная система (ASN, DB-IP Lite, офлайн)"
    description = "Номер и организация автономной системы, анонсирующей адрес. Без сети."
    target_types = frozenset({TargetType.IP})
    limitations: ClassVar[tuple[str, ...]] = (
        "Данные о маршрутизации обновляются в базе раз в месяц: ASN мог смениться.",
        "ASN показывает оператора сети (провайдера, хостинг), а не пользователя адреса.",
        ATTRIBUTION,
    )

    def availability(self, settings: Settings) -> Availability:
        if not db_path(settings.geo_dir, DbipKind.ASN).is_file():
            return Availability(False, "нет базы DB-IP ASN: выполните «osint data update»")
        return Availability(True)

    def applicability(self, target: Target, settings: Settings) -> str | None:
        return non_global_reason(target)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        path = db_path(ctx.settings.geo_dir, DbipKind.ASN)
        record, prefix = await asyncio.to_thread(lookup, path, target.normalized)
        src, url = _source(ctx.settings, DbipKind.ASN)
        number = (record or {}).get("autonomous_system_number")
        if not isinstance(number, int):
            out.limitations.append("Адрес отсутствует в базе DB-IP ASN.")
            return out
        org = (record or {}).get("autonomous_system_organization")
        network = _network(target.normalized, prefix)
        out.findings.append(
            self.finding(
                target,
                "ip.asn",
                {"asn": f"AS{number}", "organization": org, "prefix": network},
                Confidence.LIKELY,
                src,
                url,
                f"Адрес входит в префикс {network}, анонсируемый AS{number} по данным "
                "DB-IP ASN Lite (собраны из таблиц BGP).",
                exclusive=True,
            )
        )
        return out


__all__ = ["LICENSE_URL", "AsnOfflineModule", "GeoOfflineModule"]

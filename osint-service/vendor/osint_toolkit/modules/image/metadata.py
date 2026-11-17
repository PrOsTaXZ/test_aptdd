"""Embedded metadata of a local image: EXIF, GPS, XMP, PNG text chunks, comments, C2PA marker.

Findings state what the *file contains*. A camera serial number or an "Artist" field is reported as
metadata content, never as proof of who took the picture: such fields are easy to edit and are often
inherited from device settings.

XMP is parsed with the standard library: expat ≥ 2.4.1 protects against entity-expansion attacks,
documents containing DTDs/entities are rejected outright, and packets over 1 MB are skipped.
"""

from __future__ import annotations

import asyncio
import math
import pyexpat
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

from PIL import ExifTags

from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.image._common import ImageReadError, clean_text, open_image

B = ExifTags.Base
G = ExifTags.GPS
EXIF_SRC = "EXIF (метаданные файла)"
GPS_SRC = "EXIF GPS (метаданные файла)"
XMP_SRC = "XMP (метаданные файла)"
MAX_XMP = 1024 * 1024
C2PA_SCAN_BYTES = 4 * 1024 * 1024

NS = {
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "photoshop": "http://ns.adobe.com/photoshop/1.0/",
    "exif": "http://ns.adobe.com/exif/1.0/",
    "tiff": "http://ns.adobe.com/tiff/1.0/",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
    "iptcExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
}
AI_SOURCE_TYPES = (
    "trainedAlgorithmicMedia",
    "compositeSynthetic",
    "algorithmicMedia",
    "compositeWithTrainedAlgorithmicMedia",
)
GENERATOR_KEYS = frozenset(
    {
        "parameters",
        "prompt",
        "workflow",
        "dream",
        "sd-metadata",
        "invokeai_metadata",
        "negative_prompt",
    }
)
_XMP_DATE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})(?:T(\d{2}:\d{2})(:\d{2})?(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?$"
)
EXPAT_SAFE = tuple(int(x) for x in pyexpat.version_info) >= (2, 4, 1)


# --------------------------------------------------------------------------- parsing helpers
def parse_exif_datetime(raw: str | None) -> str | None:
    """'2024:05:01 12:30:00' → '2024-05-01T12:30:00' (local time as recorded, no zone)."""
    if not raw:
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M"):
        try:
            return datetime.strptime(raw.strip()[:19], fmt).isoformat()  # naive by EXIF spec
        except ValueError:
            continue
    return None


def parse_xmp_datetime(raw: str | None) -> tuple[str | None, str | None]:
    """XMP date → (local ISO datetime without zone, UTC offset or None)."""
    if not raw:
        return None, None
    match = _XMP_DATE_RE.match(raw.strip())
    if not match:
        return None, None
    date, hm, sec, zone = match.groups()
    if hm is None:
        return None, None  # date only — not comparable with a full timestamp
    return f"{date}T{hm}{sec or ':00'}", ("+00:00" if zone == "Z" else zone)


def _rational(value: Any) -> float | None:
    try:
        number: float = float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    return None if math.isnan(number) or math.isinf(number) else number


def gps_to_decimal(dms: Any, ref: Any) -> float | None:
    if dms is None:
        return None
    parts = list(dms) if isinstance(dms, tuple | list) else [dms]
    values: list[float] = []
    for part in parts[:3]:
        number = _rational(part)
        if number is None or number < 0:
            return None
        values.append(number)
    if not values:
        return None
    degrees: float = sum(v / (60.0**i) for i, v in enumerate(values))
    ref_text = clean_text(ref) or ""
    if ref_text.upper().startswith(("S", "W")):
        degrees = -degrees
    return round(degrees, 7)


def _xmp_values(root: ET.Element, prefix: str, name: str) -> list[str]:
    tag = f"{{{NS[prefix]}}}{name}"
    values: list[str] = []
    for desc in root.iter(f"{{{NS['rdf']}}}Description"):
        if tag in desc.attrib:
            values.append(desc.attrib[tag])
        for element in desc.iter(tag):
            items = list(element.iter(f"{{{NS['rdf']}}}li"))
            if items:
                values.extend(i.text or "" for i in items)
            elif element.text and element.text.strip():
                values.append(element.text)
    return [v for v in (clean_text(x) for x in values) if v]


def parse_xmp(raw: bytes | str) -> dict[str, Any] | None:
    data = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
    if len(data) > MAX_XMP or not EXPAT_SAFE:
        return None
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        return None
    start = data.find(b"<x:xmpmeta")
    if start == -1:
        start = data.find(b"<rdf:RDF")
    end_tag = b"</x:xmpmeta>" if data[start:].startswith(b"<x:xmpmeta") else b"</rdf:RDF>"
    end = data.find(end_tag, start)
    if start == -1 or end == -1:
        return None
    try:
        # Safe: DTD/entities rejected above and expat >= 2.4.1 limits amplification.
        root = ET.fromstring(data[start : end + len(end_tag)])  # noqa: S314
    except ET.ParseError:
        return None
    history_agents = _xmp_values(root, "stEvt", "softwareAgent")
    history = list(root.iter(f"{{{NS['xmpMM']}}}History"))
    entries = sum(len(list(h.iter(f"{{{NS['rdf']}}}li"))) for h in history)
    return {
        "creator_tool": _xmp_values(root, "xmp", "CreatorTool"),
        "create_date": _xmp_values(root, "xmp", "CreateDate"),
        "modify_date": _xmp_values(root, "xmp", "ModifyDate"),
        "date_created": _xmp_values(root, "photoshop", "DateCreated")
        + _xmp_values(root, "exif", "DateTimeOriginal"),
        "creator": _xmp_values(root, "dc", "creator"),
        "rights": _xmp_values(root, "dc", "rights"),
        "make": _xmp_values(root, "tiff", "Make"),
        "model": _xmp_values(root, "tiff", "Model"),
        "digital_source_type": _xmp_values(root, "iptcExt", "DigitalSourceType"),
        "history_entries": entries,
        "history_agents": list(dict.fromkeys(history_agents)),
    }


def read_metadata(path: Path) -> dict[str, Any]:
    with open_image(path) as image:
        exif = image.getexif()
        base = {int(k): v for k, v in exif.items()}
        sub = {int(k): v for k, v in exif.get_ifd(ExifTags.IFD.Exif).items()}
        gps = {int(k): v for k, v in exif.get_ifd(ExifTags.IFD.GPSInfo).items()}
        texts: dict[str, str] = {}
        png_text = getattr(image, "text", None)  # PNG tEXt/iTXt/zTXt (loads the file)
        if isinstance(png_text, dict):
            for key, value in png_text.items():
                if key.lower() == "xml:com.adobe.xmp":
                    continue
                text = clean_text(value)
                if text:
                    texts[str(key)[:80]] = text
        comment = clean_text(image.info.get("comment"))
        xmp_raw = image.info.get("xmp") or (png_text or {}).get("XML:com.adobe.xmp")
        fmt = image.format
    with path.open("rb") as handle:
        head = handle.read(C2PA_SCAN_BYTES)
    return {
        "format": fmt,
        "base": base,
        "exif": sub,
        "gps": gps,
        "texts": texts,
        "comment": comment,
        "xmp_present": bool(xmp_raw),
        "xmp": parse_xmp(xmp_raw) if xmp_raw else None,
        "c2pa": b"jumb" in head and b"c2pa" in head,
    }


# --------------------------------------------------------------------------- module
class ImageMetadataModule(BaseModule):
    name = "image.metadata"
    title = "Метаданные изображения (EXIF, GPS, XMP)"
    description = (
        "EXIF (камера, время, ПО, серийные номера), GPS-координаты, XMP (редакторы, история, "
        "признаки генерации ИИ), текстовые блоки PNG и маркер C2PA. Локально."
    )
    target_types = frozenset({TargetType.IMAGE})
    limitations = (
        "Метаданные легко изменить или удалить: они описывают содержимое файла, а не "
        "достоверно — снимок, устройство или автора.",
        "Имена, серийные номера и координаты в метаданных не устанавливают личность человека.",
    )

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        path = Path(target.normalized)
        try:
            meta = await asyncio.to_thread(read_metadata, path)
        except ImageReadError as exc:
            out.errors.append(str(exc))
            return out
        uri = path.as_uri()
        sensitive: list[str] = []
        self._exif(target, uri, meta, out, sensitive)
        self._gps(target, uri, meta["gps"], out, sensitive)
        self._xmp(target, uri, meta, out, sensitive)
        self._texts(target, uri, meta, out)
        if meta["c2pa"]:
            out.findings.append(
                self.finding(
                    target,
                    "image.c2pa_marker",
                    True,
                    Confidence.LIKELY,
                    "Сигнатуры JUMBF/C2PA",
                    uri,
                    "В файле найдены байтовые маркеры JUMBF и C2PA (Content Credentials). Подпись "
                    "манифеста не проверялась.",
                )
            )

        has_meta = bool(
            meta["base"]
            or meta["exif"]
            or meta["gps"]
            or meta["xmp_present"]
            or meta["texts"]
            or meta["comment"]
        )
        out.findings.append(
            self.finding(
                target,
                "image.metadata_present",
                has_meta,
                Confidence.CONFIRMED,
                EXIF_SRC,
                uri,
                "В файле есть встроенные метаданные."
                if has_meta
                else "Встроенных метаданных нет. Их часто удаляют соцсети, мессенджеры "
                "и редакторы.",
                exclusive=True,
            )
        )
        if sensitive:
            out.findings.append(
                self.finding(
                    target,
                    "image.privacy_exposure",
                    sorted(set(sensitive)),
                    Confidence.CONFIRMED,
                    EXIF_SRC,
                    uri,
                    "Поля, которые при публикации файла могут раскрыть местоположение, "
                    "устройство или имя. Для аудита собственных файлов: удалите их перед "
                    "публикацией.",
                )
            )
        return out

    # ------------------------------------------------------------------ sections
    def _exif(
        self,
        target: Target,
        uri: str,
        meta: dict[str, Any],
        out: ModuleOutput,
        sensitive: list[str],
    ) -> None:
        base, sub = meta["base"], meta["exif"]
        add = out.findings.append

        def text(tag: int, ifd: dict[int, Any]) -> str | None:
            return clean_text(ifd.get(tag))

        simple = (
            ("image.camera_make", B.Make, base, True, "Производитель камеры (поле Make).", None),
            ("image.camera_model", B.Model, base, True, "Модель камеры (поле Model).", None),
            (
                "image.software",
                B.Software,
                base,
                False,
                "Программа, записавшая файл (Software).",
                None,
            ),
            ("image.host_computer", B.HostComputer, base, False, "Поле HostComputer.", "host"),
            (
                "image.exif_artist",
                B.Artist,
                base,
                False,
                "Поле Artist. Обычно задаётся в настройках камеры или редактора и не доказывает "
                "авторство.",
                "artist",
            ),
            ("image.exif_copyright", B.Copyright, base, False, "Поле Copyright.", None),
            ("image.description", B.ImageDescription, base, False, "Поле ImageDescription.", None),
            ("image.lens", B.LensModel, sub, True, "Модель объектива (LensModel).", None),
            (
                "image.camera_serial",
                B.BodySerialNumber,
                sub,
                True,
                "Серийный номер корпуса камеры (BodySerialNumber).",
                "camera_serial",
            ),
            (
                "image.lens_serial",
                B.LensSerialNumber,
                sub,
                True,
                "Серийный номер объектива (LensSerialNumber).",
                "lens_serial",
            ),
            (
                "image.camera_owner",
                B.CameraOwnerName,
                sub,
                False,
                "Поле CameraOwnerName из настроек устройства. Не доказывает, кто сделал снимок.",
                "owner_name",
            ),
            (
                "image.unique_id",
                B.ImageUniqueID,
                sub,
                True,
                "Уникальный идентификатор снимка (ImageUniqueID).",
                "unique_id",
            ),
            ("image.user_comment", B.UserComment, sub, False, "Поле UserComment.", "user_comment"),
        )
        for attribute, tag, ifd, exclusive, evidence, flag in simple:
            value = text(tag, ifd)
            if value:
                add(
                    self.finding(
                        target,
                        attribute,
                        value,
                        Confidence.CONFIRMED,
                        EXIF_SRC,
                        uri,
                        evidence,
                        exclusive=exclusive,
                    )
                )
                if flag:
                    sensitive.append(flag)

        original = text(B.DateTimeOriginal, sub)
        capture = parse_exif_datetime(original)
        if original:
            offset = text(B.OffsetTimeOriginal, sub)
            evidence = "Время съёмки по часам камеры (DateTimeOriginal), без часового пояса"
            evidence += f"; смещение OffsetTimeOriginal: {offset}." if offset else "."
            if capture is None:
                evidence = f"DateTimeOriginal в нестандартном формате: «{original}»."
            add(
                self.finding(
                    target,
                    "image.capture_time",
                    capture or original,
                    Confidence.CONFIRMED,
                    EXIF_SRC,
                    uri,
                    evidence,
                    exclusive=True,
                )
            )
        modified = text(B.DateTime, base)
        if modified:
            add(
                self.finding(
                    target,
                    "image.modified_time",
                    parse_exif_datetime(modified) or modified,
                    Confidence.CONFIRMED,
                    EXIF_SRC,
                    uri,
                    "Время последнего изменения файла программой (поле DateTime).",
                    exclusive=True,
                )
            )
        digitized = parse_exif_datetime(text(B.DateTimeDigitized, sub))
        if capture and modified and (mod := parse_exif_datetime(modified)) and mod > capture:
            out.limitations.append(
                "Время изменения (DateTime) позже времени съёмки: файл, вероятно, редактировался "
                "или пересохранялся."
            )

        settings: dict[str, JsonValue] = {}
        if (exposure := _rational(sub.get(B.ExposureTime))) is not None and exposure > 0:
            settings["exposure_s"] = round(exposure, 6)
        if (fnum := _rational(sub.get(B.FNumber))) is not None:
            settings["f_number"] = round(fnum, 1)
        if (iso := sub.get(B.ISOSpeedRatings)) is not None:
            settings["iso"] = int(iso[0] if isinstance(iso, tuple) else iso)
        if (focal := _rational(sub.get(B.FocalLength))) is not None:
            settings["focal_length_mm"] = round(focal, 1)
        if (flash := sub.get(B.Flash)) is not None:
            settings["flash_fired"] = bool(int(flash) & 1)
        if (orientation := base.get(B.Orientation)) is not None:
            settings["orientation"] = int(orientation)
        if digitized:
            settings["digitized_time"] = digitized
        if settings:
            add(
                self.finding(
                    target,
                    "image.capture_settings",
                    settings,
                    Confidence.CONFIRMED,
                    EXIF_SRC,
                    uri,
                    "Параметры съёмки, записанные камерой.",
                )
            )

    def _gps(
        self, target: Target, uri: str, gps: dict[int, Any], out: ModuleOutput, sensitive: list[str]
    ) -> None:
        if not gps:
            return
        add = out.findings.append
        lat = gps_to_decimal(gps.get(G.GPSLatitude), gps.get(G.GPSLatitudeRef))
        lon = gps_to_decimal(gps.get(G.GPSLongitude), gps.get(G.GPSLongitudeRef))
        if lat is None or lon is None:
            if G.GPSLatitude in gps or G.GPSLongitude in gps:
                out.limitations.append("GPS-координаты в EXIF повреждены или неполны.")
        elif not (-90 <= lat <= 90 and -180 <= lon <= 180):
            out.limitations.append(f"GPS-координаты вне допустимого диапазона: {lat}, {lon}.")
        elif lat == 0 and lon == 0:
            out.limitations.append("GPS-координаты равны 0,0 — обычно это заглушка устройства.")
        else:
            sensitive.append("gps")
            value: dict[str, JsonValue] = {
                "latitude": lat,
                "longitude": lon,
                "map_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
            }
            alt = _rational(gps.get(G.GPSAltitude))
            if alt is not None:
                below = gps.get(G.GPSAltitudeRef) in (1, b"\x01")
                value["altitude_m"] = round(-alt if below else alt, 1)
            if (datum := clean_text(gps.get(G.GPSMapDatum))) is not None:
                value["datum"] = datum
            add(
                self.finding(
                    target,
                    "image.gps_coordinates",
                    value,
                    Confidence.CONFIRMED,
                    GPS_SRC,
                    uri,
                    "Координаты записаны в EXIF. Они могли быть изменены, указывать на место "
                    "устройства с погрешностью или быть добавлены позже. Ссылка на карту дана для "
                    "ручной проверки и не открывается автоматически.",
                    exclusive=True,
                )
            )
        date = clean_text(gps.get(G.GPSDateStamp))
        stamp = gps.get(G.GPSTimeStamp)
        if date and isinstance(stamp, tuple) and len(stamp) == 3:
            parts = [_rational(p) for p in stamp]
            if all(p is not None for p in parts):
                h, m, s = (int(p) for p in parts)  # type: ignore[arg-type]
                try:
                    utc = datetime.strptime(f"{date} {h:02d}:{m:02d}:{s:02d}", "%Y:%m:%d %H:%M:%S")
                    add(
                        self.finding(
                            target,
                            "image.gps_time_utc",
                            utc.isoformat() + "Z",
                            Confidence.CONFIRMED,
                            GPS_SRC,
                            uri,
                            "Время по спутникам GPS (UTC) из EXIF.",
                            exclusive=True,
                        )
                    )
                except ValueError:
                    out.limitations.append("GPSDateStamp/GPSTimeStamp в нестандартном формате.")
        direction = _rational(gps.get(G.GPSImgDirection))
        if direction is not None:
            add(
                self.finding(
                    target,
                    "image.gps_direction",
                    round(direction, 1),
                    Confidence.CONFIRMED,
                    GPS_SRC,
                    uri,
                    "Направление камеры в градусах (GPSImgDirection).",
                    exclusive=True,
                )
            )

    def _xmp(
        self,
        target: Target,
        uri: str,
        meta: dict[str, Any],
        out: ModuleOutput,
        sensitive: list[str],
    ) -> None:
        if not meta["xmp_present"]:
            return
        xmp = meta["xmp"]
        if xmp is None:
            out.limitations.append(
                "XMP-блок присутствует, но не разобран (повреждён, слишком велик или содержит "
                "DTD, отклонённый из соображений безопасности)."
            )
            return
        add = out.findings.append
        if xmp["creator_tool"]:
            add(
                self.finding(
                    target,
                    "image.xmp_creator_tool",
                    xmp["creator_tool"][0],
                    Confidence.CONFIRMED,
                    XMP_SRC,
                    uri,
                    "Программа, создавшая файл (xmp:CreatorTool).",
                )
            )
        if xmp["creator"]:
            sensitive.append("xmp_creator")
            add(
                self.finding(
                    target,
                    "image.xmp_creator",
                    xmp["creator"],
                    Confidence.CONFIRMED,
                    XMP_SRC,
                    uri,
                    "Поле dc:creator. Не доказывает авторство.",
                )
            )
        if xmp["rights"]:
            add(
                self.finding(
                    target,
                    "image.xmp_rights",
                    xmp["rights"][0],
                    Confidence.CONFIRMED,
                    XMP_SRC,
                    uri,
                    "Поле dc:rights (права).",
                )
            )
        for key, attribute, label in (
            ("make", "image.camera_make", "tiff:Make"),
            ("model", "image.camera_model", "tiff:Model"),
        ):
            if xmp[key]:
                add(
                    self.finding(
                        target,
                        attribute,
                        xmp[key][0],
                        Confidence.CONFIRMED,
                        XMP_SRC,
                        uri,
                        f"Камера по XMP ({label}).",
                        exclusive=True,
                    )
                )
        for raw in xmp["date_created"][:1]:
            local, offset = parse_xmp_datetime(raw)
            if local:
                evidence = "Время съёмки по XMP (photoshop:DateCreated / exif:DateTimeOriginal)"
                evidence += f"; смещение {offset}." if offset else "."
                add(
                    self.finding(
                        target,
                        "image.capture_time",
                        local,
                        Confidence.CONFIRMED,
                        XMP_SRC,
                        uri,
                        evidence,
                        exclusive=True,
                    )
                )
        for raw in xmp["modify_date"][:1]:
            local, offset = parse_xmp_datetime(raw)
            if local:
                add(
                    self.finding(
                        target,
                        "image.xmp_modify_time",
                        local + (offset or ""),
                        Confidence.CONFIRMED,
                        XMP_SRC,
                        uri,
                        "Время изменения по XMP (xmp:ModifyDate).",
                    )
                )
        if xmp["history_entries"]:
            add(
                self.finding(
                    target,
                    "image.edit_history",
                    {"entries": xmp["history_entries"], "agents": xmp["history_agents"]},
                    Confidence.CONFIRMED,
                    XMP_SRC,
                    uri,
                    "История операций с файлом (xmpMM:History): файл обрабатывался "
                    "указанными программами.",
                )
            )
        for source_type in xmp["digital_source_type"][:1]:
            declared_ai = source_type.rsplit("/", 1)[-1] in AI_SOURCE_TYPES
            add(
                self.finding(
                    target,
                    "image.digital_source_type",
                    source_type,
                    Confidence.CONFIRMED,
                    XMP_SRC,
                    uri,
                    "Метаданные заявляют, что изображение создано или изменено "
                    "генеративной моделью (IPTC DigitalSourceType). Заявление может "
                    "быть удалено или подделано."
                    if declared_ai
                    else "Тип источника изображения по IPTC (DigitalSourceType).",
                    exclusive=True,
                )
            )

    def _texts(self, target: Target, uri: str, meta: dict[str, Any], out: ModuleOutput) -> None:
        add = out.findings.append
        if meta["texts"]:
            add(
                self.finding(
                    target,
                    "image.png_text",
                    meta["texts"],
                    Confidence.CONFIRMED,
                    "PNG text chunks (tEXt/iTXt/zTXt)",
                    uri,
                    "Текстовые блоки, записанные в PNG программой-создателем.",
                )
            )
            keys = {k.lower() for k in meta["texts"]}
            hits = sorted(keys & GENERATOR_KEYS)
            if hits:
                add(
                    self.finding(
                        target,
                        "image.generator_metadata",
                        hits,
                        Confidence.LIKELY,
                        "PNG text chunks",
                        uri,
                        "Ключи вроде «parameters», «prompt» или «workflow» характерны "
                        "для генераторов изображений (Stable Diffusion, ComfyUI и др.). "
                        "Это косвенный признак, а не доказательство генерации.",
                    )
                )
        if meta["comment"]:
            add(
                self.finding(
                    target,
                    "image.comment",
                    meta["comment"],
                    Confidence.CONFIRMED,
                    "Комментарий файла (COM/Comment)",
                    uri,
                    "Встроенный текстовый комментарий.",
                )
            )


__all__ = ["ImageMetadataModule", "gps_to_decimal", "parse_exif_datetime", "parse_xmp"]

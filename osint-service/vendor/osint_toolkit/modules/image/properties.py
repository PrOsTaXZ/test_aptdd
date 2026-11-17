"""Technical characteristics of a local image (format by signature, dimensions, colour, ICC …)."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from typing import Any

import PIL
from PIL import ImageCms

from osint_toolkit.core.models import Confidence, JsonValue, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.image._common import (
    FORMAT_EXTENSIONS,
    HEIF_SUPPORT,
    ImageReadError,
    clean_text,
    open_image,
)

PILLOW = f"Pillow {PIL.__version__}"

BITS_PER_MODE = {
    "1": 1,
    "L": 8,
    "P": 8,
    "RGB": 8,
    "RGBA": 8,
    "CMYK": 8,
    "YCbCr": 8,
    "LAB": 8,
    "HSV": 8,
    "I": 32,
    "F": 32,
    "I;16": 16,
    "I;16B": 16,
    "I;16L": 16,
    "LA": 8,
    "PA": 8,
    "RGBX": 8,
    "RGBa": 8,
    "La": 8,
}


def read_properties(path: Path) -> dict[str, Any]:
    with open_image(path) as image:
        props: dict[str, Any] = {
            "format": image.format,
            "mime": image.get_format_mimetype() if hasattr(image, "get_format_mimetype") else None,
            "width": image.width,
            "height": image.height,
            "mode": image.mode,
            "bands": len(image.getbands()),
            "bits_per_channel": BITS_PER_MODE.get(image.mode),
            "frames": getattr(image, "n_frames", 1),
            "dpi": image.info.get("dpi"),
            "progressive": bool(image.info.get("progressive") or image.info.get("progression")),
            "interlaced": bool(image.info.get("interlace")),
            "has_transparency": image.has_transparency_data,
            "icc_description": None,
        }
        icc = image.info.get("icc_profile")
        if icc:
            try:
                profile = ImageCms.ImageCmsProfile(io.BytesIO(icc))
                props["icc_description"] = clean_text(ImageCms.getProfileDescription(profile))
            except (ImageCms.PyCMSError, OSError, ValueError, TypeError):
                props["icc_description"] = "встроенный профиль (не удалось прочитать описание)"
        return props


class ImagePropertiesModule(BaseModule):
    name = "image.properties"
    title = "Технические характеристики изображения"
    description = (
        "Реальный формат по сигнатуре файла, несоответствие расширению, размеры, цветовая "
        "модель, глубина цвета, кадры, DPI, ICC-профиль (локально)."
    )
    target_types = frozenset({TargetType.IMAGE})

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        path = Path(target.normalized)
        uri = path.as_uri()
        try:
            props = await asyncio.to_thread(read_properties, path)
        except ImageReadError as exc:
            if path.suffix.lower() in {".heic", ".heif"} and not HEIF_SUPPORT:
                out.limitations.append("Для HEIC нужен пакет pillow-heif.")
            out.errors.append(str(exc))
            return out

        add = out.findings.append
        fmt = props["format"] or "неизвестен"
        add(
            self.finding(
                target,
                "image.format",
                fmt,
                Confidence.CONFIRMED,
                PILLOW,
                uri,
                "Формат определён по сигнатуре содержимого файла, а не по расширению.",
                exclusive=True,
            )
        )
        expected = FORMAT_EXTENSIONS.get(fmt)
        ext = path.suffix.lower()
        if expected is not None and ext not in expected:
            add(
                self.finding(
                    target,
                    "image.extension_mismatch",
                    {"extension": ext, "actual_format": fmt},
                    Confidence.CONFIRMED,
                    PILLOW,
                    uri,
                    f"Расширение «{ext}» не соответствует реальному формату {fmt}: файл "
                    "мог быть переименован или сконвертирован.",
                    exclusive=True,
                )
            )
        if props["mime"]:
            add(
                self.finding(
                    target,
                    "image.mime_type",
                    props["mime"],
                    Confidence.CONFIRMED,
                    PILLOW,
                    uri,
                    "MIME-тип по реальному формату.",
                    exclusive=True,
                )
            )
        dims: JsonValue = {
            "width": props["width"],
            "height": props["height"],
            "megapixels": round(props["width"] * props["height"] / 1e6, 2),
        }
        add(
            self.finding(
                target,
                "image.dimensions",
                dims,
                Confidence.CONFIRMED,
                PILLOW,
                uri,
                "Размеры в пикселях из заголовка файла.",
                exclusive=True,
            )
        )
        color: JsonValue = {
            "mode": props["mode"],
            "bands": props["bands"],
            "bits_per_channel": props["bits_per_channel"],
            "transparency": props["has_transparency"],
        }
        add(
            self.finding(
                target,
                "image.color",
                color,
                Confidence.CONFIRMED,
                PILLOW,
                uri,
                "Цветовая модель, число каналов и глубина цвета.",
                exclusive=True,
            )
        )
        if props["frames"] > 1:
            add(
                self.finding(
                    target,
                    "image.frames",
                    props["frames"],
                    Confidence.CONFIRMED,
                    PILLOW,
                    uri,
                    "Файл содержит несколько кадров (анимация или multi-picture).",
                    exclusive=True,
                )
            )
        if props["dpi"]:
            dpi = [round(float(v), 2) for v in props["dpi"]]
            add(
                self.finding(
                    target,
                    "image.dpi",
                    dpi,
                    Confidence.CONFIRMED,
                    PILLOW,
                    uri,
                    "Плотность (DPI), записанная в файле; на сам снимок не влияет.",
                    exclusive=True,
                )
            )
        if props["progressive"] or props["interlaced"]:
            add(
                self.finding(
                    target,
                    "image.encoding",
                    "progressive" if props["progressive"] else "interlaced",
                    Confidence.CONFIRMED,
                    PILLOW,
                    uri,
                    "Способ кодирования (прогрессивный JPEG / чересстрочный PNG).",
                )
            )
        if props["icc_description"]:
            add(
                self.finding(
                    target,
                    "image.icc_profile",
                    props["icc_description"],
                    Confidence.CONFIRMED,
                    PILLOW,
                    uri,
                    "Встроенный цветовой профиль ICC.",
                    exclusive=True,
                )
            )
        return out

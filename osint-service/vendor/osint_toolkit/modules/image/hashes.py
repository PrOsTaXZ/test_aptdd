"""Cryptographic and perceptual hashes of a local image.

Cryptographic hashes (SHA-256, SHA-1, MD5) identify the exact file and match hash databases; MD5 and
SHA-1 are used for lookup compatibility only, never for security. Perceptual hashes (aHash, dHash)
are computed with Pillow alone — a few lines of well-known algorithms, not worth a NumPy/SciPy
dependency — and help find visually similar copies.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from PIL import Image

from osint_toolkit.core.models import Confidence, Target, TargetType
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.image._common import ImageReadError, open_image

CHUNK = 1024 * 1024


def file_hashes(path: Path) -> dict[str, str]:
    digests = {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "md5": hashlib.md5(usedforsecurity=False),
    }
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def _bits_to_hex(bits: list[bool]) -> str:
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return f"{value:0{len(bits) // 4}x}"


def average_hash(image: Image.Image, size: int = 8) -> str:
    small = image.convert("L").resize((size, size), Image.Resampling.LANCZOS)
    pixels = list(small.tobytes())  # mode L: one byte per pixel
    mean = sum(pixels) / len(pixels)
    return _bits_to_hex([p > mean for p in pixels])


def difference_hash(image: Image.Image, size: int = 8) -> str:
    small = image.convert("L").resize((size + 1, size), Image.Resampling.LANCZOS)
    px = list(small.tobytes())
    bits = [
        px[row * (size + 1) + col] > px[row * (size + 1) + col + 1]
        for row in range(size)
        for col in range(size)
    ]
    return _bits_to_hex(bits)


def hamming_distance(a: str, b: str) -> int:
    return (int(a, 16) ^ int(b, 16)).bit_count()


def perceptual_hashes(path: Path) -> dict[str, str]:
    with open_image(path) as image:
        image.seek(0)
        try:
            image.load()
        except (OSError, ValueError, SyntaxError) as exc:
            raise ImageReadError(f"Не удалось декодировать пиксели: {exc}") from exc
        return {"ahash": average_hash(image), "dhash": difference_hash(image)}


class ImageHashesModule(BaseModule):
    name = "image.hashes"
    title = "Хеши изображения"
    description = "SHA-256/SHA-1/MD5 файла и перцептивные хеши aHash/dHash (локально)."
    target_types = frozenset({TargetType.IMAGE})
    limitations = (
        "Совпадение перцептивного хеша означает визуальное сходство, а не идентичность "
        "изображения или его автора.",
    )

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        path = Path(target.normalized)
        uri = path.as_uri()
        hashes = await asyncio.to_thread(file_hashes, path)
        add = out.findings.append
        for name, value in hashes.items():
            add(
                self.finding(
                    target,
                    f"image.{name}",
                    value,
                    Confidence.CONFIRMED,
                    f"hashlib ({name.upper()})",
                    uri,
                    f"{name.upper()} содержимого файла: идентифицирует именно этот файл "
                    "байт-в-байт.",
                    exclusive=True,
                )
            )
        try:
            perceptual = await asyncio.to_thread(perceptual_hashes, path)
        except ImageReadError as exc:
            out.errors.append(f"Перцептивные хеши не вычислены: {exc}")
            return out
        add(
            self.finding(
                target,
                "image.ahash",
                perceptual["ahash"],
                Confidence.CONFIRMED,
                "Average hash (aHash, 64 бит)",
                uri,
                "Перцептивный хеш: близкие значения (малое расстояние Хэмминга) у "
                "визуально похожих копий.",
                exclusive=True,
            )
        )
        add(
            self.finding(
                target,
                "image.dhash",
                perceptual["dhash"],
                Confidence.CONFIRMED,
                "Difference hash (dHash, 64 бит)",
                uri,
                "Перцептивный хеш по градиентам яркости; устойчив к пересжатию и "
                "изменению размера.",
                exclusive=True,
            )
        )
        if perceptual["dhash"] == "0" * 16:
            out.limitations.append(
                "Изображение почти однородное: перцептивные хеши вырождены и для поиска похожих "
                "копий малоинформативны."
            )
        return out

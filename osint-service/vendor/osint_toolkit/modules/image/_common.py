"""Shared helpers for image modules: safe opening, value sanitising.

Safety: Pillow's decompression-bomb protection stays enabled and its warning is escalated to an
error, files larger than :data:`MAX_FILE_BYTES` are refused, and only the file the user selected
is read.
"""

from __future__ import annotations

import logging
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from PIL import Image, UnidentifiedImageError

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TEXT = 500

HEIF_SUPPORT = False
try:  # optional HEIC/HEIF/AVIF support (iPhone photos)
    from pillow_heif import register_heif_opener

    register_heif_opener()
    HEIF_SUPPORT = True
except ImportError:  # pragma: no cover - dependency is declared, but stay robust without it
    log.info("pillow-heif not available: HEIC files cannot be decoded")

# Pillow format name → acceptable file extensions.
FORMAT_EXTENSIONS: dict[str, frozenset[str]] = {
    "JPEG": frozenset({".jpg", ".jpeg", ".jpe", ".jfif"}),
    "PNG": frozenset({".png"}),
    "GIF": frozenset({".gif"}),
    "TIFF": frozenset({".tif", ".tiff"}),
    "WEBP": frozenset({".webp"}),
    "BMP": frozenset({".bmp", ".dib"}),
    "HEIF": frozenset({".heic", ".heif", ".hif"}),
    "AVIF": frozenset({".avif"}),
    "MPO": frozenset({".jpg", ".jpeg", ".mpo"}),  # multi-picture JPEG (many phone cameras)
}


class ImageReadError(Exception):
    """The file cannot be decoded safely as an image."""


@contextmanager
def open_image(path: Path) -> Iterator[Image.Image]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ImageReadError(f"Файл больше {MAX_FILE_BYTES // 2**20} МБ — анализ отклонён")
    if size == 0:
        raise ImageReadError("Файл пуст")
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image = Image.open(path)
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise ImageReadError(f"Подозрение на decompression bomb: {exc}") from exc
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError) as exc:
            raise ImageReadError(f"Не удалось распознать изображение: {exc}") from exc
        try:
            yield image
        finally:
            image.close()


def clean_text(value: object, limit: int = MAX_TEXT) -> str | None:
    """Printable, trimmed text from EXIF/XMP values (bytes, str, numbers)."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = decode_bytes(value)
    text = str(value).replace("\x00", "").strip()
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text).strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def decode_bytes(raw: bytes) -> str:
    # EXIF UserComment starts with an 8-byte charset id.
    for prefix, codec in (
        (b"ASCII\x00\x00\x00", "ascii"),
        (b"UNICODE\x00", "utf-16"),
        (b"JIS\x00\x00\x00\x00\x00", "shift_jis"),
    ):
        if raw.startswith(prefix):
            return raw[8:].decode(codec, errors="replace")
    if raw.startswith(b"\x00" * 8):
        raw = raw[8:]
    return raw.decode("utf-8", errors="replace")

"""Reverse image search with the TinEye API (paid, API key).

API as implemented by TinEye's official SDK ``pytineye`` (MIT): ``POST
https://api.tineye.com/rest/search/`` with header ``x-api-key`` and the image in the multipart
field ``image_upload``; matches are in ``results.matches[]`` with ``backlinks[]``.

Privacy: the image is uploaded to TinEye — consent states this explicitly. Only a re-encoded
copy is sent: metadata (EXIF/GPS/XMP, comments, ICC) is stripped and the size is capped, since
visual matching does not need it. TinEye's terms could not be retrieved automatically, so
matches are session-only unless ``OSINT_TINEYE_STORE_RESULTS=true`` (set it after reading the
terms yourself). A match means a visually similar image was found on a page — not authorship.
"""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

from PIL import Image

from osint_toolkit.config import Settings
from osint_toolkit.core.models import (
    Confidence,
    ExternalService,
    Finding,
    JsonValue,
    Target,
    TargetType,
)
from osint_toolkit.modules.base import BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.image._common import ImageReadError, open_image
from osint_toolkit.net import NetworkError

SEARCH_URL = "https://api.tineye.com/rest/search/"
MAX_SIDE = 2000


def stripped_copy(path: Path) -> tuple[bytes, tuple[int, int]]:
    """JPEG copy without any metadata, longest side ≤ MAX_SIDE."""
    with open_image(path) as image:
        image.seek(0)
        frame = image.convert("RGB")
        frame.thumbnail((MAX_SIDE, MAX_SIDE))
        clean = Image.new("RGB", frame.size)
        clean.paste(frame)  # fresh image object: no info dict, no EXIF, no ICC carried over
        buffer = io.BytesIO()
        clean.save(buffer, "JPEG", quality=90, optimize=True)
        return buffer.getvalue(), clean.size


class TinEyeModule(BaseModule):
    name = "image.tineye"
    title = "Обратный поиск изображения (TinEye)"
    description = (
        "Ищет копии изображения в индексе TinEye. Загружается копия без метаданных; каждый "
        "поиск списывается с баланса вашего ключа."
    )
    target_types = frozenset({TargetType.IMAGE})
    required_settings = ("tineye_api_key",)
    external_services: ClassVar[tuple[ExternalService, ...]] = (
        ExternalService(
            name="TinEye API",
            url="https://api.tineye.com",
            data_sent="копия изображения без метаданных (EXIF/GPS удалены) и ваш "
            "API-ключ; списывается 1 поиск",
        ),
    )
    limitations: ClassVar[tuple[str, ...]] = (
        "Совпадение означает визуально похожее изображение на странице, а не авторство, "
        "владение или личность изображённых людей.",
        "Индекс TinEye неполон: отсутствие совпадений не означает, что изображение не "
        "публиковалось.",
    )
    timeout = 120

    def request_details(self, target: Target, settings: Settings) -> tuple[str, ...]:
        name = target.details.get("file_name") or Path(target.normalized).name
        lines = [f"Будет загружена копия файла «{name}» (JPEG, до {MAX_SIDE} px, без метаданных)"]
        if not settings.tineye_store_results:
            lines.append(
                "результаты будут показаны только в этой сессии (OSINT_TINEYE_STORE_RESULTS=false)"
            )
        return tuple(lines)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        settings = ctx.settings
        key = settings.tineye_api_key.get_secret_value() if settings.tineye_api_key else ""
        try:
            payload, size = await asyncio.to_thread(stripped_copy, Path(target.normalized))
        except ImageReadError as exc:
            out.errors.append(str(exc))
            return out
        response = await ctx.net.http.post_multipart(
            SEARCH_URL,
            files={"image_upload": ("image.jpg", payload, "image/jpeg")},
            data={"limit": str(settings.tineye_max_matches), "sort": "score", "order": "desc"},
            headers={"x-api-key": key},
            request_timeout=90,
        )
        try:
            data = response.json()
        except NetworkError:
            raise NetworkError(f"TinEye ответил HTTP {response.status} без JSON") from None
        if not isinstance(data, dict):
            raise NetworkError("TinEye вернул неожиданный формат")
        code = data.get("code")
        if response.status != 200 or code != 200:
            messages = "; ".join(str(m) for m in data.get("messages") or []) or "без описания"
            hint = (
                " — проверьте ключ и баланс"
                if response.status in (401, 403) or code in (401, 403)
                else ""
            )
            raise NetworkError(f"TinEye: ошибка {code or response.status}: {messages}{hint}")
        raw_results = data.get("results")
        results: dict[str, Any] = raw_results if isinstance(raw_results, dict) else {}
        matches = [m for m in results.get("matches") or [] if isinstance(m, dict)]
        ephemeral = not settings.tineye_store_results
        raw_stats = data.get("stats")
        stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
        out.findings.append(
            self.finding(
                target,
                "image.reverse_search_scope",
                {
                    "provider": "TinEye",
                    "matches": len(matches),
                    "uploaded_size": list(size),
                    "total_results": stats.get("total_results"),
                },
                Confidence.CONFIRMED,
                "TinEye API",
                "https://api.tineye.com",
                f"Загружена копия {size[0]}×{size[1]} без метаданных; совпадений: {len(matches)}.",
                exclusive=True,
            )
        )
        for match in matches:
            finding = self._match(target, match)
            if finding is not None:
                out.findings.append(finding.model_copy(update={"ephemeral": ephemeral}))
        if ephemeral and matches:
            out.limitations.append(
                "Совпадения TinEye показаны только в этой сессии: включите "
                "OSINT_TINEYE_STORE_RESULTS после изучения условий TinEye."
            )
        return out

    def _match(self, target: Target, match: dict[str, Any]) -> Finding | None:
        backlinks = [b for b in match.get("backlinks") or [] if isinstance(b, dict)]
        pages = [
            str(b.get("backlink"))
            for b in backlinks
            if str(b.get("backlink", "")).startswith(("https://", "http://"))
        ]
        image_url = str(match.get("image_url") or "")
        source = pages[0] if pages else image_url
        if not source.startswith(("https://", "http://")):
            return None
        score = match.get("score")
        value: dict[str, JsonValue] = {
            "domain": match.get("domain") or urlsplit(source).hostname,
            "page": source,
            "image_url": image_url or None,
            "score": score if isinstance(score, int | float) else None,
            "size": [match.get("width"), match.get("height")],
            "first_crawl": min(
                (str(b.get("crawl_date")) for b in backlinks if b.get("crawl_date")), default=None
            ),
            "pages": pages[:10],
        }
        return self.finding(
            target,
            "image.web_copy",
            value,
            Confidence.LIKELY,
            f"TinEye → {value['domain']}",
            source,
            f"TinEye сопоставил загруженное изображение с изображением на этой странице "
            f"(оценка {score}). Это может быть изменённая копия; совпадение не говорит об "
            "авторстве или личности.",
        )

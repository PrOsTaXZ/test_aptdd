"""Full metadata dump with ExifTool (offline, sandboxed, no network).

ExifTool reads far more formats and vendor MakerNotes than Pillow (serial numbers, lens data,
edit history, IPTC, QuickTime/HEIC atoms). It runs inside the bwrap sandbox *without network*;
the image is mounted read-only as ``/input/image<ext>``, so the tool never sees its host path or
anything else on disk. Uses the managed ExifTool (``osint tools install exiftool``) or, if
present, the system ``/usr/bin/exiftool``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, ClassVar

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Confidence, JsonValue, ModuleStatus, Target, TargetType
from osint_toolkit.modules.base import Availability, BaseModule, ModuleContext, ModuleOutput
from osint_toolkit.modules.image._common import clean_text
from osint_toolkit.sandbox import (
    SandboxError,
    SandboxPolicy,
    SandboxTimeoutError,
    run_sandboxed,
    sandbox_status,
)
from osint_toolkit.tools import EXIFTOOL, tool_status

PERL = Path("/usr/bin/perl")
SYSTEM_EXIFTOOL = Path("/usr/bin/exiftool")
MAX_TAGS = 400
# Groups describing the file system / ExifTool itself, not the image content.
SKIP_GROUPS = ("System", "ExifTool", "SourceFile")
SKIP_TAGS = {
    "File:Directory",
    "File:FileName",
    "File:FilePermissions",
    "File:FileModifyDate",
    "File:FileAccessDate",
    "File:FileInodeChangeDate",
}
SENSITIVE = re.compile(
    r"serial|owner|artist|author|creator|by-?line|copyright|gps|location|city|country|"
    r"sub-?location|province|hostcomputer|usercomment|documentname|imageuniqueid|"
    r"cameraid|internalserial|lensserial|contact|credit|personinimage|name$",
    re.IGNORECASE,
)


def locate(settings: Settings) -> tuple[list[str], tuple[Path, ...]] | None:
    """(argv prefix, read-only mounts) for the ExifTool to use, managed first."""
    status = tool_status(settings, EXIFTOOL)
    script = status.path / "exiftool"
    if status.installed and script.is_file() and PERL.exists():
        return [str(PERL), str(script)], (status.path,)
    if SYSTEM_EXIFTOOL.exists():
        return [str(SYSTEM_EXIFTOOL)], ()
    return None


def parse_dump(data: Any) -> tuple[dict[str, str], dict[str, int], list[str]]:
    """(tags, group counts, warnings) from ``exiftool -json -G1`` output."""
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise ValueError("ExifTool вернул неожиданный формат")
    tags: dict[str, str] = {}
    groups: dict[str, int] = {}
    warnings: list[str] = []
    for key, value in data[0].items():
        group = key.split(":", 1)[0]
        if key in SKIP_TAGS or group in SKIP_GROUPS:
            if key.endswith(":Warning") or key == "ExifTool:Warning":
                warnings.append(clean_text(value) or "")
            continue
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        if "(Binary data" in text:
            text = "(двоичные данные)"
        cleaned = clean_text(text, limit=200)
        if cleaned is None:
            continue
        groups[group] = groups.get(group, 0) + 1
        if len(tags) < MAX_TAGS:
            tags[key] = cleaned
    return tags, groups, [w for w in warnings if w]


class ExifToolModule(BaseModule):
    name = "image.exiftool"
    title = "Полные метаданные (ExifTool)"
    description = (
        "Все метаданные файла по ExifTool: MakerNotes производителей, IPTC, XMP, QuickTime/HEIC "
        "и поля, раскрывающие приватность. Офлайн, в песочнице без сети."
    )
    target_types = frozenset({TargetType.IMAGE})
    limitations: ClassVar[tuple[str, ...]] = (
        "Метаданные описывают содержимое файла и легко изменяются; они не устанавливают "
        "личность автора или владельца устройства.",
    )
    timeout = 90

    def availability(self, settings: Settings) -> Availability:
        sandbox = sandbox_status()
        if not sandbox.available:
            return Availability(False, sandbox.reason)
        if locate(settings) is None:
            return Availability(
                False,
                "ExifTool не найден: osint tools install exiftool "
                "(или sudo apt install libimage-exiftool-perl)",
            )
        return Availability(True)

    async def run(self, target: Target, ctx: ModuleContext) -> ModuleOutput:
        out = ModuleOutput()
        found = locate(ctx.settings)
        if found is None:
            out.errors.append("ExifTool не найден")
            return out
        prefix, mounts = found
        image = Path(target.normalized)
        inside = f"/input/image{image.suffix.lower()[:8]}"
        policy = SandboxPolicy(network=False, read_only=mounts, mapped_read_only=((image, inside),))
        argv = [*prefix, "-json", "-G1", "-a", "-s", "-m", "-charset", "filename=utf8", inside]
        try:
            result = await run_sandboxed(policy, argv, limit_s=80, max_output=8 * 1024 * 1024)
        except SandboxTimeoutError as exc:
            raise TimeoutError(str(exc)) from exc
        except SandboxError as exc:
            out.errors.append(f"Песочница: {exc}")
            out.status = ModuleStatus.ERROR
            return out
        if result.returncode not in (0, 1):  # 1 = minor errors, output still valid
            out.errors.append(
                f"ExifTool завершился с кодом {result.returncode}: {result.stderr_tail(3)}"
            )
            out.status = ModuleStatus.ERROR
            return out
        try:
            data = json.loads(result.stdout or b"null")
        except ValueError:
            data = None
        try:
            tags, groups, warnings = parse_dump(data)
        except ValueError as exc:
            out.errors.append(str(exc))
            out.status = ModuleStatus.ERROR
            return out
        source = f"ExifTool {EXIFTOOL.version}" if len(prefix) > 1 else "ExifTool (системный)"
        uri = image.as_uri()
        add = out.findings.append
        add(
            self.finding(
                target,
                "image.exiftool_groups",
                dict(sorted(groups.items())),
                Confidence.CONFIRMED,
                source,
                uri,
                "Группы метаданных в файле и число тегов в каждой.",
            )
        )
        add(
            self.finding(
                target,
                "image.exiftool_tags",
                dict(tags),
                Confidence.CONFIRMED,
                source,
                uri,
                f"Метаданные файла по ExifTool ({len(tags)} тегов"
                + (f", показаны первые {MAX_TAGS}" if len(tags) >= MAX_TAGS else "")
                + "; служебные поля файловой системы исключены).",
            )
        )
        sensitive: dict[str, JsonValue] = {k: v for k, v in tags.items() if SENSITIVE.search(k)}
        if sensitive:
            add(
                self.finding(
                    target,
                    "image.exiftool_sensitive",
                    sensitive,
                    Confidence.CONFIRMED,
                    source,
                    uri,
                    "Поля, которые при публикации могут раскрыть местоположение, "
                    "устройство (серийные номера) или имена. Удалите их перед "
                    "публикацией, например: exiftool -all= файл.",
                )
            )
        out.limitations.extend(f"ExifTool: {w}" for w in warnings)
        return out

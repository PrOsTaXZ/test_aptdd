"""Report orchestration: format selection, safe file writing, cleanup."""

from __future__ import annotations

import enum
import os
import re
from collections.abc import Iterable
from pathlib import Path

from osint_toolkit.config import ensure_private_dir
from osint_toolkit.core.models import Investigation
from osint_toolkit.reports.html import render_html
from osint_toolkit.reports.pdf import PdfOptions, render_pdf
from osint_toolkit.reports.renderers import render_json, render_markdown, render_txt
from osint_toolkit.reports.view import build_view


class ReportFormat(enum.StrEnum):
    TXT = "txt"
    JSON = "json"
    HTML = "html"
    MD = "md"
    PDF = "pdf"


_TEXT_RENDERERS = {
    ReportFormat.TXT: render_txt,
    ReportFormat.JSON: render_json,
    ReportFormat.HTML: render_html,
    ReportFormat.MD: render_markdown,
}
_ALIASES = {"markdown": ReportFormat.MD, "text": ReportFormat.TXT, "htm": ReportFormat.HTML}
REPORT_NAME_RE = re.compile(r"^osint-\d{8}-\d{6}-[a-z]+-[0-9a-f]{8}\.(txt|json|html|md|pdf)$")


def parse_formats(spec: str | Iterable[str]) -> list[ReportFormat]:
    """'html,md' / 'all' / 'none' → formats. Raises ValueError on unknown names."""
    items = spec.split(",") if isinstance(spec, str) else list(spec)
    names = [i.strip().lower() for i in items if i.strip()]
    if not names or names == ["none"]:
        return []
    if "all" in names:
        return list(ReportFormat)
    formats: list[ReportFormat] = []
    for name in names:
        try:
            fmt = _ALIASES.get(name) or ReportFormat(name)
        except ValueError:
            allowed = ", ".join([*(f.value for f in ReportFormat), "all", "none"])
            raise ValueError(f"Неизвестный формат отчёта «{name}». Допустимо: {allowed}") from None
        if fmt not in formats:
            formats.append(fmt)
    return formats


def render_report(investigation: Investigation, fmt: ReportFormat) -> str:
    """Text formats only (TXT, JSON, HTML, Markdown); PDF: :func:`render_report_bytes`."""
    return _TEXT_RENDERERS[fmt](build_view(investigation))


def render_report_bytes(
    investigation: Investigation, fmt: ReportFormat, pdf: PdfOptions | None = None
) -> bytes:
    view = build_view(investigation)
    if fmt is ReportFormat.PDF:
        return render_pdf(view, pdf)
    return _TEXT_RENDERERS[fmt](view).encode("utf-8")


def report_basename(investigation: Investigation) -> str:
    """No identifier in the name: file listings must not leak what was investigated."""
    stamp = investigation.created_at.strftime("%Y%m%d-%H%M%S")
    return f"osint-{stamp}-{investigation.target.type.value}-{investigation.id[:8]}"


def _write_private(path: Path, content: str | bytes) -> None:
    data = content.encode("utf-8") if isinstance(content, str) else content
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    path.chmod(0o600)


def generate_reports(
    investigation: Investigation,
    formats: Iterable[ReportFormat],
    out_dir: Path,
    *,
    private_dir: bool = True,
    pdf: PdfOptions | None = None,
) -> list[Path]:
    """Write reports and return their paths.

    ``private_dir`` (default reports folder) forces mode 0700 on the directory; a folder the user
    chose explicitly is created if missing but its existing permissions are left alone.
    """
    if private_dir:
        ensure_private_dir(out_dir)
    elif not out_dir.exists():
        out_dir.mkdir(parents=True, mode=0o700)
    view = build_view(investigation)
    base = report_basename(investigation)
    written: list[Path] = []
    for fmt in formats:
        path = out_dir / f"{base}.{fmt.value}"
        content = render_pdf(view, pdf) if fmt is ReportFormat.PDF else _TEXT_RENDERERS[fmt](view)
        _write_private(path, content)
        written.append(path)
    return written


def purge_reports(out_dir: Path) -> int:
    """Delete report files created by this tool (name pattern match only). Returns count."""
    if not out_dir.is_dir():
        return 0
    removed = 0
    for path in out_dir.iterdir():
        if path.is_file() and not path.is_symlink() and REPORT_NAME_RE.match(path.name):
            path.unlink()
            removed += 1
    return removed

"""Viewing the official (PDF) report without saving it among your reports.

The PDF is rendered into a private preview directory (``<data_dir>/cache/preview``, mode 0700,
file 0600) and opened in the desktop's default PDF viewer. Only the latest preview is kept:
older previews are deleted whenever a new one is made and when the application starts, so
nothing accumulates outside the reports directory.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from osint_toolkit.config import Settings, ensure_private_dir
from osint_toolkit.core.models import Investigation
from osint_toolkit.reports.generator import ReportFormat, render_report_bytes
from osint_toolkit.reports.pdf import PdfOptions

PREVIEW_DIR = "preview"


def preview_dir(settings: Settings) -> Path:
    return settings.cache_dir / PREVIEW_DIR


def clear_previews(settings: Settings) -> int:
    """Delete every preview file; returns how many were removed."""
    directory = preview_dir(settings)
    if not directory.is_dir():
        return 0
    removed = 0
    for path in directory.glob("*.pdf"):
        if path.is_file() and not path.is_symlink():
            path.unlink(missing_ok=True)
            removed += 1
    return removed


def render_preview(investigation: Investigation, settings: Settings) -> Path:
    """Render the official PDF report into the private preview directory."""
    ensure_private_dir(settings.cache_dir)
    directory = ensure_private_dir(preview_dir(settings))
    clear_previews(settings)
    data = render_report_bytes(
        investigation.persistable(), ReportFormat.PDF, PdfOptions.from_settings(settings)
    )
    path = directory / f"osint-report-{investigation.id[:12]}.pdf"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def open_in_viewer(path: Path) -> bool:
    """Open a local file in the desktop's default application (xdg-open). No network."""
    opener = shutil.which("xdg-open")
    if opener is None:
        return False
    try:
        subprocess.Popen(  # noqa: S603 - fixed opener, local file path as a single argument
            [opener, str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # the viewer outlives the TUI and never draws over it
        )
    except OSError:
        return False
    return True

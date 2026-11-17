"""Report generation (TXT, JSON, HTML, Markdown, PDF).

Every report contains: the original query, investigation time, modules used and their status,
findings grouped by confidence (never mixed), sources with links, contradictions, errors and
limitations, and a disclaimer that technical matches do not establish identity.
File names never contain the investigated identifier.
"""

from osint_toolkit.reports.generator import (
    ReportFormat,
    generate_reports,
    parse_formats,
    purge_reports,
    render_report,
    render_report_bytes,
)
from osint_toolkit.reports.pdf import PdfOptions

__all__ = [
    "PdfOptions",
    "ReportFormat",
    "generate_reports",
    "parse_formats",
    "purge_reports",
    "render_report",
    "render_report_bytes",
]

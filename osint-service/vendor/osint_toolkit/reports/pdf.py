"""PDF report (WeasyPrint): title page with a security marking, executive summary, «Где замечен»,
documents, social networks, other findings, limitations and a numbered list of sources.

Layout follows the usual Russian report conventions (ГОСТ 7.32-2017 / ГОСТ Р 7.0.97-2016):
A4, margins 30/15/20/20 mm, a Times-compatible serif at 14 pt with 1.5 spacing, numbered
sections, page numbers centred at the bottom (none on the title page), sources in the
ГОСТ Р 7.0.100-2018 style for electronic resources with the access date.

Rendering never touches the network: every URL WeasyPrint would fetch (images, stylesheets,
fonts) is refused by the URL fetcher, so a hostile value in the data cannot make the report
"phone home". Fonts come from the local fontconfig.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from typing import Any, NoReturn
from urllib.parse import urlsplit

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from osint_toolkit.config import Settings
from osint_toolkit.core.models import Confidence
from osint_toolkit.reports.seen import SeenRow
from osint_toolkit.reports.view import ReportView, format_value, is_web_url

MAX_FRAGMENT = 300
MAX_VALUE = 400


@dataclass(frozen=True, slots=True)
class PdfOptions:
    classification: str = "Конфиденциально"
    organization: str = ""
    author: str = ""

    @classmethod
    def from_settings(cls, settings: Settings) -> PdfOptions:
        return cls(
            classification=settings.report_classification,
            organization=settings.report_organization,
            author=settings.report_author,
        )


@dataclass(frozen=True, slots=True)
class Source:
    number: int
    title: str
    url: str
    accessed: str  # DD.MM.YYYY


def _local_date(value: datetime) -> str:
    return value.astimezone().strftime("%d.%m.%Y")


def sources_of(view: ReportView) -> list[Source]:
    """Unique web sources of all findings (first access date), in order of appearance."""
    seen: dict[str, tuple[str, datetime]] = {}
    for row in view.seen:
        if is_web_url(row.url) and row.url not in seen:
            seen[row.url] = (row.title or row.platform, row.finding.observed_at)
    for section in view.sections:
        for item in section.rows:
            f = item.finding
            if is_web_url(f.source_url) and f.source_url not in seen:
                seen[f.source_url] = (f.source_name, f.observed_at)
    return [
        Source(i, title or (urlsplit(url).hostname or url), url, _local_date(when))
        for i, (url, (title, when)) in enumerate(seen.items(), 1)
    ]


def summary_of(view: ReportView) -> dict[str, Any]:
    inv = view.investigation
    confirmed = [r for r in view.seen if r.confirmed]
    return {
        "modules_total": len(inv.results),
        "modules_with_data": sum(1 for r in inv.results if r.findings),
        "pages": len(view.seen),
        "confirmed": len(confirmed),
        "documents": len(view.seen_documents),
        "documents_confirmed": sum(1 for r in view.seen_documents if r.confirmed),
        "social": len(view.seen_social),
        "social_confirmed": sum(1 for r in view.seen_social if r.confirmed),
        # "other findings": everything not already shown in the «Где замечен» tables
        **{
            key: sum(len(s.rows) for s in view.sections if s.confidence is level)
            for key, level in (
                ("confirmed_findings", Confidence.CONFIRMED),
                ("likely", Confidence.LIKELY),
                ("unverified", Confidence.UNVERIFIED),
            )
        },
        "top": confirmed[:10],
        "platforms": sorted({r.platform for r in confirmed if r.platform})[:15],
    }


def _short(text: object, limit: int) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


_env = Environment(
    loader=PackageLoader("osint_toolkit.reports", "templates"),
    autoescape=select_autoescape(["html", "j2"], default=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["short"] = _short
_env.filters["fmt_value"] = lambda v: _short(format_value(v), MAX_VALUE)
_env.tests["web_url"] = is_web_url


def render_pdf_html(view: ReportView, options: PdfOptions | None = None) -> str:
    options = options or PdfOptions()
    return _env.get_template("report_pdf.html.j2").render(
        view=view,
        inv=view.investigation,
        options=options,
        summary=summary_of(view),
        sources=sources_of(view),
        today=datetime.now(UTC).astimezone().strftime("%d.%m.%Y"),
        max_fragment=MAX_FRAGMENT,
        seen_label=_seen_label,
    )


def _seen_label(row: SeenRow) -> str:
    return row.kind_label + (
        f", {row.doc_type.upper()} {row.location}".rstrip() if row.doc_type else ""
    )


def _refuse(url: str, *args: Any, **kwargs: Any) -> NoReturn:
    raise ValueError(f"внешние ресурсы в PDF запрещены: {url[:80]}")


@cache
def offline_fetcher() -> Any:
    """A WeasyPrint URL fetcher that refuses every URL (WeasyPrint then skips the resource)."""
    from weasyprint.urls import URLFetcher

    class OfflineFetcher(URLFetcher):  # type: ignore[misc]
        def fetch(self, url: str, headers: Any = None) -> NoReturn:
            _refuse(url)

    return OfflineFetcher(allowed_protocols=())


def render_pdf(view: ReportView, options: PdfOptions | None = None) -> bytes:
    from weasyprint import HTML  # heavy import: only when a PDF is requested

    html = render_pdf_html(view, options)
    pdf: bytes = HTML(string=html, url_fetcher=offline_fetcher(), base_url=None).write_pdf()
    return pdf

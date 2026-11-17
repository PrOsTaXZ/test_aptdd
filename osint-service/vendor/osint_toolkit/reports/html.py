"""Self-contained HTML report (Jinja2, autoescaping, strict CSP, no external resources)."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from osint_toolkit.reports.view import ReportView, fmt_time, is_web_url

_env = Environment(
    loader=PackageLoader("osint_toolkit.reports", "templates"),
    autoescape=select_autoescape(["html", "j2"], default=True),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["fmt_time"] = fmt_time
_env.tests["web_url"] = is_web_url


def render_html(view: ReportView) -> str:
    return _env.get_template("report.html.j2").render(view=view, inv=view.investigation)

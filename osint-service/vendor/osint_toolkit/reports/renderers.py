"""TXT, Markdown and JSON renderers."""

from __future__ import annotations

import json
import textwrap
from urllib.parse import quote

from osint_toolkit.core.models import Investigation
from osint_toolkit.reports.view import ReportView, fmt_time, format_value, is_web_url

JSON_SCHEMA = "osint-toolkit/report-v1"


# --------------------------------------------------------------------------- JSON
def render_json(view: ReportView) -> str:
    payload = {
        "report": {
            "schema": JSON_SCHEMA,
            "generated_at": view.generated_at.isoformat(),
            "app_version": view.app_version,
            "disclaimer": view.disclaimer,
        },
        "where_seen": [
            {
                "type": r.kind,
                "type_label": r.kind_label,
                "platform": r.platform,
                "url": r.url,
                "title": r.title,
                "fragment": r.fragment,
                "location": r.location or None,
                "doc_type": r.doc_type or None,
                "verification": r.status,
                "verification_label": r.status_label,
                "confidence": r.confidence.value,
            }
            for r in view.seen
        ],
        "investigation": view.investigation.model_dump(mode="json"),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def load_json_report(text: str) -> Investigation:
    data = json.loads(text)
    if data.get("report", {}).get("schema") != JSON_SCHEMA:
        raise ValueError("unsupported report schema")
    return Investigation.model_validate(data["investigation"])


# --------------------------------------------------------------------------- TXT
def _wrap(text: str, indent: str = "    ", width: int = 100) -> str:
    lines = []
    for paragraph in text.splitlines() or [""]:
        lines.append(
            textwrap.fill(
                paragraph,
                width=width,
                initial_indent=indent,
                subsequent_indent=indent,
                break_long_words=False,  # URLs, hashes and paths stay intact for copy/paste
                break_on_hyphens=False,
            )
            or indent
        )
    return "\n".join(lines)


def render_txt(view: ReportView) -> str:
    inv = view.investigation
    rule = "=" * 100
    out: list[str] = [rule, view.title.upper(), rule]
    out += [
        f"Запрос:        {inv.query}",
        f"Цель:          {inv.target.type.label}: {inv.target.normalized}",
    ]
    if inv.related_targets:
        out.append("Связанные:     " + ", ".join(str(t) for t in inv.related_targets))
    out += [
        f"Режим:         {view.mode_text}",
        f"Начато:        {fmt_time(inv.created_at)}",
        f"Завершено:     {fmt_time(inv.finished_at)}",
        f"Статус:        {view.status_text}",
        f"ID:            {inv.id}",
        f"Отчёт создан:  {fmt_time(view.generated_at)} (osint-toolkit {view.app_version})",
        "",
        _wrap(view.disclaimer, indent=""),
        "",
        *([_wrap("⚠ " + view.banner, indent=""), ""] if view.banner else []),
        "-" * 100,
        "МОДУЛИ",
        "-" * 100,
    ]
    for m in view.modules:
        out.append(
            f"  [{m.status.label:^11}] {m.title} ({m.module}) → {m.target}"
            f" · находок: {m.findings} · {m.duration}"
        )
        for error in m.errors:
            out.append(_wrap(f"! {error}", indent="                "))

    for title, rows in (
        ("ГДЕ ЗАМЕЧЕН ИДЕНТИФИКАТОР", view.seen),
        ("ДОКУМЕНТЫ", view.seen_documents),
        ("СОЦСЕТИ", view.seen_social),
    ):
        if not rows:
            continue
        out += ["", "-" * 100, f"{title} ({len(rows)})", "-" * 100]
        for r in rows:
            where = f" · {r.doc_type.upper()} {r.location}".rstrip() if r.doc_type else ""
            out.append(f"  [{r.status_label}] {r.kind_label}: {r.platform}{where}")
            out.append(_wrap(r.url))
            if r.fragment:
                out.append(_wrap(f"«{r.fragment}»"))
    for section in view.sections:
        out += [
            "",
            "-" * 100,
            f"{section.title.upper()} ({len(section.rows)}) — {section.help}",
            "-" * 100,
        ]
        for row in section.rows:
            f = row.finding
            out.append(f"  • {f.subject} :: {f.attribute}")
            out.append(_wrap(f"Значение: {row.value_text}"))
            out.append(_wrap(f"Источник: {f.source_name} <{f.source_url}>"))
            out.append(_wrap(f"Подтверждает: {f.evidence}"))
            out.append(f"    Время: {fmt_time(f.observed_at)} · модуль: {f.module}")
    if not view.sections:
        out += ["", "Находок нет."]

    if view.helpers:
        out += ["", "-" * 100, "ДОРКИ (не находки; выполненные — с числом результатов)", "-" * 100]
        for row in view.helpers:
            v = row.finding.value
            if isinstance(v, dict) and "query" in v:
                hits = f" — результатов: {v['hits']}" if "hits" in v else ""
                out.append(f"  [{v.get('group', '')}] {v['query']}{hits}")
                out.append(_wrap(f"Google: {v.get('google', '')}"))
            else:
                out.append(_wrap(f"Варианты записи: {row.value_text}", indent="  "))
    if view.contradictions:
        out += ["", "-" * 100, "ПРОТИВОРЕЧИЯ МЕЖДУ ИСТОЧНИКАМИ", "-" * 100]
        for c in view.contradictions:
            out.append(_wrap("• " + c.description, indent="  "))
    if view.warnings or view.errors or view.limitations:
        out += ["", "-" * 100, "ОШИБКИ И ОГРАНИЧЕНИЯ", "-" * 100]
        out += [_wrap(f"! {w}", indent="  ") for w in view.warnings]
        out += [_wrap(f"! [{m}] {e}", indent="  ") for m, e in view.errors]
        out += [_wrap(f"- [{m}] {t}", indent="  ") for m, t in view.limitations]
    out += ["", rule]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- Markdown
# Data never starts a line (it sits in table cells or after "- " / "> "), so only inline markup
# characters need escaping; raw HTML is neutralised with entities.
_MD_SPECIAL = str.maketrans(
    {c: f"\\{c}" for c in "\\`*_[]|~"} | {"<": "&lt;", ">": "&gt;", "&": "&amp;"}
)


def md(text: object) -> str:
    """Escape text for a Markdown table cell or paragraph (no markup injection from data)."""
    return str(text).translate(_MD_SPECIAL).replace("\r", "").replace("\n", "<br>")


def md_link(url: str, label: str | None = None) -> str:
    if not is_web_url(url):
        return f"`{url.replace('`', '')}`"
    safe = quote(url, safe=":/?#[]@!$&'*+,;=%~-._")
    safe = safe.replace("(", "%28").replace(")", "%29")
    return f"[{md(label or url)}]({safe})"


def render_markdown(view: ReportView) -> str:
    inv = view.investigation
    out: list[str] = [f"# {md(view.title)}", ""]
    rows = [
        ("Запрос", md(inv.query)),
        ("Цель", md(f"{inv.target.type.label}: {inv.target.normalized}")),
    ]
    if inv.related_targets:
        rows.append(("Связанные", md(", ".join(str(t) for t in inv.related_targets))))
    rows += [
        ("Режим", md(view.mode_text)),
        ("Начато", fmt_time(inv.created_at)),
        ("Завершено", fmt_time(inv.finished_at)),
        ("Статус", md(view.status_text)),
        ("ID", f"`{inv.id}`"),
        ("Отчёт создан", f"{fmt_time(view.generated_at)} · osint-toolkit {md(view.app_version)}"),
    ]
    out += ["| Параметр | Значение |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in rows]
    out += ["", f"> {md(view.disclaimer)}", ""]
    if view.banner:
        out += [f"> **⚠ {md(view.banner)}**", ""]
    out += ["## Модули", ""]
    out += [
        "| Модуль | Цель | Статус | Находок | Время | Примечание |",
        "|---|---|---|---:|---:|---|",
    ]
    for m in view.modules:
        out.append(
            f"| {md(m.title)}<br>`{m.module}` | {md(m.target)} | {md(m.status.label)} | "
            f"{m.findings} | {m.duration} | {md('; '.join(m.errors)) or '—'} |"
        )
    for section in view.sections:
        out += [
            "",
            f"## {md(section.title)} ({len(section.rows)})",
            "",
            f"*{md(section.help)}*",
            "",
            "| Объект | Атрибут | Значение | Источник | Что подтверждает | Время (UTC) |",
            "|---|---|---|---|---|---|",
        ]
        for row in section.rows:
            f = row.finding
            value = md(row.value_text)
            if row.links:
                value += "<br>" + " ".join(md_link(u, "ссылка") for u in row.links)
            out.append(
                f"| {md(f.subject)} | `{f.attribute}` | {value} | {md(f.source_name)}<br>"
                f"{md_link(f.source_url)} | {md(f.evidence)} | "
                f"{f.observed_at.strftime('%Y-%m-%d %H:%M:%S')} |"
            )
    if not view.sections:
        out += ["", "*Находок нет.*"]
    for title, seen_rows in (
        ("Где замечен идентификатор", view.seen),
        ("Документы", view.seen_documents),
        ("Соцсети", view.seen_social),
    ):
        if not seen_rows:
            continue
        out += [
            "",
            f"## {title} ({len(seen_rows)})",
            "",
            "| Тип | Ресурс | Ссылка | Фрагмент | Проверка |",
            "|---|---|---|---|---|",
        ]
        for item in seen_rows:
            doc = f" {item.doc_type.upper()}, {item.location}" if item.doc_type else ""
            out.append(
                f"| {md(item.kind_label + doc)} | {md(item.platform)} | {md_link(item.url)} | "
                f"{md(item.fragment)} | {md(item.status_label)} |"
            )
    if view.helpers:
        out += [
            "",
            "## Дорки",
            "",
            "*Не находки: выполненные дорки — с числом результатов; ссылки открываются только "
            "по вашему клику.*",
            "",
            "| Группа | Запрос | Результатов | Открыть |",
            "|---|---|---|---|",
        ]
        for row in view.helpers:
            v = row.finding.value
            if isinstance(v, dict) and "query" in v:
                links = " · ".join(
                    md_link(str(v[e]), e.capitalize())
                    for e in ("google", "yandex", "bing")
                    if e in v
                )
                query = str(v["query"]).replace("`", "")
                hits = md(str(v.get("hits", "—")))
                out.append(f"| {md(v.get('group', ''))} | `{query}` | {hits} | {links} |")
            else:
                out.append(f"| Варианты записи | {md(row.value_text)} | | |")
    if view.contradictions:
        out += ["", "## Противоречия между источниками", ""]
        out += [f"- {md(c.description)}" for c in view.contradictions]
    if view.warnings or view.errors or view.limitations:
        out += ["", "## Ошибки и ограничения", ""]
        out += [f"- **{md(w)}**" for w in view.warnings]
        out += [f"- ⚠ `{m}`: {md(e)}" for m, e in view.errors]
        out += [f"- `{m}`: {md(t)}" for m, t in view.limitations]
    return "\n".join(out) + "\n"


__all__ = ["format_value", "load_json_report", "render_json", "render_markdown", "render_txt"]

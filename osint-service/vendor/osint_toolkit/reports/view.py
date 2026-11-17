"""Format-independent view of an investigation, shared by all report renderers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from osint_toolkit import __version__
from osint_toolkit.core.models import (
    Confidence,
    Contradiction,
    Finding,
    Investigation,
    InvestigationStatus,
    JsonValue,
    ModuleStatus,
    utcnow,
)
from osint_toolkit.reports.seen import SeenRow, consent_banner, documents, social, where_seen

DISCLAIMER = (
    "Отчёт содержит только сведения из открытых источников и локальных данных. Технические "
    "совпадения (метаданные, хеши, оператор номера, совпадение имени пользователя) не "
    "устанавливают личность человека и не являются доказательством принадлежности."
)

CONFIDENCE_HELP = {
    Confidence.CONFIRMED: "прочитано напрямую из первичного источника",
    Confidence.LIKELY: "сильный косвенный признак, требует проверки",
    Confidence.UNVERIFIED: "упоминание или совпадение, которое может относиться к другому объекту",
}


def is_web_url(value: str) -> bool:
    return value.startswith(("https://", "http://"))


def format_value(value: JsonValue) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, list) and all(isinstance(v, str | int | float) for v in value):
        return ", ".join(str(v) for v in value)
    return json.dumps(value, ensure_ascii=False, indent=None, sort_keys=False)


def links_in(value: JsonValue) -> list[str]:
    """Web links embedded in a finding value (e.g. map_url), for manual checking."""
    found: list[str] = []
    if isinstance(value, str) and is_web_url(value):
        found.append(value)
    elif isinstance(value, list):
        for item in value:
            found.extend(links_in(item))
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(links_in(item))
    return found


@dataclass(frozen=True, slots=True)
class ModuleRow:
    module: str
    title: str
    target: str
    status: ModuleStatus
    findings: int
    duration: str
    errors: list[str]


@dataclass(frozen=True, slots=True)
class FindingRow:
    finding: Finding
    value_text: str
    links: list[str]

    @property
    def source_is_web(self) -> bool:
        return is_web_url(self.finding.source_url)


@dataclass(frozen=True, slots=True)
class FindingSection:
    confidence: Confidence
    title: str
    help: str
    rows: list[FindingRow]


@dataclass(slots=True)
class ReportView:
    investigation: Investigation
    generated_at: datetime = field(default_factory=utcnow)
    app_version: str = __version__
    disclaimer: str = DISCLAIMER
    modules: list[ModuleRow] = field(default_factory=list)
    sections: list[FindingSection] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    helpers: list[FindingRow] = field(default_factory=list)  # dork queries & manual links
    seen: list[SeenRow] = field(default_factory=list)  # «где замечен идентификатор»
    banner: str | None = None  # e.g. "search was not performed: no consent"

    @property
    def seen_documents(self) -> list[SeenRow]:
        return documents(self.seen)

    @property
    def seen_social(self) -> list[SeenRow]:
        return social(self.seen)

    limitations: list[tuple[str, str]] = field(default_factory=list)  # (module, text)
    errors: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return f"OSINT-отчёт: {self.investigation.target.type.label}"

    @property
    def status_text(self) -> str:
        if self.investigation.status is InvestigationStatus.CANCELLED:
            return "прервано пользователем (результаты частичные)"
        return "завершено"

    @property
    def mode_text(self) -> str:
        mode = (
            "Full Investigation" if self.investigation.mode.value == "full" else "выборочные модули"
        )
        return mode + (" · офлайн" if self.investigation.offline else "")

    @property
    def total_findings(self) -> int:
        return sum(len(s.rows) for s in self.sections)


def build_view(inv: Investigation) -> ReportView:
    inv = inv.persistable()  # reports are files: ephemeral findings never reach them
    view = ReportView(investigation=inv, warnings=list(inv.warnings))
    for r in inv.results:
        view.modules.append(
            ModuleRow(
                module=r.module,
                title=r.module_title,
                target=r.target.normalized,
                status=r.status,
                findings=len(r.findings),
                duration=f"{r.duration_s:.2f} с" if r.duration_s is not None else "—",
                errors=list(r.errors),
            )
        )
        for error in r.errors:
            view.errors.append((r.module, error))
    seen: set[tuple[str, str]] = set()
    for r in inv.results:
        for item in r.limitations:
            if (r.module, item) not in seen:
                seen.add((r.module, item))
                view.limitations.append((r.module, item))
    seen_ids = {row.finding.id for row in where_seen(inv)}
    for confidence in Confidence:
        # pages/documents are shown in «Где замечен»; the sections keep everything else
        findings = [f for f in inv.findings(confidence) if f.id not in seen_ids]
        if findings:
            view.sections.append(
                FindingSection(
                    confidence=confidence,
                    title=confidence.label,
                    help=CONFIDENCE_HELP[confidence],
                    rows=[
                        FindingRow(f, format_value(f.value), links_in(f.value)) for f in findings
                    ],
                )
            )
    view.contradictions = list(inv.contradictions)
    view.seen = where_seen(inv)
    view.banner = consent_banner(inv)
    view.helpers = [FindingRow(f, format_value(f.value), links_in(f.value))
                    for f in inv.helper_findings()]  # fmt: skip
    return view


def fmt_time(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")

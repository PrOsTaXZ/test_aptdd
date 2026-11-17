"""«Досье»: every recognised entity of an investigation, grouped by kind and value.

Sources are the «Где замечен» rows (pages, documents, social posts — with the entities the
verifier recognised around the identifier) and Maigret profile candidates. Each item lists every
place it occurred with the text around it and that place's verification status, so the user can
judge each statement. Grouping only says that the same *text* occurs in several places; it never
says that the places are about the same person.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from osint_toolkit.analysis.entities import ORDER, Entity, EntityType, data_type_label
from osint_toolkit.core.models import Confidence, Investigation
from osint_toolkit.reports.seen import SeenRow, where_seen

SECTIONS: tuple[tuple[str, str, tuple[EntityType, ...]], ...] = (
    ("names", "ФИО", (EntityType.NAME,)),
    ("contacts", "Контакты", (EntityType.EMAIL, EntityType.PHONE)),
    ("accounts", "Аккаунты", (EntityType.USERNAME,)),
    ("birthdates", "Даты рождения", (EntityType.BIRTHDATE,)),
    ("organizations", "Организации", (EntityType.ORGANIZATION,)),
    ("addresses", "Адреса", (EntityType.ADDRESS,)),
)
FROM_LABELS = {
    "page": "распознано в загруженном тексте страницы",
    "snippet": "распознано только во фрагменте поисковика (страница не открывалась)",
    "fragment": "распознано в сохранённом фрагменте текста",
    "maigret": "Maigret: профиль с таким именем существует (не проверено)",
    "social": "страница соцсети, где замечен идентификатор",
}
DOSSIER_NOTE = (
    "Сущности распознаны автоматически (регулярные выражения и эвристики) и могут быть "
    "ошибочными. Одинаковое значение в разных источниках не означает, что речь об одном "
    "человеке: совпадение не устанавливает личность."
)


@dataclass(frozen=True, slots=True)
class Occurrence:
    """One place where an entity occurred."""

    finding_id: str
    title: str  # platform / site / document
    url: str
    context: str
    basis: str
    source: str  # page | snippet | fragment | maigret | social
    status: str  # verification status of the page (confirmed, skipped…)
    status_label: str
    confidence: Confidence
    kind_label: str = ""
    location: str = ""

    @property
    def confirmed(self) -> bool:
        """The page was downloaded and the entity read from its text (or from the fragment
        that was cut from that downloaded text)."""
        return self.status == "confirmed" and self.source in ("page", "fragment")

    @property
    def source_label(self) -> str:
        return FROM_LABELS.get(self.source, self.source)


@dataclass(slots=True)
class DossierItem:
    type: EntityType
    key: str
    display: str
    value: str
    platform: str | None = None
    url: str | None = None
    is_target: bool = False
    occurrences: list[Occurrence] = field(default_factory=list)

    @property
    def sources(self) -> int:
        return len({o.url for o in self.occurrences})

    @property
    def confirmed(self) -> bool:
        return any(o.confirmed for o in self.occurrences)

    @property
    def status_label(self) -> str:
        if self.confirmed:
            return "есть в тексте страницы"
        if any(o.source == "maigret" for o in self.occurrences):
            return "не проверено (Maigret)"
        if any(o.source == "social" for o in self.occurrences):
            return "ссылка на соцсеть"
        return "только фрагмент поисковика"


@dataclass(slots=True)
class DocumentItem:
    row: SeenRow

    @property
    def data_type(self) -> str:
        return self.row.data_type


@dataclass(slots=True)
class Dossier:
    sections: dict[str, list[DossierItem]]
    documents: list[DocumentItem]

    def section(self, name: str) -> list[DossierItem]:
        return self.sections.get(name, [])

    @property
    def total(self) -> int:
        return sum(len(items) for items in self.sections.values())

    def items(self) -> list[DossierItem]:
        return [item for items in self.sections.values() for item in items]


def _title(row: SeenRow) -> str:
    return row.platform or row.title or row.url


def _add(groups: dict[str, DossierItem], entity: Entity, occurrence: Occurrence) -> None:
    item = groups.get(entity.key)
    if item is None:
        item = groups[entity.key] = DossierItem(
            entity.type,
            entity.key,
            entity.display,
            entity.value,
            entity.platform,
            entity.url,
            entity.is_target,
        )
    item.is_target = item.is_target or entity.is_target
    if item.url is None and entity.url:
        item.url, item.platform = entity.url, entity.platform
        item.display = entity.display
    if not any(o.url == occurrence.url for o in item.occurrences):
        item.occurrences.append(occurrence)


def build_dossier(inv: Investigation, rows: list[SeenRow] | None = None) -> Dossier:
    rows = where_seen(inv) if rows is None else rows
    groups: dict[str, DossierItem] = {}
    for row in rows:
        for entity in row.entities:
            _add(
                groups,
                entity,
                Occurrence(
                    row.finding.id,
                    _title(row),
                    row.url,
                    entity.context,
                    entity.basis,
                    row.entities_from or "fragment",
                    row.status,
                    row.status_label,
                    row.confidence,
                    row.kind_label,
                    row.location,
                ),
            )
        if row.kind == "social":
            account = Entity(
                EntityType.USERNAME,
                row.url,
                row.fragment,
                "страница соцсети с упоминанием",
                row.platform or None,
                row.url,
            )
            item = DossierItem(
                EntityType.USERNAME,
                f"social:{row.url}",
                f"{row.platform or 'Соцсеть'}: {row.url}",
                row.url,
                row.platform or None,
                row.url,
            )
            groups.setdefault(item.key, item)
            _add_occurrence(groups[item.key], account, row, "social")
    for finding in inv.findings():
        value = finding.value
        if finding.attribute != "username.profile_candidate" or not isinstance(value, dict):
            continue
        site, url = str(value.get("site") or ""), str(value.get("url") or finding.source_url)
        key = f"maigret:{url}"
        item = groups.setdefault(
            key,
            DossierItem(
                EntityType.USERNAME,
                key,
                f"@{finding.subject} ({site})",
                finding.subject,
                site,
                url,
                True,
            ),
        )
        item.occurrences.append(
            Occurrence(
                finding.id,
                f"Maigret → {site}",
                url,
                finding.evidence,
                "Maigret: страница профиля ответила как существующая",
                "maigret",
                "unchecked",
                "не проверено (Maigret)",
                finding.confidence,
                "Профиль",
            )
        )
    sections: dict[str, list[DossierItem]] = {}
    for name, _, kinds in SECTIONS:
        items = [i for i in groups.values() if i.type in kinds]
        items.sort(
            key=lambda i: (
                not i.is_target,
                not i.confirmed,
                -i.sources,
                kinds.index(i.type),
                i.display.casefold(),
            )
        )
        sections[name] = items
    docs = [DocumentItem(r) for r in rows if r.kind == "document"]
    return Dossier(sections, docs)


def _add_occurrence(item: DossierItem, entity: Entity, row: SeenRow, source: str) -> None:
    if any(o.url == row.url for o in item.occurrences):
        return
    item.occurrences.append(
        Occurrence(
            row.finding.id,
            _title(row),
            row.url,
            row.fragment,
            entity.basis,
            source,
            row.status,
            row.status_label,
            row.confidence,
            row.kind_label,
            row.location,
        )
    )


def data_types_present(rows: list[SeenRow]) -> list[EntityType]:
    """Entity kinds that occur in at least one row (for the «Тип данных» filter)."""
    present = {k for r in rows for k in r.entity_types}
    return [k for k in ORDER if k in present]


__all__ = [
    "DOSSIER_NOTE",
    "SECTIONS",
    "DocumentItem",
    "Dossier",
    "DossierItem",
    "Occurrence",
    "build_dossier",
    "data_type_label",
    "data_types_present",
]

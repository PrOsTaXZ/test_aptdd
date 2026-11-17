"""«Где замечен идентификатор»: one row per page/document from the mention modules.

Shared by the console, the TUI and every report format, so all of them show the same table:
resource type, platform, URL, fragment (from the downloaded page when it was checked, otherwise
the search snippet), verification status and confidence. Documents and social networks are
subsets of the same rows.
"""

from __future__ import annotations

from dataclasses import dataclass

from osint_toolkit.analysis.entities import (
    Entity,
    EntityType,
    data_type_label,
    entities_from_json,
    extract_near,
)
from osint_toolkit.core.models import Confidence, Finding, Investigation, ModuleStatus, Target

CONSENT_MARKER = "согласия"
_ORDER = {
    "confirmed": 0,
    "manual": 1,
    "unchecked": 1,
    "absent": 2,
    "skipped": 3,
    "blocked": 4,
    "robots": 5,
}


@dataclass(frozen=True, slots=True)
class SeenRow:
    finding: Finding
    kind: str  # social / document / web / forum / …
    kind_label: str
    platform: str
    url: str
    title: str
    fragment: str
    location: str  # page/slide/sheet for documents
    doc_type: str
    status: str  # Check value
    status_label: str
    confidence: Confidence
    entities: tuple[Entity, ...] = ()
    entities_from: str | None = None  # page | snippet | fragment (older runs, plugins, Telegram)

    @property
    def confirmed(self) -> bool:
        return self.status == "confirmed"

    @property
    def entity_types(self) -> frozenset[EntityType]:
        return frozenset(e.type for e in self.entities)

    @property
    def data_type(self) -> str:
        """«Тип данных»: what was recognised on the page (Email, ФИО, Смешанные данные…)."""
        return data_type_label(self.entity_types)


def _text(value: object) -> str:
    return "" if value is None else str(value)


def where_seen(inv: Investigation) -> list[SeenRow]:
    rows: list[SeenRow] = []
    seen_urls: set[str] = set()
    for target, finding in _findings_with_targets(inv):
        value = finding.value
        if not (
            finding.attribute.startswith(("mention.", "plugin."))
            and not finding.attribute.endswith("_search_scope")
            and isinstance(value, dict)
            and "verification" in value
            and value.get("url")
        ):
            continue
        url = _text(value.get("url"))
        if url in seen_urls:
            continue
        seen_urls.add(url)
        entities, source = _row_entities(target, value)
        rows.append(
            SeenRow(
                finding=finding,
                kind=_text(value.get("resource")) or "web",
                kind_label=_text(value.get("resource_label")) or "Веб-страница",
                platform=_text(value.get("platform") or value.get("site")),
                url=url,
                title=_text(value.get("title")),
                fragment=_text(value.get("fragment") or value.get("snippet")),
                location=_text(value.get("location")),
                doc_type=_text(value.get("doc_type")),
                status=_text(value.get("verification")),
                status_label=_text(value.get("verification_label")),
                confidence=finding.confidence,
                entities=entities,
                entities_from=source,
            )
        )
    rows.sort(key=lambda r: (_ORDER.get(r.status, 6), r.kind != "document", r.platform))
    return rows


def _findings_with_targets(inv: Investigation) -> list[tuple[Target, Finding]]:
    return [(r.target, f) for r in inv.results for f in r.findings if not f.is_helper]


def _row_entities(
    target: Target, value: dict[str, object]
) -> tuple[tuple[Entity, ...], str | None]:
    """Entities stored by the module, or recognised now in the stored fragment (older runs,
    Telegram posts and plugin items keep only the fragment)."""
    if "entities" in value:
        stored = entities_from_json(value.get("entities"))
        source = value.get("entities_from")
        return tuple(stored), (str(source) if stored and source else None)
    text = "\n".join(_text(value.get(k)) for k in ("title", "fragment") if value.get(k))
    found = tuple(extract_near(target, text, whole=True)) if text else ()
    return found, ("fragment" if found else None)


def documents(rows: list[SeenRow]) -> list[SeenRow]:
    return [r for r in rows if r.kind == "document"]


def social(rows: list[SeenRow]) -> list[SeenRow]:
    return [r for r in rows if r.kind == "social"]


def skipped_for_consent(inv: Investigation) -> list[str]:
    """Titles of network modules that did not run because consent was not given."""
    return [
        r.module_title
        for r in inv.results
        if r.status is ModuleStatus.SKIPPED and any(CONSENT_MARKER in e for e in r.errors)
    ]


def consent_banner(inv: Investigation) -> str | None:
    skipped = skipped_for_consent(inv)
    if not skipped:
        return None
    return (
        f"Поиск в интернете не выполнялся: {len(skipped)} сетевых модулей пропущено, потому что "
        f"не было дано согласие ({', '.join(skipped[:6])}"
        + (" …" if len(skipped) > 6 else "")
        + "). Запустите исследование снова и в окне согласия нажмите «Разрешить всё и начать» "
        "(в CLI: ответ y или --allow all)."
    )

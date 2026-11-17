"""Detect sources that disagree about single-valued attributes.

A finding marked ``exclusive=True`` claims that the attribute has exactly one true value for its
subject (e.g. the registrar of a domain, the country of an IP). When two or more exclusive findings
for the same ``(subject, attribute)`` carry different normalised values, a :class:`Contradiction`
is produced. Nothing is resolved automatically: the report shows every variant with its sources and
the strongest confidence behind it, so the reader decides.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable

from osint_toolkit.core.models import (
    Confidence,
    Contradiction,
    ContradictionVariant,
    Finding,
    JsonValue,
)


def normalize_value(value: JsonValue) -> str:
    """Canonical comparison key: case/whitespace-insensitive strings, order-insensitive lists."""
    if isinstance(value, str):
        return " ".join(value.split()).casefold().rstrip(".")
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, int | float):
        return repr(float(value))
    if isinstance(value, list):
        return json.dumps(sorted(normalize_value(v) for v in value))
    return json.dumps({k: normalize_value(v) for k, v in sorted(value.items())}, ensure_ascii=False)


def detect_contradictions(findings: Iterable[Finding]) -> list[Contradiction]:
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.exclusive:
            groups[(finding.subject.casefold(), finding.attribute)].append(finding)

    contradictions: list[Contradiction] = []
    for (_, attribute), items in sorted(groups.items()):
        by_value: dict[str, list[Finding]] = defaultdict(list)
        for finding in items:
            by_value[normalize_value(finding.value)].append(finding)
        if len(by_value) < 2:
            continue

        variants = []
        for group in by_value.values():
            best = max((f.confidence for f in group), key=lambda c: c.rank)
            variants.append(
                ContradictionVariant(
                    value=group[0].value,
                    finding_ids=tuple(f.id for f in group),
                    sources=tuple(dict.fromkeys(f.source_name for f in group)),
                    best_confidence=best,
                )
            )
        variants.sort(key=lambda v: (-v.best_confidence.rank, len(v.sources) * -1))
        contradictions.append(
            Contradiction(
                subject=items[0].subject,
                attribute=attribute,
                variants=tuple(variants),
                description=_describe(items[0].subject, attribute, variants),
            )
        )
    return contradictions


def _describe(subject: str, attribute: str, variants: list[ContradictionVariant]) -> str:
    parts = [
        f"«{v.value}» ({', '.join(v.sources)}; {v.best_confidence.label.lower()})" for v in variants
    ]
    note = ""
    confirmed = [v for v in variants if v.best_confidence is Confidence.CONFIRMED]
    if len(confirmed) > 1:
        note = (
            " Несколько подтверждённых источников расходятся — данные могли измениться со временем."
        )
    elif len(confirmed) == 1:
        note = " Только один вариант подтверждён первичным источником."
    return (
        f"Источники расходятся в «{attribute}» для {subject}: "
        + " против ".join(parts)
        + "."
        + note
    )

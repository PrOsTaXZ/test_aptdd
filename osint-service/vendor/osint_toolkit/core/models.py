"""Data models shared by every layer.

Design rules:

* Every :class:`Finding` carries *who* says it (``source_name`` / ``source_url``), *when* it was
  observed (``observed_at``), *how sure* we are (``confidence``) and *what exactly* the source
  confirms (``evidence``). Reports never mix confidence levels.
* ``source_url`` is always present. Network sources use ``https://``; local or protocol sources use
  ``file://``, ``dns://`` (RFC 4501) or ``urn:`` so the origin of a fact is never implicit.
* Models are plain pydantic objects so they serialise losslessly to JSON (reports, history DB).
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

HELPER_PREFIXES = ("dork.",)  # aids for the user, reported separately from findings
ALLOWED_SOURCE_SCHEMES = ("https://", "http://", "file://", "dns://", "whois://", "urn:")

JsonValue = str | int | float | bool | None | list[Any] | dict[str, Any]


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


class TargetType(enum.StrEnum):
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    NAME = "name"
    IMAGE = "image"
    DOMAIN = "domain"
    IP = "ip"

    @property
    def label(self) -> str:
        return _TARGET_LABELS[self]


_TARGET_LABELS = {
    TargetType.EMAIL: "Email",
    TargetType.USERNAME: "Username",
    TargetType.PHONE: "Телефон",
    TargetType.NAME: "ФИО",
    TargetType.IMAGE: "Изображение",
    TargetType.DOMAIN: "Домен",
    TargetType.IP: "IP-адрес",
}


class Confidence(enum.StrEnum):
    """How strongly a finding is supported.

    * ``confirmed``  — read directly from an authoritative source (DNS answer, RDAP record, EXIF).
    * ``likely``     — strong indirect signal (profile page exists for the same username).
    * ``unverified`` — a mention or match that may refer to someone/something else.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"

    @property
    def rank(self) -> int:
        return {"confirmed": 3, "likely": 2, "unverified": 1}[self.value]

    @property
    def label(self) -> str:
        return {"confirmed": "Подтверждено", "likely": "Вероятно", "unverified": "Не проверено"}[
            self.value
        ]


class ModuleStatus(enum.StrEnum):
    OK = "ok"
    NO_RESULTS = "no_results"
    NOT_CONFIGURED = "not_configured"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ERROR = "error"
    CANCELLED = "cancelled"

    @property
    def label(self) -> str:
        return _STATUS_LABELS[self]


_STATUS_LABELS = {
    ModuleStatus.OK: "Готово",
    ModuleStatus.NO_RESULTS: "Нет данных",
    ModuleStatus.NOT_CONFIGURED: "Не настроен",
    ModuleStatus.SKIPPED: "Пропущен",
    ModuleStatus.TIMEOUT: "Таймаут",
    ModuleStatus.ERROR: "Ошибка",
    ModuleStatus.CANCELLED: "Отменён",
}


class InvestigationMode(enum.StrEnum):
    FULL = "full"  # auto-detected type, all compatible modules, related targets
    TARGETED = "targeted"  # user-chosen type and/or module subset


class InvestigationStatus(enum.StrEnum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Target(BaseModel):
    """A normalised search identifier."""

    model_config = ConfigDict(frozen=True)

    raw: str = Field(min_length=1)
    type: TargetType
    normalized: str = Field(min_length=1)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    derived_from: str | None = None  # normalized value of the parent target, if derived

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.normalized}"

    def __str__(self) -> str:
        return f"{self.type.label}: {self.normalized}"


class ExternalService(BaseModel):
    """A third party a module contacts. Shown to the user before consent is requested."""

    model_config = ConfigDict(frozen=True)

    name: str
    url: str
    data_sent: str  # human description, e.g. "домен", "email-адрес целиком"


class ExternalRequest(BaseModel):
    """One consent question: module X wants to send target Y to services Z."""

    model_config = ConfigDict(frozen=True)

    module: str
    module_title: str
    target: Target
    services: tuple[ExternalService, ...]
    details: tuple[str, ...] = ()  # exact data to be sent, e.g. search queries


class Finding(BaseModel):
    """A single sourced statement about a subject."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=new_id)
    module: str
    subject: str = Field(min_length=1)  # entity the statement is about
    attribute: str = Field(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")  # e.g. "domain.registrar"
    value: JsonValue
    confidence: Confidence
    source_name: str = Field(min_length=1)
    source_url: str = Field(min_length=1)
    evidence: str = Field(min_length=1)  # what exactly the source confirms
    observed_at: datetime = Field(default_factory=utcnow)
    exclusive: bool = False  # attribute should have exactly one true value per subject
    # Shown in the current session only; never written to history or reports (e.g. provider
    # terms forbid storing search results).
    ephemeral: bool = False

    @property
    def is_helper(self) -> bool:
        return self.attribute.startswith(HELPER_PREFIXES)

    @field_validator("source_url")
    @classmethod
    def _check_scheme(cls, value: str) -> str:
        if not value.startswith(ALLOWED_SOURCE_SCHEMES):
            raise ValueError(f"source_url must start with one of {ALLOWED_SOURCE_SCHEMES}")
        return value

    @field_validator("observed_at")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(UTC)


class ContradictionVariant(BaseModel):
    model_config = ConfigDict(frozen=True)

    value: JsonValue
    finding_ids: tuple[str, ...]
    sources: tuple[str, ...]
    best_confidence: Confidence


class Contradiction(BaseModel):
    """Sources disagree about an attribute that should have a single value."""

    model_config = ConfigDict(frozen=True)

    subject: str
    attribute: str
    variants: tuple[ContradictionVariant, ...]
    description: str


class ModuleResult(BaseModel):
    module: str
    module_title: str
    target: Target
    status: ModuleStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    external_services: list[ExternalService] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_s(self) -> float | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return round((self.finished_at - self.started_at).total_seconds(), 3)


class Investigation(BaseModel):
    id: str = Field(default_factory=new_id)
    mode: InvestigationMode
    query: str  # raw user input
    target: Target
    related_targets: list[Target] = Field(default_factory=list)
    status: InvestigationStatus = InvestigationStatus.COMPLETED
    offline: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    consent: dict[str, bool] = Field(default_factory=dict)  # "<module>@<target key>" -> allowed
    results: list[ModuleResult] = Field(default_factory=list)
    contradictions: list[Contradiction] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)  # engine-level problems (e.g. history save)
    app_version: str = ""

    def findings(self, confidence: Confidence | None = None) -> list[Finding]:
        """Statements about the target (helper items such as dork links are excluded)."""
        items = [f for r in self.results for f in r.findings if not f.is_helper]
        if confidence is not None:
            items = [f for f in items if f.confidence is confidence]
        return items

    def helper_findings(self) -> list[Finding]:
        """Tool-generated aids (search queries, manual links) — not facts about the target."""
        return [f for r in self.results for f in r.findings if f.is_helper]

    def persistable(self) -> Investigation:
        """Copy without ephemeral findings, with a note on what was left out and why."""
        dropped = sum(1 for f in self.findings() if f.ephemeral)
        if not dropped:
            return self
        results = [
            r.model_copy(update={"findings": [f for f in r.findings if not f.ephemeral]})
            for r in self.results
        ]
        note = (
            f"{dropped} результат(ов) поиска показаны только в сессии и не сохранены: условия "
            "провайдера запрещают хранить его поисковую выдачу."
        )
        return self.model_copy(update={"results": results, "warnings": [*self.warnings, note]})

    def status_counts(self) -> dict[ModuleStatus, int]:
        counts: dict[ModuleStatus, int] = {}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return counts

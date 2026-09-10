from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final, cast

from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, noload

from app.ingestion.ioc.validators import ValidationStatus, validate_indicator
from app.ingestion.models import Indicator, IOCType, RawArticle
from app.models.phase6b import (
    CorrelatedEvent,
    EventArticle,
    EventIndicator,
    ScoreComponentRecord,
    ScoreHistory,
)
from app.scoring.event_engine import EVENT_FORMULA_VERSION, calculate_event_score
from app.scoring.event_evidence_snapshot import build_event_evidence_snapshot
from app.scoring.event_models import (
    EventScoreResult,
    EventScoringEvidence,
    MemberIndicatorScoreEvidence,
)
from app.scoring.evidence_snapshot import CanonicalEvidenceSnapshot
from app.scoring.models import ScoreComponent, ScoringInputError, Severity
from app.scoring.normalization import normalize_sources, severity_for
from app.services.cve_correlation import RULE_NAME, RULE_VERSION

EVENT_EVIDENCE_UNIQUE_INDEX: Final = "uq_score_history_event_evidence"


class EventNotFoundError(LookupError):
    pass


class UnsupportedEventError(ValueError):
    pass


class InvalidEventKeyError(ValueError):
    pass


class MissingMatchingCVERelationshipError(ValueError):
    pass


class AmbiguousEventRelationshipsError(ValueError):
    pass


class InconsistentEventRelationshipsError(ValueError):
    pass


class InvalidStoredScoreEvidenceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PersistedEventScore:
    score_history: ScoreHistory
    components: tuple[ScoreComponentRecord, ...]
    created: bool
    evidence_hash: str


def calculate_and_persist_event_score(
    session: Session,
    event_id: int,
    *,
    as_of: datetime,
) -> PersistedEventScore:
    evidence = load_event_scoring_evidence(session, event_id, as_of=as_of)
    snapshot = build_event_evidence_snapshot(evidence)
    result = calculate_event_score(evidence)
    return persist_event_score(session, event_id=event_id, result=result, snapshot=snapshot)


def load_event_scoring_evidence(
    session: Session,
    event_id: int,
    *,
    as_of: datetime,
) -> EventScoringEvidence:
    as_of_utc = _strict_aware(as_of, "as_of")
    event = session.scalar(
        select(CorrelatedEvent)
        .options(
            noload(CorrelatedEvent.article_links),
            noload(CorrelatedEvent.indicator_links),
            noload(CorrelatedEvent.scores),
        )
        .where(CorrelatedEvent.id == event_id)
    )
    if event is None:
        raise EventNotFoundError(f"event {event_id} was not found")
    if event.rule_name != RULE_NAME or event.rule_version != RULE_VERSION:
        raise UnsupportedEventError("event is not a shared-cve v1 event")
    canonical_cve = _canonical_cve_from_key(event.event_key)
    relationships = list(
        session.execute(
            select(Indicator.id, Indicator.indicator_type, Indicator.indicator_value)
            .join(EventIndicator, EventIndicator.indicator_id == Indicator.id)
            .where(EventIndicator.event_id == event.id)
            .order_by(Indicator.id)
        )
    )
    cves = [row for row in relationships if row.indicator_type is IOCType.CVE]
    if not cves:
        raise MissingMatchingCVERelationshipError("event has no CVE relationship")
    if len(cves) > 1:
        raise AmbiguousEventRelationshipsError("event has multiple CVE relationships")
    cve = cves[0]
    validation = validate_indicator(IOCType.CVE, cve.indicator_value)
    if (
        validation.status is not ValidationStatus.VALID
        or validation.normalized_value != cve.indicator_value
    ):
        raise InconsistentEventRelationshipsError("related CVE is not canonical")
    if cve.indicator_value != canonical_cve:
        raise InconsistentEventRelationshipsError("event key and related CVE disagree")

    latest = session.scalar(
        select(ScoreHistory)
        .options(
            noload(ScoreHistory.components),
            noload(ScoreHistory.indicator),
            noload(ScoreHistory.event),
        )
        .where(ScoreHistory.target_kind == "indicator", ScoreHistory.indicator_id == cve.id)
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(1)
    )
    member = _member_score(latest, cve.id) if latest is not None else None
    source_names = normalize_sources(
        tuple(
            cast(str, value)
            for value in session.scalars(
                select(RawArticle.source_name)
                .join(EventArticle, EventArticle.article_id == RawArticle.id)
                .where(
                    EventArticle.event_id == event.id,
                    RawArticle.source_name.is_not(None),
                    func.length(func.trim(RawArticle.source_name)) > 0,
                )
                .order_by(RawArticle.source_name, RawArticle.id)
            )
        )
    )
    return EventScoringEvidence(
        event_id=event.id,
        event_key=event.event_key,
        rule_name=event.rule_name,
        rule_version=event.rule_version,
        cve_indicator_id=cve.id,
        canonical_cve=canonical_cve,
        as_of=as_of_utc,
        member_score=member,
        source_names=source_names,
    )


def persist_event_score(
    session: Session,
    *,
    event_id: int,
    result: EventScoreResult,
    snapshot: CanonicalEvidenceSnapshot,
) -> PersistedEventScore:
    existing = _find_existing(session, event_id, snapshot.evidence_hash)
    if existing is not None:
        return _persisted_result(session, existing, result, snapshot, created=False)
    component_rows = [_component_record(component) for component in result.components]
    history = ScoreHistory(
        target_kind="event",
        indicator_id=None,
        event_id=event_id,
        score=result.final_score,
        severity=result.severity.value,
        formula_version=EVENT_FORMULA_VERSION,
        evidence_hash=snapshot.evidence_hash,
        canonical_evidence=snapshot.payload(),
        calculated_at=_strict_aware(result.calculated_at, "result.calculated_at"),
        components=component_rows,
    )
    try:
        with session.begin_nested():
            session.add(history)
            session.flush()
    except IntegrityError as exc:
        if not _is_event_idempotency_violation(exc):
            raise
        existing = _find_existing(session, event_id, snapshot.evidence_hash)
        if existing is None:
            raise
        return _persisted_result(session, existing, result, snapshot, created=False)
    return PersistedEventScore(history, tuple(component_rows), True, snapshot.evidence_hash)


def _find_existing(session: Session, event_id: int, evidence_hash: str) -> ScoreHistory | None:
    with session.no_autoflush:
        return session.scalar(
            select(ScoreHistory)
            .options(
                noload(ScoreHistory.components),
                noload(ScoreHistory.indicator),
                noload(ScoreHistory.event),
            )
            .where(
                ScoreHistory.target_kind == "event",
                ScoreHistory.event_id == event_id,
                ScoreHistory.formula_version == EVENT_FORMULA_VERSION,
                ScoreHistory.evidence_hash == evidence_hash,
            )
        )


def _persisted_result(
    session: Session,
    history: ScoreHistory,
    result: EventScoreResult,
    snapshot: CanonicalEvidenceSnapshot,
    *,
    created: bool,
) -> PersistedEventScore:
    order = {item.name: position for position, item in enumerate(result.components)}
    rows = tuple(
        session.scalars(
            select(ScoreComponentRecord)
            .where(ScoreComponentRecord.score_history_id == history.id)
            .order_by(
                case(order, value=ScoreComponentRecord.component_name),
                ScoreComponentRecord.component_name,
            )
        )
    )
    if tuple(row.component_name for row in rows) != tuple(order):
        raise InvalidStoredScoreEvidenceError("persisted event-score components are inconsistent")
    return PersistedEventScore(history, rows, created, snapshot.evidence_hash)


def _member_score(history: ScoreHistory, indicator_id: int) -> MemberIndicatorScoreEvidence:
    try:
        score = history.score
        if (
            not isinstance(score, Decimal)
            or not score.is_finite()
            or not Decimal("0") <= score <= Decimal("100")
        ):
            raise ValueError
        severity = Severity(history.severity)
        if severity is not severity_for(score):
            raise ValueError
        calculated_at = _database_aware(history.calculated_at, "member calculated_at")
        return MemberIndicatorScoreEvidence(
            score_history_id=history.id,
            indicator_id=indicator_id,
            score=score,
            severity=severity,
            formula_version=history.formula_version,
            evidence_hash=history.evidence_hash,
            calculated_at=calculated_at,
        )
    except (ValueError, ScoringInputError, TypeError) as exc:
        raise InvalidStoredScoreEvidenceError("latest indicator score is invalid") from exc


def _canonical_cve_from_key(event_key: str) -> str:
    if not event_key.startswith("cve:"):
        raise InvalidEventKeyError("event key is not a CVE key")
    value = event_key.removeprefix("cve:")
    validation = validate_indicator(IOCType.CVE, value)
    if validation.status is not ValidationStatus.VALID or validation.normalized_value != value:
        raise InvalidEventKeyError("event key does not contain a canonical CVE")
    return value


def _component_record(component: ScoreComponent) -> ScoreComponentRecord:
    return ScoreComponentRecord(
        component_name=component.name,
        raw_input={key: _json_value(value) for key, value in component.raw_input},
        normalized_input=_json_value(component.normalized_value),
        weight=component.weight,
        contribution=component.contribution,
        freshness_multiplier=component.freshness_multiplier,
        explanation=component.explanation,
        provider=component.provider,
        evidence_at=component.evidence_at,
    )


def _json_value(value: object) -> str | int | bool | None:
    if value is None or type(value) in {str, int, bool}:
        return cast(str | int | bool | None, value)
    if isinstance(value, Decimal) and value.is_finite():
        return format(value, "f")
    raise ScoringInputError("component value is not JSON-safe")


def _strict_aware(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ScoringInputError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _database_aware(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise InvalidStoredScoreEvidenceError(f"{name} is invalid")
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _is_event_idempotency_violation(exc: IntegrityError) -> bool:
    diagnostic = getattr(exc.orig, "diag", None)
    constraint_name = getattr(diagnostic, "constraint_name", None)
    if constraint_name is not None:
        return constraint_name == EVENT_EVIDENCE_UNIQUE_INDEX
    message = str(exc.orig).casefold()
    return all(
        value in message
        for value in (
            "score_history.event_id",
            "score_history.formula_version",
            "score_history.evidence_hash",
        )
    )


__all__ = [
    "AmbiguousEventRelationshipsError",
    "EventNotFoundError",
    "InconsistentEventRelationshipsError",
    "InvalidEventKeyError",
    "InvalidStoredScoreEvidenceError",
    "MissingMatchingCVERelationshipError",
    "PersistedEventScore",
    "UnsupportedEventError",
    "calculate_and_persist_event_score",
    "load_event_scoring_evidence",
    "persist_event_score",
]

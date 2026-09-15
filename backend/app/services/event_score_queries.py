from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final, cast

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, noload, selectinload

from app.models.phase6b import CorrelatedEvent, ScoreComponentRecord, ScoreHistory
from app.schemas.event_scores import (
    EventScoreComponentResponse,
    EventScoreHistoryResponse,
    EventScoreResponse,
)
from app.schemas.indicator_scores import JsonScalar
from app.scoring.models import EvidenceStatus, Severity

_COMPONENT_ORDER: Final = {
    "member_indicator_score": 0,
    "independent_sources": 1,
}


class EventNotFoundError(LookupError):
    """Raised when a requested correlated event does not exist."""


class EventScoreNotFoundError(LookupError):
    """Raised when an existing event has no persisted event score."""


def get_latest_event_score(session: Session, event_id: int) -> EventScoreResponse:
    """Return the newest persisted event score without calculating or writing."""

    history = session.scalar(
        _score_query(event_id)
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(1)
    )
    if history is None:
        _require_event(session, event_id)
        raise EventScoreNotFoundError(event_id)
    event = cast(CorrelatedEvent, history.event)
    return event_score_response(history, event, history.components)


def list_event_score_history(
    session: Session,
    event_id: int,
    *,
    limit: int,
    offset: int,
) -> EventScoreHistoryResponse:
    """Return a bounded newest-first event-score history page."""

    event, total = _event_and_score_total(session, event_id)
    histories = session.scalars(
        select(ScoreHistory)
        .options(
            selectinload(ScoreHistory.components),
            noload(ScoreHistory.indicator),
            noload(ScoreHistory.event),
        )
        .where(*_score_predicate(event_id))
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return EventScoreHistoryResponse(
        event_id=event_id,
        items=[event_score_response(item, event, item.components) for item in histories],
        limit=limit,
        offset=offset,
        total=total,
    )


def latest_event_score_calculated_at(session: Session, event_id: int) -> datetime | None:
    """Return the reusable calculation context for a prior persisted event score."""

    value = session.scalar(
        select(ScoreHistory.calculated_at)
        .where(*_score_predicate(event_id))
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(1)
    )
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def event_score_response(
    history: ScoreHistory,
    event: CorrelatedEvent,
    components: list[ScoreComponentRecord] | tuple[ScoreComponentRecord, ...],
) -> EventScoreResponse:
    """Map trusted persisted score rows to the safe event-specific API contract."""

    ordered = sorted(components, key=_component_sort_key)
    return EventScoreResponse(
        id=history.id,
        event_id=cast(int, history.event_id),
        event_key=event.event_key,
        event_title=event.title,
        score=history.score,
        severity=Severity(history.severity),
        formula_version=history.formula_version,
        evidence_hash=history.evidence_hash,
        as_of=_stored_as_of(history.canonical_evidence, history.calculated_at),
        calculated_at=history.calculated_at,
        components=[
            EventScoreComponentResponse(
                name=row.component_name,
                raw_input=cast(dict[str, JsonScalar] | list[JsonScalar], row.raw_input),
                normalized_value=cast(JsonScalar, row.normalized_input),
                weight=row.weight,
                contribution=row.contribution,
                freshness_multiplier=row.freshness_multiplier,
                status=_component_status(row.component_name, history.canonical_evidence),
                provider=row.provider,
                evidence_at=row.evidence_at,
                explanation=row.explanation,
            )
            for row in ordered
        ],
    )


def _score_query(event_id: int) -> Any:
    return (
        select(ScoreHistory)
        .options(
            joinedload(ScoreHistory.event).options(
                noload(CorrelatedEvent.article_links),
                noload(CorrelatedEvent.indicator_links),
                noload(CorrelatedEvent.scores),
            ),
            selectinload(ScoreHistory.components),
            noload(ScoreHistory.indicator),
        )
        .where(*_score_predicate(event_id))
    )


def _score_predicate(event_id: int) -> tuple[Any, ...]:
    return (
        ScoreHistory.target_kind == "event",
        ScoreHistory.event_id == event_id,
        ScoreHistory.indicator_id.is_(None),
    )


def _require_event(session: Session, event_id: int) -> CorrelatedEvent:
    event = session.get(CorrelatedEvent, event_id)
    if event is None:
        raise EventNotFoundError(event_id)
    return event


def _event_and_score_total(session: Session, event_id: int) -> tuple[CorrelatedEvent, int]:
    total = select(func.count(ScoreHistory.id)).where(*_score_predicate(event_id)).scalar_subquery()
    row = session.execute(
        select(CorrelatedEvent, total.label("score_total"))
        .options(
            noload(CorrelatedEvent.article_links),
            noload(CorrelatedEvent.indicator_links),
            noload(CorrelatedEvent.scores),
        )
        .where(CorrelatedEvent.id == event_id)
    ).one_or_none()
    if row is None:
        raise EventNotFoundError(event_id)
    return row[0], int(row.score_total)


def _component_status(name: str, payload: dict[str, Any]) -> EvidenceStatus:
    if name == "independent_sources":
        return EvidenceStatus.USABLE
    if name != "member_indicator_score":
        return EvidenceStatus.INVALID
    member = payload.get("member_indicator_score")
    if not isinstance(member, dict):
        return EvidenceStatus.INVALID
    status = member.get("status")
    if status == "present":
        return EvidenceStatus.USABLE
    if status == "missing":
        return EvidenceStatus.MISSING
    return EvidenceStatus.INVALID


def _component_sort_key(item: ScoreComponentRecord) -> tuple[int, str]:
    return _COMPONENT_ORDER.get(item.component_name, len(_COMPONENT_ORDER)), item.component_name


def _stored_as_of(payload: dict[str, Any], fallback: datetime) -> datetime:
    value = payload.get("as_of")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                return parsed.astimezone(UTC)
        except ValueError:
            pass
    return fallback.replace(tzinfo=UTC) if fallback.tzinfo is None else fallback.astimezone(UTC)


__all__ = [
    "EventNotFoundError",
    "EventScoreNotFoundError",
    "event_score_response",
    "get_latest_event_score",
    "latest_event_score_calculated_at",
    "list_event_score_history",
]

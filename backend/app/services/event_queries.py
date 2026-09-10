from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ingestion.models import Indicator, IOCType, RawArticle
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator, ScoreHistory
from app.schemas.events import (
    EventArticleListResponse,
    EventArticleResponse,
    EventDetailResponse,
    EventIndicatorListResponse,
    EventIndicatorResponse,
    EventListResponse,
    EventSummaryResponse,
    PersistedScoreSummary,
)


class EventNotFoundError(LookupError):
    """Raised when a requested correlated event does not exist."""


def list_events(
    session: Session,
    *,
    limit: int,
    offset: int,
    cve: str | None = None,
    source_name: str | None = None,
    updated_from: datetime | None = None,
    updated_to: datetime | None = None,
) -> EventListResponse:
    """Return a filtered event page in two SQL statements."""

    predicates = _event_filters(
        cve=cve,
        source_name=source_name,
        updated_from=updated_from,
        updated_to=updated_to,
    )
    total = session.scalar(select(func.count(CorrelatedEvent.id)).where(*predicates)) or 0
    rows = session.execute(
        _event_projection()
        .where(*predicates)
        .order_by(CorrelatedEvent.updated_at.desc(), CorrelatedEvent.id.desc())
        .limit(limit)
        .offset(offset)
    ).mappings()
    return EventListResponse(
        items=[_event_response(row, detail=False) for row in rows],
        limit=limit,
        offset=offset,
        total=total,
    )


def get_event(session: Session, event_id: int) -> EventDetailResponse:
    """Return one event and its aggregate metadata in one SQL statement."""

    row = (
        session.execute(_event_projection().where(CorrelatedEvent.id == event_id))
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise EventNotFoundError(event_id)
    return cast(EventDetailResponse, _event_response(row, detail=True))


def list_event_articles(
    session: Session,
    event_id: int,
    *,
    limit: int,
    offset: int,
) -> EventArticleListResponse:
    """Return a bounded relationship page, newest useful article timestamp first."""

    total = _relationship_total(session, event_id, EventArticle)
    rows = session.execute(
        select(
            RawArticle.id,
            RawArticle.source_id,
            RawArticle.source_name,
            RawArticle.title,
            RawArticle.url,
            RawArticle.published_at,
            RawArticle.fetched_at,
            RawArticle.author,
            RawArticle.categories,
            EventArticle.reason.label("relationship_reason"),
            EventArticle.rule_name.label("relationship_rule_name"),
            EventArticle.rule_version.label("relationship_rule_version"),
            EventArticle.created_at.label("relationship_created_at"),
        )
        .join(EventArticle, EventArticle.article_id == RawArticle.id)
        .where(EventArticle.event_id == event_id)
        .order_by(
            func.coalesce(RawArticle.published_at, RawArticle.fetched_at).desc(),
            RawArticle.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    ).mappings()
    return EventArticleListResponse(
        event_id=event_id,
        items=[
            EventArticleResponse(
                id=row["id"],
                source_id=row["source_id"],
                source_name=row["source_name"],
                title=row["title"],
                url=row["url"],
                published_at=row["published_at"],
                fetched_at=row["fetched_at"],
                author=row["author"],
                categories=_categories(row["categories"]),
                relationship_reason=row["relationship_reason"],
                relationship_rule_name=row["relationship_rule_name"],
                relationship_rule_version=row["relationship_rule_version"],
                relationship_created_at=row["relationship_created_at"],
            )
            for row in rows
        ],
        limit=limit,
        offset=offset,
        total=total,
    )


def list_event_indicators(
    session: Session,
    event_id: int,
    *,
    limit: int,
    offset: int,
) -> EventIndicatorListResponse:
    """Return a bounded indicator page with deterministic persisted score summaries."""

    total = _relationship_total(session, event_id, EventIndicator)
    latest_score = _latest_indicator_score_subquery()
    rows = session.execute(
        select(
            Indicator.id,
            Indicator.indicator_type,
            Indicator.indicator_value,
            Indicator.created_at,
            EventIndicator.reason.label("relationship_reason"),
            EventIndicator.rule_name.label("relationship_rule_name"),
            EventIndicator.rule_version.label("relationship_rule_version"),
            EventIndicator.created_at.label("relationship_created_at"),
            latest_score.c.score,
            latest_score.c.severity,
            latest_score.c.formula_version,
            latest_score.c.calculated_at,
        )
        .join(EventIndicator, EventIndicator.indicator_id == Indicator.id)
        .outerjoin(
            latest_score,
            (latest_score.c.target_id == Indicator.id) & (latest_score.c.score_rank == 1),
        )
        .where(EventIndicator.event_id == event_id)
        .order_by(Indicator.indicator_type, Indicator.indicator_value, Indicator.id)
        .limit(limit)
        .offset(offset)
    ).mappings()
    return EventIndicatorListResponse(
        event_id=event_id,
        items=[
            EventIndicatorResponse(
                id=row["id"],
                indicator_type=row["indicator_type"],
                indicator_value=row["indicator_value"],
                created_at=row["created_at"],
                relationship_reason=row["relationship_reason"],
                relationship_rule_name=row["relationship_rule_name"],
                relationship_rule_version=row["relationship_rule_version"],
                relationship_created_at=row["relationship_created_at"],
                latest_score=_score_summary(row),
            )
            for row in rows
        ],
        limit=limit,
        offset=offset,
        total=total,
    )


def _event_projection() -> Any:
    article_counts = (
        select(EventArticle.event_id, func.count().label("article_count"))
        .group_by(EventArticle.event_id)
        .subquery()
    )
    indicator_counts = (
        select(EventIndicator.event_id, func.count().label("indicator_count"))
        .group_by(EventIndicator.event_id)
        .subquery()
    )
    latest_score = _latest_event_score_subquery()
    return (
        select(
            CorrelatedEvent.id,
            CorrelatedEvent.event_key,
            CorrelatedEvent.title,
            CorrelatedEvent.rule_name,
            CorrelatedEvent.rule_version,
            CorrelatedEvent.created_at,
            CorrelatedEvent.updated_at,
            func.coalesce(article_counts.c.article_count, 0).label("article_count"),
            func.coalesce(indicator_counts.c.indicator_count, 0).label("indicator_count"),
            latest_score.c.score,
            latest_score.c.severity,
            latest_score.c.formula_version,
            latest_score.c.calculated_at,
        )
        .outerjoin(article_counts, article_counts.c.event_id == CorrelatedEvent.id)
        .outerjoin(indicator_counts, indicator_counts.c.event_id == CorrelatedEvent.id)
        .outerjoin(
            latest_score,
            (latest_score.c.target_id == CorrelatedEvent.id) & (latest_score.c.score_rank == 1),
        )
    )


def _event_filters(
    *,
    cve: str | None,
    source_name: str | None,
    updated_from: datetime | None,
    updated_to: datetime | None,
) -> tuple[Any, ...]:
    predicates: list[Any] = []
    if cve is not None:
        predicates.append(
            select(EventIndicator.event_id)
            .join(Indicator, Indicator.id == EventIndicator.indicator_id)
            .where(
                EventIndicator.event_id == CorrelatedEvent.id,
                Indicator.indicator_type == IOCType.CVE,
                Indicator.indicator_value == cve,
            )
            .exists()
        )
    if source_name is not None:
        predicates.append(
            select(EventArticle.event_id)
            .join(RawArticle, RawArticle.id == EventArticle.article_id)
            .where(
                EventArticle.event_id == CorrelatedEvent.id,
                RawArticle.source_name == source_name,
            )
            .exists()
        )
    if updated_from is not None:
        predicates.append(CorrelatedEvent.updated_at >= updated_from)
    if updated_to is not None:
        predicates.append(CorrelatedEvent.updated_at <= updated_to)
    return tuple(predicates)


def _relationship_total(session: Session, event_id: int, relationship: Any) -> int:
    row = session.execute(
        select(
            CorrelatedEvent.id,
            select(func.count())
            .select_from(relationship)
            .where(relationship.event_id == CorrelatedEvent.id)
            .scalar_subquery()
            .label("total"),
        ).where(CorrelatedEvent.id == event_id)
    ).one_or_none()
    if row is None:
        raise EventNotFoundError(event_id)
    return int(row.total)


def _latest_event_score_subquery() -> Any:
    return (
        select(
            ScoreHistory.event_id.label("target_id"),
            ScoreHistory.score,
            ScoreHistory.severity,
            ScoreHistory.formula_version,
            ScoreHistory.calculated_at,
            func.row_number()
            .over(
                partition_by=ScoreHistory.event_id,
                order_by=(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc()),
            )
            .label("score_rank"),
        )
        .where(ScoreHistory.target_kind == "event", ScoreHistory.event_id.is_not(None))
        .subquery()
    )


def _latest_indicator_score_subquery() -> Any:
    return (
        select(
            ScoreHistory.indicator_id.label("target_id"),
            ScoreHistory.score,
            ScoreHistory.severity,
            ScoreHistory.formula_version,
            ScoreHistory.calculated_at,
            func.row_number()
            .over(
                partition_by=ScoreHistory.indicator_id,
                order_by=(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc()),
            )
            .label("score_rank"),
        )
        .where(ScoreHistory.target_kind == "indicator", ScoreHistory.indicator_id.is_not(None))
        .subquery()
    )


def _event_response(row: Any, *, detail: bool) -> EventSummaryResponse | EventDetailResponse:
    response_type = EventDetailResponse if detail else EventSummaryResponse
    return response_type(
        id=row["id"],
        event_key=row["event_key"],
        title=row["title"],
        rule_name=row["rule_name"],
        rule_version=row["rule_version"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        article_count=row["article_count"],
        indicator_count=row["indicator_count"],
        latest_score=_score_summary(row),
    )


def _score_summary(row: Any) -> PersistedScoreSummary | None:
    if row["score"] is None:
        return None
    return PersistedScoreSummary(
        score=row["score"],
        severity=row["severity"],
        formula_version=row["formula_version"],
        calculated_at=row["calculated_at"],
    )


def _categories(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


__all__ = [
    "EventNotFoundError",
    "get_event",
    "list_event_articles",
    "list_event_indicators",
    "list_events",
]

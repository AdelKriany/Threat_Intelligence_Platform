from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, noload

from app.ingestion.ioc.validators import ValidationStatus, validate_indicator
from app.ingestion.models import ArticleIndicator, Indicator, IOCType
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator

RULE_NAME: Final = "shared-cve"
RULE_VERSION: Final = "v1"
RELATIONSHIP_REASON: Final = "shared_canonical_cve"


class CorrelationIndicatorNotFoundError(LookupError):
    """Raised when the requested stored indicator does not exist."""


class UnsupportedCorrelationIndicatorError(ValueError):
    """Raised when exact CVE correlation receives another IOC type."""


class InvalidCVEIndicatorError(ValueError):
    """Raised when a stored CVE value is malformed or not canonical uppercase."""


class CorrelationInvariantError(RuntimeError):
    """Raised when a stable event key already has incompatible rule metadata."""


@dataclass(frozen=True, slots=True)
class CVECorrelationResult:
    event: CorrelatedEvent
    event_created: bool
    indicator_link_created: bool
    article_link_ids_created: tuple[int, ...]

    @property
    def article_links_created(self) -> int:
        return len(self.article_link_ids_created)


def correlate_cve_indicator(
    session: Session,
    indicator_id: int,
    *,
    as_of: datetime,
) -> CVECorrelationResult:
    """Create or extend the exact-CVE event for one canonical stored indicator.

    The caller owns the transaction. This service issues writes and flushes ORM state,
    but never commits or rolls back the caller's outer transaction.
    """

    correlated_at = _aware_utc(as_of)
    indicator = session.scalar(
        select(Indicator)
        .options(
            noload(Indicator.articles),
            noload(Indicator.enrichments),
            noload(Indicator.epss_history),
        )
        .where(Indicator.id == indicator_id)
    )
    if indicator is None:
        raise CorrelationIndicatorNotFoundError(f"indicator {indicator_id} was not found")
    canonical_cve = _canonical_cve(indicator)

    article_ids = tuple(
        session.scalars(
            select(ArticleIndicator.raw_article_id)
            .where(ArticleIndicator.indicator_id == indicator.id)
            .order_by(ArticleIndicator.raw_article_id)
        )
    )
    event_key = f"cve:{canonical_cve}"
    title = f"{canonical_cve} vulnerability"
    event_created = _insert_event(
        session,
        event_key=event_key,
        title=title,
        as_of=correlated_at,
    )
    event = session.scalar(
        select(CorrelatedEvent)
        .options(
            noload(CorrelatedEvent.article_links),
            noload(CorrelatedEvent.indicator_links),
            noload(CorrelatedEvent.scores),
        )
        .where(CorrelatedEvent.event_key == event_key)
    )
    if event is None:  # pragma: no cover - protected by insert/select transaction semantics
        raise CorrelationInvariantError(f"event {event_key!r} was not found after insert")
    _require_event_metadata(event, title)

    indicator_link_created = _insert_indicator_link(
        session,
        event_id=event.id,
        indicator_id=indicator.id,
        as_of=correlated_at,
    )
    article_link_ids = _insert_article_links(
        session,
        event_id=event.id,
        article_ids=article_ids,
        as_of=correlated_at,
    )
    if not event_created and (indicator_link_created or article_link_ids):
        session.execute(
            update(CorrelatedEvent)
            .where(CorrelatedEvent.id == event.id)
            .values(updated_at=correlated_at)
        )
        event.updated_at = correlated_at
    session.flush()
    return CVECorrelationResult(
        event=event,
        event_created=event_created,
        indicator_link_created=indicator_link_created,
        article_link_ids_created=article_link_ids,
    )


def _canonical_cve(indicator: Indicator) -> str:
    if indicator.indicator_type is not IOCType.CVE:
        raise UnsupportedCorrelationIndicatorError(
            f"indicator {indicator.id} has unsupported type {indicator.indicator_type.value!r}"
        )
    validation = validate_indicator(IOCType.CVE, indicator.indicator_value)
    if (
        validation.status is not ValidationStatus.VALID
        or validation.normalized_value != indicator.indicator_value
    ):
        raise InvalidCVEIndicatorError(
            f"indicator {indicator.id} is not a valid canonical uppercase CVE"
        )
    return indicator.indicator_value


def _require_event_metadata(event: CorrelatedEvent, title: str) -> None:
    if event.title != title or event.rule_name != RULE_NAME or event.rule_version != RULE_VERSION:
        raise CorrelationInvariantError(
            f"event {event.event_key!r} has incompatible exact-CVE rule metadata"
        )


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("as_of must be a timezone-aware datetime")
    return value.astimezone(UTC)


def _insert_event(
    session: Session,
    *,
    event_key: str,
    title: str,
    as_of: datetime,
) -> bool:
    values = {
        "event_key": event_key,
        "title": title,
        "rule_name": RULE_NAME,
        "rule_version": RULE_VERSION,
        "created_at": as_of,
        "updated_at": as_of,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement = (
            postgresql_insert(CorrelatedEvent)
            .values(values)
            .on_conflict_do_nothing(constraint="uq_correlated_events_event_key")
            .returning(CorrelatedEvent.id)
        )
    elif dialect == "sqlite":
        statement = (
            sqlite_insert(CorrelatedEvent)
            .values(values)
            .on_conflict_do_nothing(index_elements=["event_key"])
            .returning(CorrelatedEvent.id)
        )
    else:  # pragma: no cover - production and portable tests use PostgreSQL/SQLite
        raise RuntimeError(f"exact CVE correlation does not support dialect {dialect!r}")
    return session.scalar(statement) is not None


def _insert_indicator_link(
    session: Session,
    *,
    event_id: int,
    indicator_id: int,
    as_of: datetime,
) -> bool:
    values = {
        "event_id": event_id,
        "indicator_id": indicator_id,
        "reason": RELATIONSHIP_REASON,
        "rule_name": RULE_NAME,
        "rule_version": RULE_VERSION,
        "created_at": as_of,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement = (
            postgresql_insert(EventIndicator)
            .values(values)
            .on_conflict_do_nothing(constraint="pk_event_indicators")
            .returning(EventIndicator.indicator_id)
        )
    elif dialect == "sqlite":
        statement = (
            sqlite_insert(EventIndicator)
            .values(values)
            .on_conflict_do_nothing(index_elements=["event_id", "indicator_id"])
            .returning(EventIndicator.indicator_id)
        )
    else:  # pragma: no cover
        raise RuntimeError(f"exact CVE correlation does not support dialect {dialect!r}")
    return session.scalar(statement) is not None


def _insert_article_links(
    session: Session,
    *,
    event_id: int,
    article_ids: tuple[int, ...],
    as_of: datetime,
) -> tuple[int, ...]:
    if not article_ids:
        return ()
    values = [
        {
            "event_id": event_id,
            "article_id": article_id,
            "reason": RELATIONSHIP_REASON,
            "rule_name": RULE_NAME,
            "rule_version": RULE_VERSION,
            "created_at": as_of,
        }
        for article_id in article_ids
    ]
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement = (
            postgresql_insert(EventArticle)
            .values(values)
            .on_conflict_do_nothing(constraint="pk_event_articles")
            .returning(EventArticle.article_id)
        )
    elif dialect == "sqlite":
        statement = (
            sqlite_insert(EventArticle)
            .values(values)
            .on_conflict_do_nothing(index_elements=["event_id", "article_id"])
            .returning(EventArticle.article_id)
        )
    else:  # pragma: no cover
        raise RuntimeError(f"exact CVE correlation does not support dialect {dialect!r}")
    return tuple(sorted(session.scalars(statement)))


__all__ = [
    "CVECorrelationResult",
    "CorrelationIndicatorNotFoundError",
    "CorrelationInvariantError",
    "InvalidCVEIndicatorError",
    "RELATIONSHIP_REASON",
    "RULE_NAME",
    "RULE_VERSION",
    "UnsupportedCorrelationIndicatorError",
    "correlate_cve_indicator",
]

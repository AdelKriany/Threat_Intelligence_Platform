"""Bounded dry-run/apply backfill for exact canonical-CVE events."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.database.session import SessionLocal
from app.ingestion.ioc.validators import ValidationStatus, validate_indicator
from app.ingestion.models import ArticleIndicator, Indicator, IOCType
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator
from app.services.cve_correlation import (
    RULE_NAME,
    RULE_VERSION,
    CorrelationInvariantError,
    correlate_cve_indicator,
)

DEFAULT_LIMIT = 100
MAX_LIMIT = 1_000


@dataclass(frozen=True, slots=True)
class CVECorrelationBackfillResult:
    mode: str
    limit: int
    after_id: int
    scanned: int
    eligible: int
    invalid_skipped: int
    first_scanned_id: int | None
    last_scanned_id: int | None
    next_after_id: int | None
    has_more: bool
    events_would_create: int
    indicator_links_would_create: int
    article_links_would_create: int
    events_created: int
    indicator_links_created: int
    article_links_created: int


@dataclass(frozen=True, slots=True)
class _BackfillPlan:
    indicator_ids: tuple[int, ...]
    scanned: int
    invalid_skipped: int
    first_scanned_id: int | None
    last_scanned_id: int | None
    next_after_id: int | None
    has_more: bool
    events_would_create: int
    indicator_links_would_create: int
    article_links_would_create: int


def backfill_cve_correlations(
    session: Session,
    *,
    apply: bool,
    limit: int = DEFAULT_LIMIT,
    after_id: int = 0,
    as_of: datetime,
) -> CVECorrelationBackfillResult:
    """Forecast or apply one bounded page without owning the caller's transaction."""

    correlated_at = _aware_utc(as_of)
    _validate_bounds(limit=limit, after_id=after_id)
    plan = _build_plan(session, limit=limit, after_id=after_id)

    events_created = 0
    indicator_links_created = 0
    article_links_created = 0
    if apply:
        for indicator_id in plan.indicator_ids:
            result = correlate_cve_indicator(session, indicator_id, as_of=correlated_at)
            events_created += int(result.event_created)
            indicator_links_created += int(result.indicator_link_created)
            article_links_created += result.article_links_created
        session.flush()

    return CVECorrelationBackfillResult(
        mode="apply" if apply else "dry-run",
        limit=limit,
        after_id=after_id,
        scanned=plan.scanned,
        eligible=len(plan.indicator_ids),
        invalid_skipped=plan.invalid_skipped,
        first_scanned_id=plan.first_scanned_id,
        last_scanned_id=plan.last_scanned_id,
        next_after_id=plan.next_after_id,
        has_more=plan.has_more,
        events_would_create=plan.events_would_create,
        indicator_links_would_create=plan.indicator_links_would_create,
        article_links_would_create=plan.article_links_would_create,
        events_created=events_created,
        indicator_links_created=indicator_links_created,
        article_links_created=article_links_created,
    )


def _build_plan(session: Session, *, limit: int, after_id: int) -> _BackfillPlan:
    rows = list(
        session.execute(
            select(Indicator.id, Indicator.indicator_value)
            .where(Indicator.indicator_type == IOCType.CVE, Indicator.id > after_id)
            .order_by(Indicator.id)
            .limit(limit + 1)
        )
    )
    has_more = len(rows) > limit
    page = rows[:limit]
    valid = tuple((indicator_id, value) for indicator_id, value in page if _is_canonical_cve(value))
    indicator_ids = tuple(indicator_id for indicator_id, _value in valid)
    keys_by_indicator = {indicator_id: f"cve:{value}" for indicator_id, value in valid}
    events_by_key = _load_compatible_events(session, tuple(keys_by_indicator.values()))
    event_ids_by_indicator = {
        indicator_id: events_by_key[key]
        for indicator_id, key in keys_by_indicator.items()
        if key in events_by_key
    }

    article_pairs = (
        set(
            session.execute(
                select(ArticleIndicator.indicator_id, ArticleIndicator.raw_article_id).where(
                    ArticleIndicator.indicator_id.in_(indicator_ids)
                )
            )
        )
        if indicator_ids
        else set()
    )
    event_ids = tuple(event_ids_by_indicator.values())
    existing_indicator_links = (
        set(
            session.execute(
                select(EventIndicator.event_id, EventIndicator.indicator_id).where(
                    EventIndicator.event_id.in_(event_ids)
                )
            )
        )
        if event_ids
        else set()
    )
    existing_article_links = (
        set(
            session.execute(
                select(EventArticle.event_id, EventArticle.article_id).where(
                    EventArticle.event_id.in_(event_ids)
                )
            )
        )
        if event_ids
        else set()
    )

    articles_by_indicator: dict[int, set[int]] = {}
    for indicator_id, article_id in article_pairs:
        articles_by_indicator.setdefault(indicator_id, set()).add(article_id)

    indicator_links_missing = 0
    article_links_missing = 0
    for indicator_id in indicator_ids:
        event_id = event_ids_by_indicator.get(indicator_id)
        if event_id is None or (event_id, indicator_id) not in existing_indicator_links:
            indicator_links_missing += 1
        for article_id in articles_by_indicator.get(indicator_id, set()):
            if event_id is None or (event_id, article_id) not in existing_article_links:
                article_links_missing += 1

    first_id = page[0].id if page else None
    last_id = page[-1].id if page else None
    return _BackfillPlan(
        indicator_ids=indicator_ids,
        scanned=len(page),
        invalid_skipped=len(page) - len(valid),
        first_scanned_id=first_id,
        last_scanned_id=last_id,
        next_after_id=last_id if has_more else None,
        has_more=has_more,
        events_would_create=len(indicator_ids) - len(event_ids_by_indicator),
        indicator_links_would_create=indicator_links_missing,
        article_links_would_create=article_links_missing,
    )


def _load_compatible_events(
    session: Session,
    event_keys: tuple[str, ...],
) -> dict[str, int]:
    if not event_keys:
        return {}
    events: dict[str, int] = {}
    for event_id, event_key, title, rule_name, rule_version in session.execute(
        select(
            CorrelatedEvent.id,
            CorrelatedEvent.event_key,
            CorrelatedEvent.title,
            CorrelatedEvent.rule_name,
            CorrelatedEvent.rule_version,
        ).where(CorrelatedEvent.event_key.in_(event_keys))
    ):
        cve = event_key.removeprefix("cve:")
        if (
            title != f"{cve} vulnerability"
            or rule_name != RULE_NAME
            or rule_version != RULE_VERSION
        ):
            raise CorrelationInvariantError(
                f"event {event_key!r} has incompatible exact-CVE rule metadata"
            )
        events[event_key] = event_id
    return events


def _is_canonical_cve(value: str) -> bool:
    validation = validate_indicator(IOCType.CVE, value)
    return validation.status is ValidationStatus.VALID and validation.normalized_value == value


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("as_of must be a timezone-aware datetime")
    return value.astimezone(UTC)


def _validate_bounds(*, limit: int, after_id: int) -> None:
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    if after_id < 0:
        raise ValueError("after_id must be non-negative")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Forecast changes (default).")
    mode.add_argument("--apply", action="store_true", help="Commit one bounded page.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--after-id", type=int, default=0)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: sessionmaker[Session] = SessionLocal,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        with session_factory() as session:
            result = backfill_cve_correlations(
                session,
                apply=args.apply,
                limit=args.limit,
                after_id=args.after_id,
                as_of=clock(),
            )
            if args.apply:
                session.commit()
            else:
                session.rollback()
    except Exception as exc:
        stderr.write(f"CVE correlation backfill aborted: {type(exc).__name__}: {exc}\n")
        return 2

    stdout.write(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CVECorrelationBackfillResult",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "backfill_cve_correlations",
    "build_parser",
    "main",
]

"""Bounded dry-run/apply backfill for exact-CVE event scores."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TextIO

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.phase6b import CorrelatedEvent, ScoreHistory
from app.scoring.models import ScoringInputError
from app.services.cve_correlation import RULE_NAME
from app.services.event_scoring import (
    AmbiguousEventRelationshipsError,
    EventNotFoundError,
    InconsistentEventRelationshipsError,
    InvalidEventKeyError,
    InvalidStoredScoreEvidenceError,
    MissingMatchingCVERelationshipError,
    PersistedEventScore,
    UnsupportedEventError,
    calculate_and_persist_event_score,
)

DEFAULT_LIMIT = 100
MAX_LIMIT = 1_000

_MALFORMED_ERRORS = (
    EventNotFoundError,
    InvalidEventKeyError,
    MissingMatchingCVERelationshipError,
    AmbiguousEventRelationshipsError,
    InconsistentEventRelationshipsError,
)
_UNSCORABLE_ERRORS = (InvalidStoredScoreEvidenceError, ScoringInputError)


@dataclass(frozen=True, slots=True)
class EventScoreBackfillItem:
    event_id: int
    event_key: str
    outcome: str
    score: str | None = None
    severity: str | None = None
    formula_version: str | None = None
    evidence_hash: str | None = None


@dataclass(frozen=True, slots=True)
class EventScoreBackfillResult:
    mode: str
    limit: int
    after_id: int
    scanned: int
    scoreable: int
    unsupported: int
    malformed: int
    unscorable: int
    first_scanned_id: int | None
    last_scanned_id: int | None
    next_after_id: int | None
    has_more: bool
    scores_would_create: int
    scores_would_reuse: int
    scores_created: int
    scores_reused: int
    items: tuple[EventScoreBackfillItem, ...]


@dataclass(frozen=True, slots=True)
class _ScoreOutcome:
    created: bool
    score: str
    severity: str
    formula_version: str
    evidence_hash: str


def backfill_event_scores(
    session: Session,
    *,
    apply: bool,
    limit: int = DEFAULT_LIMIT,
    after_id: int = 0,
    as_of: datetime,
) -> EventScoreBackfillResult:
    """Forecast or apply one atomic caller-owned page of exact-CVE event scores."""

    calculation_time = _aware_utc(as_of)
    _validate_bounds(limit=limit, after_id=after_id)
    page, has_more = _load_page(session, limit=limit, after_id=after_id)

    items: list[EventScoreBackfillItem] = []
    unsupported = 0
    malformed = 0
    unscorable = 0
    would_create = 0
    would_reuse = 0
    created = 0
    reused = 0

    for event_id, event_key in page:
        reusable_as_of = _latest_calculated_at(session, event_id)
        try:
            persisted = _run_one(
                session,
                event_id=event_id,
                as_of=reusable_as_of or calculation_time,
                apply=apply,
            )
        except UnsupportedEventError:
            unsupported += 1
            items.append(EventScoreBackfillItem(event_id, event_key, "unsupported"))
        except _MALFORMED_ERRORS:
            malformed += 1
            items.append(EventScoreBackfillItem(event_id, event_key, "malformed"))
        except _UNSCORABLE_ERRORS:
            unscorable += 1
            items.append(EventScoreBackfillItem(event_id, event_key, "unscorable"))
        else:
            is_new = persisted.created
            would_create += int(is_new)
            would_reuse += int(not is_new)
            if apply:
                created += int(is_new)
                reused += int(not is_new)
            items.append(_score_item(event_id, event_key, persisted, apply=apply))

    first_id = page[0][0] if page else None
    last_id = page[-1][0] if page else None
    return EventScoreBackfillResult(
        mode="apply" if apply else "dry-run",
        limit=limit,
        after_id=after_id,
        scanned=len(page),
        scoreable=would_create + would_reuse,
        unsupported=unsupported,
        malformed=malformed,
        unscorable=unscorable,
        first_scanned_id=first_id,
        last_scanned_id=last_id,
        next_after_id=last_id if has_more else None,
        has_more=has_more,
        scores_would_create=would_create,
        scores_would_reuse=would_reuse,
        scores_created=created,
        scores_reused=reused,
        items=tuple(items),
    )


def _load_page(
    session: Session,
    *,
    limit: int,
    after_id: int,
) -> tuple[list[tuple[int, str]], bool]:
    rows = list(
        session.execute(
            select(CorrelatedEvent.id, CorrelatedEvent.event_key)
            .where(
                CorrelatedEvent.id > after_id,
                or_(
                    CorrelatedEvent.event_key.like("cve:%"),
                    CorrelatedEvent.rule_name == RULE_NAME,
                ),
            )
            .order_by(CorrelatedEvent.id)
            .limit(limit + 1)
        )
    )
    return [(row.id, row.event_key) for row in rows[:limit]], len(rows) > limit


def _run_one(
    session: Session,
    *,
    event_id: int,
    as_of: datetime,
    apply: bool,
) -> _ScoreOutcome:
    if apply:
        persisted = calculate_and_persist_event_score(session, event_id, as_of=as_of)
        return _capture_score(persisted)

    savepoint = session.begin_nested()
    try:
        persisted = calculate_and_persist_event_score(session, event_id, as_of=as_of)
        return _capture_score(persisted)
    finally:
        if savepoint.is_active:
            savepoint.rollback()


def _score_item(
    event_id: int,
    event_key: str,
    persisted: _ScoreOutcome,
    *,
    apply: bool,
) -> EventScoreBackfillItem:
    if apply:
        outcome = "created" if persisted.created else "reused"
    else:
        outcome = "would_create" if persisted.created else "would_reuse"
    return EventScoreBackfillItem(
        event_id=event_id,
        event_key=event_key,
        outcome=outcome,
        score=persisted.score,
        severity=persisted.severity,
        formula_version=persisted.formula_version,
        evidence_hash=persisted.evidence_hash,
    )


def _capture_score(persisted: PersistedEventScore) -> _ScoreOutcome:
    history = persisted.score_history
    return _ScoreOutcome(
        created=persisted.created,
        score=format(history.score, "f"),
        severity=history.severity,
        formula_version=history.formula_version,
        evidence_hash=persisted.evidence_hash,
    )


def _latest_calculated_at(session: Session, event_id: int) -> datetime | None:
    value = session.scalar(
        select(ScoreHistory.calculated_at)
        .where(
            ScoreHistory.target_kind == "event",
            ScoreHistory.event_id == event_id,
            ScoreHistory.indicator_id.is_(None),
        )
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(1)
    )
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


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
    mode.add_argument("--dry-run", action="store_true", help="Forecast scores (default).")
    mode.add_argument("--apply", action="store_true", help="Commit one bounded page.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--after-id", type=int, default=0)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: Callable[[], Session] = SessionLocal,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        with session_factory() as session:
            try:
                result = backfill_event_scores(
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
            except Exception:
                session.rollback()
                raise
    except Exception as exc:
        stderr.write(f"Event scoring backfill aborted: {type(exc).__name__}: {exc}\n")
        return 2

    stdout.write(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "EventScoreBackfillItem",
    "EventScoreBackfillResult",
    "backfill_event_scores",
    "build_parser",
    "main",
]

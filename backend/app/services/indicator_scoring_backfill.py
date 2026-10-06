"""Bounded dry-run/apply backfill for canonical indicator scores."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.ingestion.models import Indicator
from app.models.phase6b import ScoreHistory
from app.scoring.models import ScoringInputError
from app.services.indicator_scoring import (
    IndicatorNotFoundError,
    PersistedIndicatorScore,
    calculate_and_persist_indicator_score,
)

DEFAULT_LIMIT = 100
MAX_LIMIT = 1_000


@dataclass(frozen=True, slots=True)
class IndicatorScoreBackfillItem:
    indicator_id: int
    indicator_type: str
    indicator_value: str
    outcome: str
    score: str | None = None
    severity: str | None = None
    formula_version: str | None = None
    evidence_hash: str | None = None


@dataclass(frozen=True, slots=True)
class IndicatorScoreBackfillResult:
    mode: str
    limit: int
    after_id: int
    scanned: int
    scoreable: int
    missing: int
    unscorable: int
    first_scanned_id: int | None
    last_scanned_id: int | None
    next_after_id: int | None
    has_more: bool
    scores_would_create: int
    scores_would_reuse: int
    scores_created: int
    scores_reused: int
    items: tuple[IndicatorScoreBackfillItem, ...]


@dataclass(frozen=True, slots=True)
class _ScoreOutcome:
    created: bool
    score: str
    severity: str
    formula_version: str
    evidence_hash: str


def backfill_indicator_scores(
    session: Session,
    *,
    apply: bool,
    limit: int = DEFAULT_LIMIT,
    after_id: int = 0,
    as_of: datetime,
) -> IndicatorScoreBackfillResult:
    """Forecast or apply one atomic caller-owned page of indicator scores."""

    calculation_time = _aware_utc(as_of)
    _validate_bounds(limit=limit, after_id=after_id)
    page, has_more = _load_page(session, limit=limit, after_id=after_id)

    items: list[IndicatorScoreBackfillItem] = []
    missing = 0
    unscorable = 0
    would_create = 0
    would_reuse = 0
    created = 0
    reused = 0

    for indicator_id, indicator_type, indicator_value in page:
        reusable_as_of = _latest_calculated_at(session, indicator_id)
        try:
            persisted = _run_one(
                session,
                indicator_id=indicator_id,
                as_of=reusable_as_of or calculation_time,
                apply=apply,
            )
        except IndicatorNotFoundError:
            missing += 1
            items.append(
                IndicatorScoreBackfillItem(
                    indicator_id,
                    indicator_type,
                    indicator_value,
                    "missing",
                )
            )
        except ScoringInputError:
            unscorable += 1
            items.append(
                IndicatorScoreBackfillItem(
                    indicator_id,
                    indicator_type,
                    indicator_value,
                    "unscorable",
                )
            )
        else:
            is_new = persisted.created
            would_create += int(is_new)
            would_reuse += int(not is_new)
            if apply:
                created += int(is_new)
                reused += int(not is_new)
            items.append(
                _score_item(
                    indicator_id,
                    indicator_type,
                    indicator_value,
                    persisted,
                    apply=apply,
                )
            )

    first_id = page[0][0] if page else None
    last_id = page[-1][0] if page else None
    return IndicatorScoreBackfillResult(
        mode="apply" if apply else "dry-run",
        limit=limit,
        after_id=after_id,
        scanned=len(page),
        scoreable=would_create + would_reuse,
        missing=missing,
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
) -> tuple[list[tuple[int, str, str]], bool]:
    rows = list(
        session.execute(
            select(Indicator.id, Indicator.indicator_type, Indicator.indicator_value)
            .where(Indicator.id > after_id)
            .order_by(Indicator.id)
            .limit(limit + 1)
        )
    )
    page = [(row.id, row.indicator_type.value, row.indicator_value) for row in rows[:limit]]
    return page, len(rows) > limit


def _run_one(
    session: Session,
    *,
    indicator_id: int,
    as_of: datetime,
    apply: bool,
) -> _ScoreOutcome:
    if apply:
        persisted = calculate_and_persist_indicator_score(session, indicator_id, as_of=as_of)
        return _capture_score(persisted)

    savepoint = session.begin_nested()
    try:
        persisted = calculate_and_persist_indicator_score(session, indicator_id, as_of=as_of)
        return _capture_score(persisted)
    finally:
        if savepoint.is_active:
            savepoint.rollback()


def _score_item(
    indicator_id: int,
    indicator_type: str,
    indicator_value: str,
    persisted: _ScoreOutcome,
    *,
    apply: bool,
) -> IndicatorScoreBackfillItem:
    if apply:
        outcome = "created" if persisted.created else "reused"
    else:
        outcome = "would_create" if persisted.created else "would_reuse"
    return IndicatorScoreBackfillItem(
        indicator_id=indicator_id,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        outcome=outcome,
        score=persisted.score,
        severity=persisted.severity,
        formula_version=persisted.formula_version,
        evidence_hash=persisted.evidence_hash,
    )


def _capture_score(persisted: PersistedIndicatorScore) -> _ScoreOutcome:
    history = persisted.score_history
    return _ScoreOutcome(
        created=persisted.created,
        score=format(history.score, "f"),
        severity=history.severity,
        formula_version=history.formula_version,
        evidence_hash=persisted.evidence_hash,
    )


def _latest_calculated_at(session: Session, indicator_id: int) -> datetime | None:
    value = session.scalar(
        select(ScoreHistory.calculated_at)
        .where(
            ScoreHistory.target_kind == "indicator",
            ScoreHistory.indicator_id == indicator_id,
            ScoreHistory.event_id.is_(None),
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
                result = backfill_indicator_scores(
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
        stderr.write(f"Indicator scoring backfill aborted: {type(exc).__name__}: {exc}\n")
        return 2

    stdout.write(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "IndicatorScoreBackfillItem",
    "IndicatorScoreBackfillResult",
    "backfill_indicator_scores",
    "build_parser",
    "main",
]

"""Celery orchestration for bounded canonical indicator scoring."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from app.database.session import SessionLocal
from app.ingestion.enrichment.cache import acquire_task_lock, release_task_lock
from app.services.indicator_scoring_backfill import DEFAULT_LIMIT, backfill_indicator_scores
from app.workers.celery_app import celery_app

TASK_NAME = "app.workers.indicator_scoring_tasks.score_indicator_page_task"
LOCK_NAME = "indicator-scoring-backfill"
LOCK_TTL_SECONDS = 1800


@celery_app.task(name=TASK_NAME)
def score_indicator_page_task(
    limit: int = DEFAULT_LIMIT,
    after_id: int = 0,
    as_of: str | None = None,
) -> dict[str, Any]:
    """Apply one atomic score page and enqueue its successor after commit."""

    logical_as_of = datetime.fromisoformat(as_of) if as_of is not None else datetime.now(UTC)
    lock_client, lock_token = acquire_task_lock(LOCK_NAME, LOCK_TTL_SECONDS)
    if lock_token is None:
        return {
            "status": "skipped",
            "reason": "indicator_scoring_backfill_already_running",
            "limit": limit,
            "after_id": after_id,
        }

    continuation: dict[str, int | str] | None = None
    try:
        with SessionLocal() as session:
            try:
                result = backfill_indicator_scores(
                    session,
                    apply=True,
                    limit=limit,
                    after_id=after_id,
                    as_of=logical_as_of,
                )
                session.commit()
            except Exception:
                session.rollback()
                raise

        if result.has_more and result.next_after_id is not None:
            continuation = {
                "limit": limit,
                "after_id": result.next_after_id,
                "as_of": logical_as_of.isoformat(),
            }
        payload = asdict(result)
    finally:
        release_task_lock(lock_client, LOCK_NAME, lock_token)

    if continuation is not None:
        score_indicator_page_task.apply_async(kwargs=continuation)
    payload["continuation_enqueued"] = continuation is not None
    return payload


__all__ = ["LOCK_NAME", "LOCK_TTL_SECONDS", "TASK_NAME", "score_indicator_page_task"]

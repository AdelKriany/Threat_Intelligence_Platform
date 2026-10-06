"""Durable Celery coordination for the complete ThreatLens intelligence workflow."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, Callable

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import SessionLocal
from app.ingestion.enrichment.cache import acquire_task_lock, release_task_lock
from app.ingestion.enrichment.tasks import enrich_pending_batch
from app.ingestion.scheduler import run_ingestion
from app.models.intelligence_workflow import IntelligenceWorkflowRun
from app.services.cve_correlation_backfill import backfill_cve_correlations
from app.services.event_scoring_backfill import backfill_event_scores
from app.services.indicator_scoring_backfill import backfill_indicator_scores
from app.services.intelligence_workflow import (
    WorkflowPageLimits,
    WorkflowStage,
    WorkflowStart,
    create_or_get_active_workflow,
    get_active_workflow,
    get_workflow_for_update,
    is_active_slot_conflict,
    mark_stage_running,
    mark_workflow_failed,
    record_backfill_page,
    record_enrichment_page,
    record_ingestion_completed,
    record_stage_contention,
    record_stage_skipped_and_advance,
    workflow_payload,
)
from app.workers.celery_app import celery_app
from app.workers.cve_correlation_tasks import LOCK_NAME as CVE_CORRELATION_LOCK_NAME
from app.workers.event_scoring_tasks import LOCK_NAME as EVENT_SCORING_LOCK_NAME
from app.workers.indicator_scoring_tasks import LOCK_NAME as INDICATOR_SCORING_LOCK_NAME

logger = logging.getLogger(__name__)

START_TASK_NAME = "app.workers.intelligence_workflow_tasks.start_intelligence_workflow_task"
ADVANCE_TASK_NAME = "app.workers.intelligence_workflow_tasks.advance_intelligence_workflow_task"
WORKFLOW_LOCK_PREFIX = "intelligence-workflow"
LOCK_TTL_SECONDS = 1800

BackfillCallable = Callable[..., Any]


class WorkflowTaskSuperseded(RuntimeError):
    """A duplicate delivery observed that another page already advanced the run."""


_BACKFILL_STAGES: dict[WorkflowStage, tuple[BackfillCallable, str]] = {
    WorkflowStage.INDICATOR_SCORING: (
        backfill_indicator_scores,
        INDICATOR_SCORING_LOCK_NAME,
    ),
    WorkflowStage.CVE_CORRELATION: (
        backfill_cve_correlations,
        CVE_CORRELATION_LOCK_NAME,
    ),
    WorkflowStage.EVENT_SCORING: (
        backfill_event_scores,
        EVENT_SCORING_LOCK_NAME,
    ),
}


def _logical_as_of(value: str | None) -> datetime:
    parsed = datetime.fromisoformat(value) if value is not None else datetime.now(UTC)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    return parsed


def _aware(value: datetime) -> datetime:
    """SQLite drops timezone metadata; production PostgreSQL preserves it."""

    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _configured_limits() -> WorkflowPageLimits:
    return WorkflowPageLimits(
        enrichment=settings.enrichment_batch_size,
        indicator_scoring=settings.indicator_scoring_page_limit,
        cve_correlation=settings.cve_correlation_page_limit,
        event_scoring=settings.event_scoring_page_limit,
    )


@celery_app.task(name=START_TASK_NAME)
def start_intelligence_workflow_task(as_of: str | None = None) -> dict[str, Any]:
    """Create or recover the single active workflow, then enqueue its current stage."""

    logical_as_of = _logical_as_of(as_of)
    try:
        with SessionLocal() as session:
            try:
                started = create_or_get_active_workflow(
                    session,
                    logical_as_of=logical_as_of,
                    page_limits=_configured_limits(),
                )
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                if not is_active_slot_conflict(exc):
                    raise
                active = get_active_workflow(session)
                if active is None:
                    raise
                started = WorkflowStart(run=active, created=False)
            payload = workflow_payload(started.run)
    except Exception:
        logger.exception("Unable to create or recover an intelligence workflow run")
        raise

    advance_intelligence_workflow_task.apply_async(kwargs={"run_id": started.run.run_id})
    payload["start_status"] = "created" if started.created else "resumed"
    payload["continuation_enqueued"] = True
    return payload


@celery_app.task(name=ADVANCE_TASK_NAME)
def advance_intelligence_workflow_task(run_id: str) -> dict[str, Any]:
    """Execute one durable workflow stage/page and enqueue only after its commit."""

    workflow_lock_name = f"{WORKFLOW_LOCK_PREFIX}:{run_id}"
    lock_client, lock_token = acquire_task_lock(workflow_lock_name, LOCK_TTL_SECONDS)
    if lock_token is None:
        return {
            "run_id": run_id,
            "status": "skipped",
            "reason": "workflow_page_already_running",
            "continuation_enqueued": False,
        }

    continuation = False
    retry_delay = False
    try:
        with SessionLocal() as session:
            run = get_workflow_for_update(session, run_id)
            if run is None:
                return {
                    "run_id": run_id,
                    "status": "missing",
                    "continuation_enqueued": False,
                }
            if run.status in {"completed", "failed"}:
                return {
                    **workflow_payload(run),
                    "continuation_enqueued": False,
                }
            stage = WorkflowStage(run.current_stage)

        if stage is WorkflowStage.INGESTION:
            payload, continuation = _run_ingestion_stage(run_id)
        elif stage is WorkflowStage.ENRICHMENT:
            payload, continuation, retry_delay = _run_enrichment_stage(run_id)
        elif stage in _BACKFILL_STAGES:
            payload, continuation, retry_delay = _run_backfill_stage(run_id, stage)
        else:
            raise ValueError(f"active workflow has unsupported stage: {stage.value}")
    except WorkflowTaskSuperseded:
        with SessionLocal() as session:
            run = get_workflow_for_update(session, run_id)
            if run is None:
                payload = {
                    "run_id": run_id,
                    "status": "missing",
                }
                continuation = False
            else:
                payload = workflow_payload(run)
                continuation = run.active_slot == 1
        retry_delay = False
    except Exception as exc:
        _persist_terminal_failure(run_id, exc)
        raise
    finally:
        release_task_lock(lock_client, workflow_lock_name, lock_token)

    if continuation:
        options: dict[str, Any] = {"kwargs": {"run_id": run_id}}
        if retry_delay:
            options["countdown"] = settings.intelligence_workflow_retry_delay_seconds
        advance_intelligence_workflow_task.apply_async(**options)
    payload["continuation_enqueued"] = continuation
    return payload


def _run_ingestion_stage(run_id: str) -> tuple[dict[str, Any], bool]:
    _mark_running(run_id, WorkflowStage.INGESTION)
    result = run_ingestion(dispatch_enrichment=False)
    with SessionLocal() as session:
        run = _require_current_run(session, run_id, WorkflowStage.INGESTION)
        record_ingestion_completed(run, result)
        session.commit()
        return workflow_payload(run), run.active_slot == 1


def _run_enrichment_stage(run_id: str) -> tuple[dict[str, Any], bool, bool]:
    if not settings.enrichment_enabled:
        with SessionLocal() as session:
            run = _require_current_run(session, run_id, WorkflowStage.ENRICHMENT)
            mark_stage_running(run)
            record_stage_skipped_and_advance(
                run,
                WorkflowStage.ENRICHMENT,
                reason="enrichment_disabled",
            )
            session.commit()
            return workflow_payload(run), run.active_slot == 1, False

    _mark_running(run_id, WorkflowStage.ENRICHMENT)
    with SessionLocal() as session:
        run = _require_current_run(session, run_id, WorkflowStage.ENRICHMENT)
        page_limit = int(run.page_limits[WorkflowStage.ENRICHMENT.value])
    effective_limit = min(page_limit, settings.enrichment_batch_size)
    result = enrich_pending_batch(batch_size=effective_limit, atomic=True)
    with SessionLocal() as session:
        run = _require_current_run(session, run_id, WorkflowStage.ENRICHMENT)
        record_enrichment_page(
            run,
            result,
            page_limit=effective_limit,
        )
        continuation = run.active_slot == 1
        retry_delay = bool(result.get("skipped"))
        session.commit()
        return workflow_payload(run), continuation, retry_delay


def _run_backfill_stage(
    run_id: str,
    stage: WorkflowStage,
) -> tuple[dict[str, Any], bool, bool]:
    backfill, stage_lock_name = _BACKFILL_STAGES[stage]
    lock_client, lock_token = acquire_task_lock(stage_lock_name, LOCK_TTL_SECONDS)
    if lock_token is None:
        with SessionLocal() as session:
            run = _require_current_run(session, run_id, stage)
            record_stage_contention(
                run,
                stage,
                reason="standalone_stage_lock_busy",
            )
            session.commit()
            return workflow_payload(run), True, True

    try:
        with SessionLocal() as session:
            run = _require_current_run(session, run_id, stage)
            mark_stage_running(run)
            page_limit = int(run.page_limits[stage.value])
            result = backfill(
                session,
                apply=True,
                limit=page_limit,
                after_id=run.after_id,
                as_of=_aware(run.logical_as_of),
            )
            payload = asdict(result)
            record_backfill_page(run, stage, payload)
            continuation = run.active_slot == 1
            session.commit()
            return workflow_payload(run), continuation, False
    finally:
        release_task_lock(lock_client, stage_lock_name, lock_token)


def _mark_running(run_id: str, stage: WorkflowStage) -> None:
    with SessionLocal() as session:
        run = _require_current_run(session, run_id, stage)
        mark_stage_running(run)
        session.commit()


def _require_current_run(
    session: Session,
    run_id: str,
    expected_stage: WorkflowStage,
) -> IntelligenceWorkflowRun:
    run = get_workflow_for_update(session, run_id)
    if run is None:
        raise LookupError(f"workflow run not found: {run_id}")
    if run.active_slot != 1 or run.status in {"completed", "failed"}:
        raise WorkflowTaskSuperseded(f"workflow run is not active: {run_id}")
    if run.current_stage != expected_stage.value:
        raise WorkflowTaskSuperseded(
            f"workflow stage changed: expected {expected_stage.value}, got {run.current_stage}"
        )
    return run


def _persist_terminal_failure(run_id: str, error: Exception) -> None:
    try:
        with SessionLocal() as session:
            run = get_workflow_for_update(session, run_id)
            if run is None or run.status in {"completed", "failed"}:
                return
            mark_workflow_failed(run, stage=run.current_stage, error=error)
            session.commit()
    except Exception:
        logger.exception(
            "Unable to persist terminal workflow failure run_id=%s original_error=%s",
            run_id,
            type(error).__name__,
        )


__all__ = [
    "ADVANCE_TASK_NAME",
    "LOCK_TTL_SECONDS",
    "START_TASK_NAME",
    "WORKFLOW_LOCK_PREFIX",
    "advance_intelligence_workflow_task",
    "start_intelligence_workflow_task",
]

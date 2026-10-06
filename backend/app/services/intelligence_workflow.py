"""Durable state transitions for the Phase 10C intelligence workflow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.intelligence_workflow import IntelligenceWorkflowRun

WORKFLOW_VERSION = "v1"
ACTIVE_SLOT_CONSTRAINT = "uq_intelligence_workflow_runs_active_slot"


class WorkflowStage(StrEnum):
    INGESTION = "ingestion"
    ENRICHMENT = "enrichment"
    INDICATOR_SCORING = "indicator_scoring"
    CVE_CORRELATION = "cve_correlation"
    EVENT_SCORING = "event_scoring"
    COMPLETED = "completed"


NEXT_STAGE = {
    WorkflowStage.INGESTION: WorkflowStage.ENRICHMENT,
    WorkflowStage.ENRICHMENT: WorkflowStage.INDICATOR_SCORING,
    WorkflowStage.INDICATOR_SCORING: WorkflowStage.CVE_CORRELATION,
    WorkflowStage.CVE_CORRELATION: WorkflowStage.EVENT_SCORING,
    WorkflowStage.EVENT_SCORING: WorkflowStage.COMPLETED,
}

BACKFILL_COUNTERS: dict[WorkflowStage, tuple[str, ...]] = {
    WorkflowStage.INDICATOR_SCORING: (
        "scanned",
        "scoreable",
        "missing",
        "unscorable",
        "scores_would_create",
        "scores_would_reuse",
        "scores_created",
        "scores_reused",
    ),
    WorkflowStage.CVE_CORRELATION: (
        "scanned",
        "eligible",
        "invalid_skipped",
        "events_would_create",
        "indicator_links_would_create",
        "article_links_would_create",
        "events_created",
        "indicator_links_created",
        "article_links_created",
    ),
    WorkflowStage.EVENT_SCORING: (
        "scanned",
        "scoreable",
        "unsupported",
        "malformed",
        "unscorable",
        "scores_would_create",
        "scores_would_reuse",
        "scores_created",
        "scores_reused",
    ),
}


@dataclass(frozen=True, slots=True)
class WorkflowPageLimits:
    enrichment: int
    indicator_scoring: int
    cve_correlation: int
    event_scoring: int

    def __post_init__(self) -> None:
        if any(value <= 0 for value in self.as_dict().values()):
            raise ValueError("workflow page limits must be positive")

    def as_dict(self) -> dict[str, int]:
        return {
            WorkflowStage.ENRICHMENT.value: self.enrichment,
            WorkflowStage.INDICATOR_SCORING.value: self.indicator_scoring,
            WorkflowStage.CVE_CORRELATION.value: self.cve_correlation,
            WorkflowStage.EVENT_SCORING.value: self.event_scoring,
        }


@dataclass(frozen=True, slots=True)
class WorkflowStart:
    run: IntelligenceWorkflowRun
    created: bool


def get_active_workflow(
    session: Session, *, for_update: bool = False
) -> IntelligenceWorkflowRun | None:
    statement = select(IntelligenceWorkflowRun).where(IntelligenceWorkflowRun.active_slot == 1)
    if for_update:
        statement = statement.with_for_update()
    return session.scalar(statement)


def get_workflow_for_update(session: Session, run_id: str) -> IntelligenceWorkflowRun | None:
    return session.scalar(
        select(IntelligenceWorkflowRun)
        .where(IntelligenceWorkflowRun.run_id == run_id)
        .with_for_update()
    )


def create_or_get_active_workflow(
    session: Session,
    *,
    logical_as_of: datetime,
    page_limits: WorkflowPageLimits,
) -> WorkflowStart:
    active = get_active_workflow(session, for_update=True)
    if active is not None:
        return WorkflowStart(run=active, created=False)

    now = datetime.now(UTC)
    run = IntelligenceWorkflowRun(
        run_id=str(uuid4()),
        workflow_version=WORKFLOW_VERSION,
        status="queued",
        current_stage=WorkflowStage.INGESTION.value,
        stage_status="queued",
        after_id=0,
        active_slot=1,
        logical_as_of=logical_as_of,
        page_limits=page_limits.as_dict(),
        stage_outcomes={},
        created_at=now,
        updated_at=now,
    )
    session.add(run)
    session.flush()
    return WorkflowStart(run=run, created=True)


def is_active_slot_conflict(exc: IntegrityError) -> bool:
    """Recognize only the active-run uniqueness conflict; never mask other integrity errors."""

    diagnostic = getattr(exc.orig, "diag", None)
    if getattr(diagnostic, "constraint_name", None) == ACTIVE_SLOT_CONSTRAINT:
        return True
    message = str(exc.orig)
    return (
        ACTIVE_SLOT_CONSTRAINT in message
        or "UNIQUE constraint failed: intelligence_workflow_runs.active_slot" in message
    )


def mark_stage_running(run: IntelligenceWorkflowRun) -> None:
    now = datetime.now(UTC)
    run.status = "running"
    run.stage_status = "running"
    run.started_at = run.started_at or now
    run.updated_at = now


def record_ingestion_completed(
    run: IntelligenceWorkflowRun,
    result: dict[str, int],
) -> None:
    outcomes = dict(run.stage_outcomes)
    outcomes[WorkflowStage.INGESTION.value] = {
        "status": "completed",
        "pages_completed": 1,
        "degraded": result.get("errors", 0) > 0,
        "result": dict(result),
    }
    outcomes["ioc_extraction"] = {
        "status": "completed",
        "indicators_extracted": int(result.get("iocs_extracted", 0)),
        "note": "IOC extraction and indicator persistence use the existing ingestion path.",
    }
    run.stage_outcomes = outcomes
    _advance(run, WorkflowStage.INGESTION)


def record_stage_skipped_and_advance(
    run: IntelligenceWorkflowRun,
    stage: WorkflowStage,
    *,
    reason: str,
) -> None:
    outcomes = dict(run.stage_outcomes)
    outcomes[stage.value] = {
        "status": "skipped",
        "pages_completed": 0,
        "reason": reason,
    }
    run.stage_outcomes = outcomes
    _advance(run, stage)


def record_stage_contention(
    run: IntelligenceWorkflowRun,
    stage: WorkflowStage,
    *,
    reason: str,
) -> None:
    """Record a retryable skip without advancing beyond the blocked stage."""

    outcomes = dict(run.stage_outcomes)
    previous = dict(outcomes.get(stage.value, {}))
    previous.update(
        {
            "status": "skipped",
            "skipped_attempts": int(previous.get("skipped_attempts", 0)) + 1,
            "reason": reason,
        }
    )
    outcomes[stage.value] = previous
    run.stage_outcomes = outcomes
    run.status = "running"
    run.stage_status = "skipped"
    run.updated_at = datetime.now(UTC)


def record_enrichment_page(
    run: IntelligenceWorkflowRun,
    result: dict[str, int],
    *,
    page_limit: int,
) -> bool:
    """Record one pending-enrichment batch and return whether the stage needs another page."""

    outcomes = dict(run.stage_outcomes)
    previous = dict(outcomes.get(WorkflowStage.ENRICHMENT.value, {}))
    if result.get("skipped"):
        previous["status"] = "skipped"
        previous["skipped_attempts"] = int(previous.get("skipped_attempts", 0)) + 1
        previous["reason"] = "enrichment_batch_lock_busy"
        outcomes[WorkflowStage.ENRICHMENT.value] = previous
        run.stage_outcomes = outcomes
        run.stage_status = "skipped"
        run.updated_at = datetime.now(UTC)
        return True

    totals = dict(previous.get("totals", {}))
    totals["indicators"] = int(totals.get("indicators", 0)) + int(result.get("indicators", 0))
    totals["results"] = int(totals.get("results", 0)) + int(result.get("results", 0))
    pages_completed = int(previous.get("pages_completed", 0)) + 1
    has_more = int(result.get("indicators", 0)) >= page_limit
    outcomes[WorkflowStage.ENRICHMENT.value] = {
        **previous,
        "status": "queued" if has_more else "completed",
        "pages_completed": pages_completed,
        "totals": totals,
        "last_page": dict(result),
    }
    run.stage_outcomes = outcomes
    run.updated_at = datetime.now(UTC)
    if has_more:
        run.stage_status = "queued"
        return True
    _advance(run, WorkflowStage.ENRICHMENT)
    return False


def record_backfill_page(
    run: IntelligenceWorkflowRun,
    stage: WorkflowStage,
    payload: dict[str, Any],
) -> bool:
    """Persist aggregate page telemetry and advance only after the final bounded page."""

    if stage not in BACKFILL_COUNTERS:
        raise ValueError(f"unsupported workflow backfill stage: {stage}")
    outcomes = dict(run.stage_outcomes)
    previous = dict(outcomes.get(stage.value, {}))
    totals = dict(previous.get("totals", {}))
    for field in BACKFILL_COUNTERS[stage]:
        totals[field] = int(totals.get(field, 0)) + int(payload.get(field, 0))

    has_more = bool(payload["has_more"])
    next_after_id = payload.get("next_after_id")
    last_page = {key: value for key, value in payload.items() if key != "items"}
    outcomes[stage.value] = {
        **previous,
        "status": "queued" if has_more else "completed",
        "pages_completed": int(previous.get("pages_completed", 0)) + 1,
        "totals": totals,
        "last_page": last_page,
    }
    run.stage_outcomes = outcomes
    run.updated_at = datetime.now(UTC)
    if has_more:
        if not isinstance(next_after_id, int) or next_after_id <= run.after_id:
            raise ValueError("workflow backfill returned a non-advancing cursor")
        run.after_id = next_after_id
        run.stage_status = "queued"
        return True
    _advance(run, stage)
    return False


def mark_workflow_failed(
    run: IntelligenceWorkflowRun,
    *,
    stage: str,
    error: Exception,
) -> None:
    outcomes = dict(run.stage_outcomes)
    previous = dict(outcomes.get(stage, {}))
    previous.update(
        {
            "status": "failed",
            "error_type": type(error).__name__,
            "error_message": (str(error) or "workflow stage failed")[:1000],
        }
    )
    outcomes[stage] = previous
    now = datetime.now(UTC)
    run.stage_outcomes = outcomes
    run.status = "failed"
    run.stage_status = "failed"
    run.active_slot = None
    run.error_type = type(error).__name__[:255]
    run.error_message = (str(error) or "workflow stage failed")[:1000]
    run.completed_at = now
    run.updated_at = now


def workflow_payload(run: IntelligenceWorkflowRun) -> dict[str, Any]:
    logical_as_of = (
        run.logical_as_of
        if run.logical_as_of.tzinfo is not None
        else run.logical_as_of.replace(tzinfo=UTC)
    )
    return {
        "run_id": run.run_id,
        "workflow_version": run.workflow_version,
        "status": run.status,
        "current_stage": run.current_stage,
        "stage_status": run.stage_status,
        "after_id": run.after_id,
        "logical_as_of": logical_as_of.isoformat(),
        "page_limits": dict(run.page_limits),
        "stage_outcomes": dict(run.stage_outcomes),
        "error_type": run.error_type,
        "error_message": run.error_message,
    }


def _advance(run: IntelligenceWorkflowRun, completed_stage: WorkflowStage) -> None:
    next_stage = NEXT_STAGE[completed_stage]
    now = datetime.now(UTC)
    run.after_id = 0
    run.current_stage = next_stage.value
    run.updated_at = now
    if next_stage is WorkflowStage.COMPLETED:
        run.status = "completed"
        run.stage_status = "completed"
        run.active_slot = None
        run.completed_at = now
    else:
        run.status = "running"
        run.stage_status = "queued"


__all__ = [
    "ACTIVE_SLOT_CONSTRAINT",
    "BACKFILL_COUNTERS",
    "WORKFLOW_VERSION",
    "WorkflowPageLimits",
    "WorkflowStage",
    "WorkflowStart",
    "create_or_get_active_workflow",
    "get_active_workflow",
    "get_workflow_for_update",
    "is_active_slot_conflict",
    "mark_stage_running",
    "mark_workflow_failed",
    "record_backfill_page",
    "record_enrichment_page",
    "record_ingestion_completed",
    "record_stage_contention",
    "record_stage_skipped_and_advance",
    "workflow_payload",
]

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.database.base import Base
from app.ingestion.feed_manager import FeedManager
from app.ingestion.models import Indicator, IOCType, NormalizedArticle
from app.models.intelligence_workflow import IntelligenceWorkflowRun
from app.models.phase6b import CorrelatedEvent, ScoreHistory
from app.services.indicator_scoring_backfill import (
    IndicatorScoreBackfillItem,
    IndicatorScoreBackfillResult,
)
from app.services.intelligence_workflow import WorkflowPageLimits, WorkflowStage
from app.workers import intelligence_workflow_tasks
from app.workers.celery_app import celery_app, configure_beat_schedule

NOW = datetime(2026, 10, 7, 16, tzinfo=UTC)


@pytest.fixture()
def workflow_factory() -> Generator[sessionmaker[Session], None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _allow_locks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        intelligence_workflow_tasks,
        "acquire_task_lock",
        lambda name, ttl: (object(), f"token:{name}"),
    )
    monkeypatch.setattr(
        intelligence_workflow_tasks,
        "release_task_lock",
        lambda *args: None,
    )


def _capture_continuations(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    queued: list[dict[str, Any]] = []
    monkeypatch.setattr(
        intelligence_workflow_tasks.advance_intelligence_workflow_task,
        "apply_async",
        lambda **options: queued.append(options),
    )
    return queued


def _seed_run(
    factory: sessionmaker[Session],
    *,
    stage: WorkflowStage,
    after_id: int = 0,
) -> str:
    run = IntelligenceWorkflowRun(
        run_id=f"00000000-0000-0000-0000-{stage.value[:12]:0<12}",
        workflow_version="v1",
        status="running",
        current_stage=stage.value,
        stage_status="queued",
        after_id=after_id,
        active_slot=1,
        logical_as_of=NOW,
        page_limits=WorkflowPageLimits(10, 10, 10, 10).as_dict(),
        stage_outcomes={},
    )
    with factory() as session:
        session.add(run)
        session.commit()
    return run.run_id


def _indicator_result(*, after_id: int, has_more: bool) -> IndicatorScoreBackfillResult:
    return IndicatorScoreBackfillResult(
        mode="apply",
        limit=10,
        after_id=after_id,
        scanned=1,
        scoreable=1,
        missing=0,
        unscorable=0,
        first_scanned_id=after_id + 1,
        last_scanned_id=after_id + 1,
        next_after_id=after_id + 1 if has_more else None,
        has_more=has_more,
        scores_would_create=1,
        scores_would_reuse=0,
        scores_created=1,
        scores_reused=0,
        items=(
            IndicatorScoreBackfillItem(
                after_id + 1,
                "cve",
                "CVE-2026-10001",
                "created",
                score="10.00",
            ),
        ),
    )


def test_start_creates_one_run_then_recovers_the_same_active_run(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    queued = _capture_continuations(monkeypatch)

    created = intelligence_workflow_tasks.start_intelligence_workflow_task.run(
        as_of=NOW.isoformat()
    )
    resumed = intelligence_workflow_tasks.start_intelligence_workflow_task.run(
        as_of=(NOW.replace(hour=17)).isoformat()
    )

    assert created["start_status"] == "created"
    assert resumed["start_status"] == "resumed"
    assert resumed["run_id"] == created["run_id"]
    assert resumed["logical_as_of"] == created["logical_as_of"]
    assert len(queued) == 2
    with workflow_factory() as session:
        assert session.scalar(select(func.count(IntelligenceWorkflowRun.run_id))) == 1


def test_invalid_start_timestamp_does_not_touch_database_or_broker(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    queued = _capture_continuations(monkeypatch)

    with pytest.raises(ValueError, match="timezone-aware"):
        intelligence_workflow_tasks.start_intelligence_workflow_task.run(
            as_of="2026-10-07T16:00:00"
        )

    assert queued == []
    with workflow_factory() as session:
        assert session.scalar(select(func.count(IntelligenceWorkflowRun.run_id))) == 0


def test_backfill_cursor_is_durable_and_advances_only_after_final_page(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    _allow_locks(monkeypatch)
    queued = _capture_continuations(monkeypatch)
    run_id = _seed_run(workflow_factory, stage=WorkflowStage.INDICATOR_SCORING)
    observed_after_ids: list[int] = []

    def backfill(session: Session, **kwargs: Any) -> IndicatorScoreBackfillResult:
        observed_after_ids.append(kwargs["after_id"])
        return _indicator_result(
            after_id=kwargs["after_id"],
            has_more=len(observed_after_ids) == 1,
        )

    monkeypatch.setitem(
        intelligence_workflow_tasks._BACKFILL_STAGES,
        WorkflowStage.INDICATOR_SCORING,
        (backfill, "indicator-scoring-backfill"),
    )

    first = intelligence_workflow_tasks.advance_intelligence_workflow_task.run(run_id)
    with workflow_factory() as session:
        persisted = session.get(IntelligenceWorkflowRun, run_id)
        assert persisted is not None
        assert persisted.current_stage == WorkflowStage.INDICATOR_SCORING.value
        assert persisted.after_id == 1

    second = intelligence_workflow_tasks.advance_intelligence_workflow_task.run(run_id)

    assert first["continuation_enqueued"] is True
    assert second["continuation_enqueued"] is True
    assert observed_after_ids == [0, 1]
    assert len(queued) == 2
    with workflow_factory() as session:
        persisted = session.get(IntelligenceWorkflowRun, run_id)
        assert persisted is not None
        assert persisted.current_stage == WorkflowStage.CVE_CORRELATION.value
        assert persisted.after_id == 0
        outcome = persisted.stage_outcomes[WorkflowStage.INDICATOR_SCORING.value]
        assert outcome["pages_completed"] == 2
        assert outcome["totals"]["scores_created"] == 2


def test_failed_page_rolls_back_domain_work_and_records_terminal_failure(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    _allow_locks(monkeypatch)
    _capture_continuations(monkeypatch)
    run_id = _seed_run(workflow_factory, stage=WorkflowStage.INDICATOR_SCORING)

    def fail(session: Session, **kwargs: Any) -> IndicatorScoreBackfillResult:
        session.add(
            IntelligenceWorkflowRun(
                run_id="11111111-1111-1111-1111-111111111111",
                workflow_version="v1",
                status="completed",
                current_stage="completed",
                stage_status="completed",
                after_id=0,
                active_slot=None,
                logical_as_of=NOW,
                page_limits=WorkflowPageLimits(1, 1, 1, 1).as_dict(),
                stage_outcomes={},
            )
        )
        raise RuntimeError("indicator page failed")

    monkeypatch.setitem(
        intelligence_workflow_tasks._BACKFILL_STAGES,
        WorkflowStage.INDICATOR_SCORING,
        (fail, "indicator-scoring-backfill"),
    )

    with pytest.raises(RuntimeError, match="indicator page failed"):
        intelligence_workflow_tasks.advance_intelligence_workflow_task.run(run_id)

    with workflow_factory() as session:
        run = session.get(IntelligenceWorkflowRun, run_id)
        assert run is not None
        assert run.status == "failed"
        assert run.stage_status == "failed"
        assert run.active_slot is None
        assert run.error_type == "RuntimeError"
        assert run.error_message == "indicator page failed"
        assert (
            session.get(
                IntelligenceWorkflowRun,
                "11111111-1111-1111-1111-111111111111",
            )
            is None
        )


def test_stage_lock_contention_is_recorded_and_retried_with_delay(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    monkeypatch.setattr(
        intelligence_workflow_tasks,
        "acquire_task_lock",
        lambda name, ttl: (
            (object(), "workflow-token")
            if name.startswith(intelligence_workflow_tasks.WORKFLOW_LOCK_PREFIX)
            else (object(), None)
        ),
    )
    monkeypatch.setattr(intelligence_workflow_tasks, "release_task_lock", lambda *args: None)
    queued = _capture_continuations(monkeypatch)
    run_id = _seed_run(workflow_factory, stage=WorkflowStage.INDICATOR_SCORING)

    payload = intelligence_workflow_tasks.advance_intelligence_workflow_task.run(run_id)

    assert payload["stage_status"] == "skipped"
    assert payload["continuation_enqueued"] is True
    assert queued == [
        {
            "kwargs": {"run_id": run_id},
            "countdown": settings.intelligence_workflow_retry_delay_seconds,
        }
    ]
    with workflow_factory() as session:
        run = session.get(IntelligenceWorkflowRun, run_id)
        assert run is not None
        assert run.status == "running"
        assert run.current_stage == WorkflowStage.INDICATOR_SCORING.value
        outcome = run.stage_outcomes[WorkflowStage.INDICATOR_SCORING.value]
        assert outcome["reason"] == "standalone_stage_lock_busy"
        assert outcome["skipped_attempts"] == 1


def test_enrichment_stage_uses_the_existing_batch_as_one_atomic_page(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    monkeypatch.setattr(settings, "enrichment_enabled", True)
    monkeypatch.setattr(settings, "enrichment_batch_size", 10)
    _allow_locks(monkeypatch)
    queued = _capture_continuations(monkeypatch)
    run_id = _seed_run(workflow_factory, stage=WorkflowStage.ENRICHMENT)
    calls: list[dict[str, object]] = []

    def enrich(**kwargs: object) -> dict[str, int]:
        calls.append(kwargs)
        return {"indicators": 0, "results": 0}

    monkeypatch.setattr(intelligence_workflow_tasks, "enrich_pending_batch", enrich)

    payload = intelligence_workflow_tasks.advance_intelligence_workflow_task.run(run_id)

    assert calls == [{"batch_size": 10, "atomic": True}]
    assert payload["current_stage"] == WorkflowStage.INDICATOR_SCORING.value
    assert payload["continuation_enqueued"] is True
    assert queued == [{"kwargs": {"run_id": run_id}}]


def test_real_services_take_ingested_cve_articles_to_one_scored_event(
    workflow_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", workflow_factory)
    monkeypatch.setattr(settings, "enrichment_enabled", False)
    monkeypatch.setattr(settings, "indicator_scoring_page_limit", 100)
    monkeypatch.setattr(settings, "cve_correlation_page_limit", 100)
    monkeypatch.setattr(settings, "event_scoring_page_limit", 100)
    _allow_locks(monkeypatch)
    queued = _capture_continuations(monkeypatch)
    execution_order: list[str] = []

    def ingest(*, dispatch_enrichment: bool) -> dict[str, int]:
        execution_order.append("ingestion")
        assert dispatch_enrichment is False
        manager = FeedManager(
            session_factory=workflow_factory,
            enrichment_dispatch_enabled=False,
        )
        extracted = 0
        for number, source_name in enumerate(("Source A", "Source B"), start=1):
            stored, count = manager.store(
                NormalizedArticle(
                    source_id=f"phase10c-{number}",
                    source_name=source_name,
                    title=f"Phase 10C article {number}",
                    description="CVE-2026-10101 is actively discussed.",
                    url=f"https://example.com/phase10c/{number}",
                    published_at=NOW,
                )
            )
            assert stored is True
            extracted += count
        return {
            "fetched": 2,
            "stored": 2,
            "duplicates": 0,
            "errors": 0,
            "iocs_extracted": extracted,
        }

    monkeypatch.setattr(intelligence_workflow_tasks, "run_ingestion", ingest)
    started = intelligence_workflow_tasks.start_intelligence_workflow_task.run(
        as_of=NOW.isoformat()
    )
    run_id = started["run_id"]

    for _ in range(5):
        intelligence_workflow_tasks.advance_intelligence_workflow_task.run(run_id)

    with workflow_factory() as session:
        run = session.get(IntelligenceWorkflowRun, run_id)
        assert run is not None
        assert run.status == "completed"
        assert run.current_stage == WorkflowStage.COMPLETED.value
        assert run.active_slot is None
        assert run.error_message is None
        assert run.stage_outcomes["ioc_extraction"]["indicators_extracted"] >= 2
        assert run.stage_outcomes[WorkflowStage.ENRICHMENT.value] == {
            "status": "skipped",
            "pages_completed": 0,
            "reason": "enrichment_disabled",
        }
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 1
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id))
                .join(Indicator, Indicator.id == ScoreHistory.indicator_id)
                .where(
                    ScoreHistory.target_kind == "indicator",
                    Indicator.indicator_type == IOCType.CVE,
                )
            )
            == 1
        )
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.target_kind == "event")
            )
            == 1
        )
    assert execution_order == ["ingestion"]
    assert len(queued) == 5


def test_workflow_tasks_are_registered_and_schedule_is_exclusive_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_schedule = celery_app.conf.beat_schedule
    try:
        assert intelligence_workflow_tasks.START_TASK_NAME in celery_app.tasks
        assert intelligence_workflow_tasks.ADVANCE_TASK_NAME in celery_app.tasks
        monkeypatch.setattr(settings, "intelligence_workflow_schedule_enabled", True)
        monkeypatch.setattr(settings, "intelligence_workflow_schedule_interval_minutes", 12)
        monkeypatch.setattr(settings, "indicator_scoring_schedule_enabled", True)
        monkeypatch.setattr(settings, "cve_correlation_schedule_enabled", True)
        monkeypatch.setattr(settings, "event_scoring_schedule_enabled", True)
        monkeypatch.setattr(settings, "enrichment_enabled", True)

        configure_beat_schedule()

        assert celery_app.conf.beat_schedule == {
            "run-intelligence-workflow": {
                "task": intelligence_workflow_tasks.START_TASK_NAME,
                "schedule": 720,
            }
        }
    finally:
        celery_app.conf.beat_schedule = original_schedule

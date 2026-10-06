from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier, Lock

import pytest
from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    create_guarded_test_engine,
    run_guarded_alembic_command,
)
from app.workers import intelligence_workflow_tasks

PARENT_REVISION = "c9f4e2a7b6d1"
TABLE_NAME = "intelligence_workflow_runs"


def test_phase10c_postgres_migration_constraints_downgrade_and_reupgrade(
    phase6b_postgres_database: OwnedDisposablePostgres,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    inspector = inspect(engine)

    assert TABLE_NAME in inspector.get_table_names()
    assert {column["name"] for column in inspector.get_columns(TABLE_NAME)} == {
        "run_id",
        "workflow_version",
        "status",
        "current_stage",
        "stage_status",
        "after_id",
        "active_slot",
        "logical_as_of",
        "page_limits",
        "stage_outcomes",
        "error_type",
        "error_message",
        "created_at",
        "started_at",
        "completed_at",
        "updated_at",
    }
    assert {check["name"] for check in inspector.get_check_constraints(TABLE_NAME)} == {
        "ck_intelligence_workflow_runs_active_slot",
        "ck_intelligence_workflow_runs_after_id_nonnegative",
        "ck_intelligence_workflow_runs_current_stage",
        "ck_intelligence_workflow_runs_stage_status",
        "ck_intelligence_workflow_runs_status",
    }
    unique_constraints = {
        constraint["name"]: constraint
        for constraint in inspector.get_unique_constraints(TABLE_NAME)
    }
    assert unique_constraints["uq_intelligence_workflow_runs_active_slot"]["column_names"] == [
        "active_slot"
    ]

    now = datetime.now(UTC)
    insert_sql = text(
        "INSERT INTO intelligence_workflow_runs "
        "(run_id, workflow_version, status, current_stage, stage_status, after_id, "
        "active_slot, logical_as_of, page_limits, stage_outcomes, created_at, updated_at) "
        "VALUES "
        "(:run_id, 'v1', :status, :stage, :stage_status, :after_id, :active_slot, "
        ":logical_as_of, CAST(:page_limits AS jsonb), CAST(:stage_outcomes AS jsonb), "
        ":created_at, :updated_at)"
    )
    common: dict[str, object] = {
        "run_id": "00000000-0000-0000-0000-000000000001",
        "status": "running",
        "stage": "indicator_scoring",
        "stage_status": "queued",
        "after_id": 0,
        "active_slot": 1,
        "logical_as_of": now,
        "page_limits": json.dumps(
            {
                "enrichment": 100,
                "indicator_scoring": 100,
                "cve_correlation": 100,
                "event_scoring": 100,
            }
        ),
        "stage_outcomes": json.dumps({}),
        "created_at": now,
        "updated_at": now,
    }
    with engine.begin() as connection:
        connection.execute(text(f"DELETE FROM {TABLE_NAME}"))
        connection.execute(insert_sql, common)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            insert_sql,
            {**common, "run_id": "00000000-0000-0000-0000-000000000002"},
        )

    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE intelligence_workflow_runs SET status = 'completed', "
                "current_stage = 'completed', stage_status = 'completed', active_slot = NULL "
                "WHERE run_id = :run_id"
            ),
            {"run_id": common["run_id"]},
        )
        connection.execute(
            insert_sql,
            {**common, "run_id": "00000000-0000-0000-0000-000000000002"},
        )
        connection.execute(
            insert_sql,
            {
                **common,
                "run_id": "00000000-0000-0000-0000-000000000003",
                "status": "completed",
                "stage": "completed",
                "stage_status": "completed",
                "active_slot": None,
            },
        )
        assert connection.scalar(text(f"SELECT count(*) FROM {TABLE_NAME}")) == 3

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            insert_sql,
            {
                **common,
                "run_id": "00000000-0000-0000-0000-000000000004",
                "stage": "not-a-stage",
                "active_slot": None,
            },
        )

    engine.dispose()
    run_guarded_alembic_command(url, command.downgrade, PARENT_REVISION)
    downgraded_engine = create_guarded_test_engine(url)
    try:
        downgraded_tables = set(inspect(downgraded_engine).get_table_names())
        assert TABLE_NAME not in downgraded_tables
        assert {"correlated_events", "score_history"}.issubset(downgraded_tables)
    finally:
        downgraded_engine.dispose()

    run_guarded_alembic_command(url, command.upgrade, "head")
    upgraded_engine = create_guarded_test_engine(url)
    try:
        assert TABLE_NAME in inspect(upgraded_engine).get_table_names()
    finally:
        upgraded_engine.dispose()


def test_concurrent_workflow_starts_reuse_one_active_postgres_run(
    phase6b_postgres_database: OwnedDisposablePostgres,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with engine.begin() as connection:
        connection.execute(text(f"DELETE FROM {TABLE_NAME}"))

    barrier = Barrier(2, timeout=10)
    enqueue_lock = Lock()
    enqueued: list[str] = []
    monkeypatch.setattr(intelligence_workflow_tasks, "SessionLocal", factory)

    def enqueue(**options: object) -> None:
        with enqueue_lock:
            enqueued.append(str(options))

    monkeypatch.setattr(
        intelligence_workflow_tasks.advance_intelligence_workflow_task,
        "apply_async",
        enqueue,
    )

    def start(_: int) -> dict[str, object]:
        barrier.wait()
        return intelligence_workflow_tasks.start_intelligence_workflow_task.run(
            as_of="2026-10-07T16:00:00+00:00"
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(start, (1, 2)))

        assert len({result["run_id"] for result in results}) == 1
        assert sorted(str(result["start_status"]) for result in results) == [
            "created",
            "resumed",
        ]
        assert len(enqueued) == 2
        with factory() as session:
            assert session.scalar(text(f"SELECT count(*) FROM {TABLE_NAME}")) == 1
            assert (
                session.scalar(text(f"SELECT count(*) FROM {TABLE_NAME} WHERE active_slot = 1"))
                == 1
            )
    finally:
        with engine.begin() as connection:
            connection.execute(text(f"DELETE FROM {TABLE_NAME}"))
        engine.dispose()

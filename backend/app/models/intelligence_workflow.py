from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, CheckConstraint, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IntelligenceWorkflowRun(Base):
    """Durable cursor and operational state for one coordinated intelligence run."""

    __tablename__ = "intelligence_workflow_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_intelligence_workflow_runs_status",
        ),
        CheckConstraint(
            "stage_status IN ('queued', 'running', 'completed', 'skipped', 'failed')",
            name="ck_intelligence_workflow_runs_stage_status",
        ),
        CheckConstraint(
            "current_stage IN ('ingestion', 'enrichment', 'indicator_scoring', "
            "'cve_correlation', 'event_scoring', 'completed')",
            name="ck_intelligence_workflow_runs_current_stage",
        ),
        CheckConstraint(
            "active_slot IS NULL OR active_slot = 1",
            name="ck_intelligence_workflow_runs_active_slot",
        ),
        CheckConstraint(
            "after_id >= 0",
            name="ck_intelligence_workflow_runs_after_id_nonnegative",
        ),
        UniqueConstraint(
            "active_slot",
            name="uq_intelligence_workflow_runs_active_slot",
        ),
        Index(
            "ix_intelligence_workflow_runs_status_updated_at",
            "status",
            "updated_at",
        ),
    )

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    current_stage: Mapped[str] = mapped_column(String(32), nullable=False, default="ingestion")
    stage_status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    after_id: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_slot: Mapped[int | None] = mapped_column(Integer, nullable=True, default=1)
    logical_as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    page_limits: Mapped[dict[str, int]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
    )
    stage_outcomes: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=dict,
    )
    error_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


__all__ = ["IntelligenceWorkflowRun"]

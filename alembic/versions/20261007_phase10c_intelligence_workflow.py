"""Add durable Phase 10C intelligence workflow state.

Revision ID: 7d3e1a9c5b20
Revises: c9f4e2a7b6d1
Create Date: 2026-10-07 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "7d3e1a9c5b20"
down_revision = "c9f4e2a7b6d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the single durable workflow-run table used by Phase 10C."""

    op.create_table(
        "intelligence_workflow_runs",
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("workflow_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("current_stage", sa.String(length=32), nullable=False),
        sa.Column("stage_status", sa.String(length=16), nullable=False),
        sa.Column("after_id", sa.Integer(), nullable=False),
        sa.Column("active_slot", sa.Integer(), nullable=True),
        sa.Column("logical_as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "page_limits",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "stage_outcomes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("error_type", sa.String(length=255), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "active_slot IS NULL OR active_slot = 1",
            name="ck_intelligence_workflow_runs_active_slot",
        ),
        sa.CheckConstraint(
            "after_id >= 0",
            name="ck_intelligence_workflow_runs_after_id_nonnegative",
        ),
        sa.CheckConstraint(
            "current_stage IN ('ingestion', 'enrichment', 'indicator_scoring', "
            "'cve_correlation', 'event_scoring', 'completed')",
            name="ck_intelligence_workflow_runs_current_stage",
        ),
        sa.CheckConstraint(
            "stage_status IN ('queued', 'running', 'completed', 'skipped', 'failed')",
            name="ck_intelligence_workflow_runs_stage_status",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_intelligence_workflow_runs_status",
        ),
        sa.PrimaryKeyConstraint("run_id", name="pk_intelligence_workflow_runs"),
        sa.UniqueConstraint(
            "active_slot",
            name="uq_intelligence_workflow_runs_active_slot",
        ),
    )
    op.create_index(
        "ix_intelligence_workflow_runs_status_updated_at",
        "intelligence_workflow_runs",
        ["status", "updated_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove only the Phase 10C workflow state."""

    op.drop_index(
        "ix_intelligence_workflow_runs_status_updated_at",
        table_name="intelligence_workflow_runs",
    )
    op.drop_table("intelligence_workflow_runs")

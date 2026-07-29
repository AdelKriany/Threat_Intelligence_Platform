"""Add Phase 5 error codes and EPSS history.

Revision ID: 61b739ac42e5
Revises: 8c31f1e782b4
Create Date: 2026-07-29 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "61b739ac42e5"
down_revision = "8c31f1e782b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add safe provider error codes and precise daily EPSS observations."""

    op.add_column(
        "indicator_enrichments",
        sa.Column("error_code", sa.String(length=64), nullable=True),
    )
    op.create_table(
        "epss_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("epss", sa.Numeric(precision=8, scale=7), nullable=False),
        sa.Column("percentile", sa.Numeric(precision=8, scale=7), nullable=False),
        sa.Column("model_date", sa.Date(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "indicator_id",
            "model_date",
            name="uq_epss_history_indicator_model_date",
        ),
    )
    op.create_index(
        op.f("ix_epss_history_indicator_id"),
        "epss_history",
        ["indicator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_epss_history_model_date"),
        "epss_history",
        ["model_date"],
        unique=False,
    )


def downgrade() -> None:
    """Remove Phase 5 EPSS history and error codes."""

    op.drop_index(op.f("ix_epss_history_model_date"), table_name="epss_history")
    op.drop_index(op.f("ix_epss_history_indicator_id"), table_name="epss_history")
    op.drop_table("epss_history")
    op.drop_column("indicator_enrichments", "error_code")

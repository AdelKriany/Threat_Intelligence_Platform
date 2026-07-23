"""Create indicator enrichment results.

Revision ID: 8c31f1e782b4
Revises: 2d1d8a617db8
Create Date: 2026-07-24 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "8c31f1e782b4"
down_revision = "2d1d8a617db8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the provider-neutral enrichment table."""

    op.create_table(
        "indicator_enrichments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "normalized_data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "raw_response",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "indicator_id",
            "provider",
            name="uq_indicator_enrichments_indicator_provider",
        ),
    )
    op.create_index(
        op.f("ix_indicator_enrichments_indicator_id"),
        "indicator_enrichments",
        ["indicator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicator_enrichments_provider"),
        "indicator_enrichments",
        ["provider"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicator_enrichments_status"),
        "indicator_enrichments",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicator_enrichments_expires_at"),
        "indicator_enrichments",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove enrichment results without changing indicators."""

    op.drop_index(
        op.f("ix_indicator_enrichments_expires_at"),
        table_name="indicator_enrichments",
    )
    op.drop_index(
        op.f("ix_indicator_enrichments_status"),
        table_name="indicator_enrichments",
    )
    op.drop_index(
        op.f("ix_indicator_enrichments_provider"),
        table_name="indicator_enrichments",
    )
    op.drop_index(
        op.f("ix_indicator_enrichments_indicator_id"),
        table_name="indicator_enrichments",
    )
    op.drop_table("indicator_enrichments")

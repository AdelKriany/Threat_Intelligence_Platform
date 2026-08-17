"""Add explainable score history and exact correlated-event persistence.

Revision ID: c9f4e2a7b6d1
Revises: b74f3c9a21de
Create Date: 2026-08-17 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c9f4e2a7b6d1"
down_revision = "b74f3c9a21de"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create only the Phase 6B event and score-history schema."""

    op.create_table(
        "correlated_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_key", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("rule_name", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_correlated_events"),
        sa.UniqueConstraint("event_key", name="uq_correlated_events_event_key"),
    )
    op.create_index(
        "ix_correlated_events_updated_at",
        "correlated_events",
        ["updated_at"],
        unique=False,
    )

    op.create_table(
        "event_articles",
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("rule_name", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["correlated_events.id"],
            name="fk_event_articles_event_id_correlated_events",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["article_id"],
            ["raw_articles.id"],
            name="fk_event_articles_article_id_raw_articles",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id", "article_id", name="pk_event_articles"),
    )
    op.create_index(
        "ix_event_articles_article_event",
        "event_articles",
        ["article_id", "event_id"],
        unique=False,
    )

    op.create_table(
        "event_indicators",
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("rule_name", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["correlated_events.id"],
            name="fk_event_indicators_event_id_correlated_events",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_event_indicators_indicator_id_indicators",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id", "indicator_id", name="pk_event_indicators"),
    )
    op.create_index(
        "ix_event_indicators_indicator_rule_event",
        "event_indicators",
        ["indicator_id", "rule_name", "rule_version", "event_id"],
        unique=False,
    )

    op.create_table(
        "score_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_kind", sa.String(length=16), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=True),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("formula_version", sa.String(length=64), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "canonical_evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "score >= 0.00 AND score <= 100.00",
            name="ck_score_history_score_range",
        ),
        sa.CheckConstraint(
            "target_kind IN ('indicator', 'event')",
            name="ck_score_history_target_kind",
        ),
        sa.CheckConstraint(
            "severity IN ('none', 'low', 'medium', 'high', 'critical')",
            name="ck_score_history_severity",
        ),
        sa.CheckConstraint(
            "(target_kind = 'indicator' AND indicator_id IS NOT NULL AND event_id IS NULL) "
            "OR (target_kind = 'event' AND event_id IS NOT NULL AND indicator_id IS NULL)",
            name="ck_score_history_exactly_one_target",
        ),
        sa.CheckConstraint(
            "evidence_hash ~ '^[0-9a-f]{64}$'",
            name="ck_score_history_evidence_hash_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name="fk_score_history_indicator_id_indicators",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["correlated_events.id"],
            name="fk_score_history_event_id_correlated_events",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_score_history"),
    )
    op.create_index(
        "uq_score_history_indicator_evidence",
        "score_history",
        ["indicator_id", "formula_version", "evidence_hash"],
        unique=True,
        postgresql_where=sa.text("target_kind = 'indicator'"),
    )
    op.create_index(
        "uq_score_history_event_evidence",
        "score_history",
        ["event_id", "formula_version", "evidence_hash"],
        unique=True,
        postgresql_where=sa.text("target_kind = 'event'"),
    )
    op.create_index(
        "ix_score_history_indicator_calculated_at",
        "score_history",
        ["indicator_id", "calculated_at"],
        unique=False,
        postgresql_where=sa.text("target_kind = 'indicator'"),
    )
    op.create_index(
        "ix_score_history_event_calculated_at",
        "score_history",
        ["event_id", "calculated_at"],
        unique=False,
        postgresql_where=sa.text("target_kind = 'event'"),
    )
    # This supports the known target-kind/score/time ordering. Its final shape must
    # be reviewed against the actual ranked/latest API query before that API ships.
    op.create_index(
        "ix_score_history_ranked",
        "score_history",
        ["target_kind", "score", "calculated_at"],
        unique=False,
    )

    op.create_table(
        "score_components",
        sa.Column("score_history_id", sa.Integer(), nullable=False),
        sa.Column("component_name", sa.String(length=64), nullable=False),
        sa.Column(
            "raw_input",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "normalized_input",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("weight", sa.Numeric(precision=12, scale=6), nullable=False),
        sa.Column("contribution", sa.Numeric(precision=12, scale=6), nullable=False),
        sa.Column(
            "freshness_multiplier",
            sa.Numeric(precision=12, scale=6),
            nullable=False,
        ),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("evidence_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "weight >= 0",
            name="ck_score_components_weight_nonnegative",
        ),
        sa.CheckConstraint(
            "contribution >= 0",
            name="ck_score_components_contribution_nonnegative",
        ),
        sa.CheckConstraint(
            "freshness_multiplier >= 0",
            name="ck_score_components_freshness_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ["score_history_id"],
            ["score_history.id"],
            name="fk_score_components_score_history_id_score_history",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "score_history_id",
            "component_name",
            name="pk_score_components",
        ),
    )


def downgrade() -> None:
    """Drop only Phase 6B objects in reverse dependency order."""

    op.drop_table("score_components")

    op.drop_index("ix_score_history_ranked", table_name="score_history")
    op.drop_index("ix_score_history_event_calculated_at", table_name="score_history")
    op.drop_index("ix_score_history_indicator_calculated_at", table_name="score_history")
    op.drop_index("uq_score_history_event_evidence", table_name="score_history")
    op.drop_index("uq_score_history_indicator_evidence", table_name="score_history")
    op.drop_table("score_history")

    op.drop_index(
        "ix_event_indicators_indicator_rule_event",
        table_name="event_indicators",
    )
    op.drop_table("event_indicators")

    op.drop_index("ix_event_articles_article_event", table_name="event_articles")
    op.drop_table("event_articles")

    op.drop_index("ix_correlated_events_updated_at", table_name="correlated_events")
    op.drop_table("correlated_events")

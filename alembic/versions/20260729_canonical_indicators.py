"""Canonicalize indicators and preserve article mentions in an association table.

The downgrade is structurally valid but lossy: where a canonical indicator belongs to
multiple articles, only its lowest raw_article_id can be restored to the old one-owner
shape. No indicator, enrichment, or EPSS measurement is fabricated.

Revision ID: b74f3c9a21de
Revises: 61b739ac42e5
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision = "b74f3c9a21de"
down_revision = "61b739ac42e5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_NORMALIZED_VALUE_SQL = """
CASE
    WHEN indicator_type::text = 'cve'
         AND upper(indicator_value) ~ '^CVE-(19|20)[0-9]{2}-[0-9]{4,7}$'
        THEN upper(indicator_value)
    WHEN indicator_type::text IN ('md5', 'sha1', 'sha256')
         AND lower(indicator_value) ~ '^[a-f0-9]+$'
        THEN lower(indicator_value)
    WHEN indicator_type::text = 'domain' AND position('.' IN indicator_value) > 0
        THEN rtrim(lower(indicator_value), '.')
    WHEN indicator_type::text = 'email'
        THEN lower(indicator_value)
    ELSE indicator_value
END
"""


def upgrade() -> None:
    op.create_table(
        "article_indicators",
        sa.Column("raw_article_id", sa.Integer(), nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["raw_article_id"], ["raw_articles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["indicator_id"], ["indicators.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("raw_article_id", "indicator_id"),
    )
    op.create_index(
        op.f("ix_article_indicators_raw_article_id"),
        "article_indicators",
        ["raw_article_id"],
    )
    op.create_index(
        op.f("ix_article_indicators_indicator_id"),
        "article_indicators",
        ["indicator_id"],
    )

    op.execute(
        f"""
        CREATE TEMPORARY TABLE indicator_dedup_map ON COMMIT DROP AS
        WITH normalized AS (
            SELECT
                id AS old_id,
                raw_article_id,
                indicator_type,
                {_NORMALIZED_VALUE_SQL} AS normalized_value
            FROM indicators
        )
        SELECT
            old_id,
            raw_article_id,
            normalized_value,
            min(old_id) OVER (
                PARTITION BY indicator_type, normalized_value
            ) AS canonical_id
        FROM normalized;

        CREATE UNIQUE INDEX ON indicator_dedup_map(old_id);
        CREATE INDEX ON indicator_dedup_map(canonical_id);

        INSERT INTO article_indicators (raw_article_id, indicator_id, created_at)
        SELECT DISTINCT
            mapping.raw_article_id,
            mapping.canonical_id,
            indicators.created_at
        FROM indicator_dedup_map AS mapping
        JOIN indicators ON indicators.id = mapping.old_id
        ON CONFLICT (raw_article_id, indicator_id) DO NOTHING;
        """
    )

    # Retain exactly one current provider result. Status quality wins first; a more
    # recent updated/enriched result wins only within the same quality class.
    op.execute(
        """
        WITH ranked AS (
            SELECT
                enrichment.id,
                row_number() OVER (
                    PARTITION BY mapping.canonical_id, enrichment.provider
                    ORDER BY
                        CASE enrichment.status
                            WHEN 'success' THEN 0
                            WHEN 'not_found' THEN 1
                            WHEN 'rate_limited' THEN 2
                            WHEN 'temporary_failure' THEN 3
                            WHEN 'permanent_failure' THEN 4
                            WHEN 'auth_error' THEN 5
                            WHEN 'failed' THEN 6
                            ELSE 7
                        END,
                        enrichment.updated_at DESC NULLS LAST,
                        enrichment.enriched_at DESC NULLS LAST,
                        enrichment.id DESC
                ) AS winner_rank
            FROM indicator_enrichments AS enrichment
            JOIN indicator_dedup_map AS mapping
              ON mapping.old_id = enrichment.indicator_id
        )
        DELETE FROM indicator_enrichments
        WHERE id IN (SELECT id FROM ranked WHERE winner_rank > 1);

        UPDATE indicator_enrichments AS enrichment
        SET indicator_id = mapping.canonical_id
        FROM indicator_dedup_map AS mapping
        WHERE enrichment.indicator_id = mapping.old_id
          AND enrichment.indicator_id <> mapping.canonical_id;
        """
    )

    # EPSS is historical rather than a current status. For an identical canonical
    # CVE/model date, retain the most recently fetched observation deterministically.
    op.execute(
        """
        WITH ranked AS (
            SELECT
                history.id,
                row_number() OVER (
                    PARTITION BY mapping.canonical_id, history.model_date
                    ORDER BY history.fetched_at DESC, history.id DESC
                ) AS winner_rank
            FROM epss_history AS history
            JOIN indicator_dedup_map AS mapping
              ON mapping.old_id = history.indicator_id
        )
        DELETE FROM epss_history
        WHERE id IN (SELECT id FROM ranked WHERE winner_rank > 1);

        UPDATE epss_history AS history
        SET indicator_id = mapping.canonical_id
        FROM indicator_dedup_map AS mapping
        WHERE history.indicator_id = mapping.old_id
          AND history.indicator_id <> mapping.canonical_id;

        DELETE FROM indicators AS duplicate
        USING indicator_dedup_map AS mapping
        WHERE duplicate.id = mapping.old_id
          AND mapping.old_id <> mapping.canonical_id;

        UPDATE indicators AS indicator
        SET indicator_value = mapping.normalized_value
        FROM indicator_dedup_map AS mapping
        WHERE indicator.id = mapping.canonical_id
          AND indicator.indicator_value IS DISTINCT FROM mapping.normalized_value;
        """
    )

    op.drop_constraint(
        "uq_indicators_article_type_value",
        "indicators",
        type_="unique",
    )
    op.drop_index(op.f("ix_indicators_raw_article_id"), table_name="indicators")
    op.drop_column("indicators", "raw_article_id")
    op.create_unique_constraint(
        "uq_indicators_type_value",
        "indicators",
        ["indicator_type", "indicator_value"],
    )

    op.execute(
        """
        DO $validation$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM indicators
                GROUP BY indicator_type, indicator_value HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION 'canonical indicator duplicates remain';
            END IF;
            IF EXISTS (
                SELECT 1 FROM indicator_enrichments
                GROUP BY indicator_id, provider HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION 'duplicate current provider results remain';
            END IF;
            IF EXISTS (
                SELECT 1 FROM epss_history
                GROUP BY indicator_id, model_date HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION 'duplicate EPSS history observations remain';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM article_indicators association
                LEFT JOIN raw_articles article ON article.id = association.raw_article_id
                LEFT JOIN indicators indicator ON indicator.id = association.indicator_id
                WHERE article.id IS NULL OR indicator.id IS NULL
            ) OR EXISTS (
                SELECT 1
                FROM indicator_enrichments enrichment
                LEFT JOIN indicators indicator ON indicator.id = enrichment.indicator_id
                WHERE indicator.id IS NULL
            ) THEN
                RAISE EXCEPTION 'orphaned canonical indicator references remain';
            END IF;
        END
        $validation$;
        """
    )


def downgrade() -> None:
    op.add_column("indicators", sa.Column("raw_article_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_indicators_raw_article_id_raw_articles",
        "indicators",
        "raw_articles",
        ["raw_article_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.execute(
        """
        UPDATE indicators AS indicator
        SET raw_article_id = ownership.raw_article_id
        FROM (
            SELECT indicator_id, min(raw_article_id) AS raw_article_id
            FROM article_indicators
            GROUP BY indicator_id
        ) AS ownership
        WHERE indicator.id = ownership.indicator_id;

        DO $validation$
        BEGIN
            IF EXISTS (SELECT 1 FROM indicators WHERE raw_article_id IS NULL) THEN
                RAISE EXCEPTION
                    'cannot downgrade: canonical indicators without article associations exist';
            END IF;
        END
        $validation$;
        """
    )
    op.alter_column("indicators", "raw_article_id", nullable=False)
    op.drop_constraint("uq_indicators_type_value", "indicators", type_="unique")
    op.create_unique_constraint(
        "uq_indicators_article_type_value",
        "indicators",
        ["raw_article_id", "indicator_type", "indicator_value"],
    )
    op.create_index(
        op.f("ix_indicators_raw_article_id"),
        "indicators",
        ["raw_article_id"],
    )
    op.drop_index(
        op.f("ix_article_indicators_indicator_id"),
        table_name="article_indicators",
    )
    op.drop_index(
        op.f("ix_article_indicators_raw_article_id"),
        table_name="article_indicators",
    )
    op.drop_table("article_indicators")

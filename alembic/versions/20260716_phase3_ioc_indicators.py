"""Create IOC indicators table for enrichment phase.

Revision ID: 2d1d8a617db8
Revises: 4a2abfa08cbe
Create Date: 2026-07-16 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "2d1d8a617db8"
down_revision = "4a2abfa08cbe"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create IOC enum and indicators table."""

    ioc_type = postgresql.ENUM(
        "cve",
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "email",
        "md5",
        "sha1",
        "sha256",
        name="ioc_type",
        create_type=False,
    )
    ioc_type.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "indicators",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("raw_article_id", sa.Integer(), nullable=False),
        sa.Column("indicator_type", ioc_type, nullable=False),
        sa.Column("indicator_value", sa.String(length=2048), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["raw_article_id"], ["raw_articles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "raw_article_id",
            "indicator_type",
            "indicator_value",
            name="uq_indicators_article_type_value",
        ),
    )

    op.create_index(
        op.f("ix_indicators_raw_article_id"), "indicators", ["raw_article_id"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_indicator_type"), "indicators", ["indicator_type"], unique=False
    )
    op.create_index(
        op.f("ix_indicators_indicator_value"), "indicators", ["indicator_value"], unique=False
    )


def downgrade() -> None:
    """Drop indicators table and IOC enum."""

    op.drop_index(op.f("ix_indicators_indicator_value"), table_name="indicators")
    op.drop_index(op.f("ix_indicators_indicator_type"), table_name="indicators")
    op.drop_index(op.f("ix_indicators_raw_article_id"), table_name="indicators")
    op.drop_table("indicators")

    ioc_type = postgresql.ENUM(
        "cve",
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "email",
        "md5",
        "sha1",
        "sha256",
        name="ioc_type",
        create_type=False,
    )
    ioc_type.drop(op.get_bind(), checkfirst=True)

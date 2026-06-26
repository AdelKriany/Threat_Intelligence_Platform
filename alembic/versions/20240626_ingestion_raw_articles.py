"""Create raw_articles table for ingestion phase.

Revision ID: dd6ff59cc6bb
Revises: 3f7b8817d2de
Create Date: 2026-06-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "dd6ff59cc6bb"
down_revision = "3f7b8817d2de"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the raw_articles table."""

    op.create_table(
        "raw_articles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column("source_name", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=True),
        sa.Column("categories", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("content_hash"),
    )
    op.create_index(op.f("ix_raw_articles_content_hash"), "raw_articles", ["content_hash"], unique=True)
    op.create_index(op.f("ix_raw_articles_source_id"), "raw_articles", ["source_id"], unique=False)
    op.create_index(op.f("ix_raw_articles_source_name"), "raw_articles", ["source_name"], unique=False)
    op.create_index(op.f("ix_raw_articles_url"), "raw_articles", ["url"], unique=False)


def downgrade() -> None:
    """Drop the raw_articles table."""

    op.drop_index(op.f("ix_raw_articles_url"), table_name="raw_articles")
    op.drop_index(op.f("ix_raw_articles_source_name"), table_name="raw_articles")
    op.drop_index(op.f("ix_raw_articles_source_id"), table_name="raw_articles")
    op.drop_index(op.f("ix_raw_articles_content_hash"), table_name="raw_articles")
    op.drop_table("raw_articles")

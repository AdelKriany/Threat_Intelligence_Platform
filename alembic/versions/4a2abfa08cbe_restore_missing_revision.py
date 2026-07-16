"""Restore missing migration revision referenced by the live database.

Revision ID: 4a2abfa08cbe
Revises: dd6ff59cc6bb
Create Date: 2026-07-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "4a2abfa08cbe"
down_revision = "dd6ff59cc6bb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """No-op migration to restore Alembic history continuity."""

    pass


def downgrade() -> None:
    """No-op downgrade for restored revision."""

    pass

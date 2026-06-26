"""Initial empty migration for ThreatLens Phase 1.

Revision ID: 3f7b8817d2de
Revises: 
Create Date: 2026-06-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = "3f7b8817d2de"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """No-op migration for initial foundation setup."""

    pass


def downgrade() -> None:
    """No-op downgrade for initial foundation setup."""

    pass

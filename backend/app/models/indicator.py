"""Compatibility imports for the canonical ingestion indicator models.

The active mappings live in :mod:`app.ingestion.models`. Keeping this module as a
re-export prevents a second SQLAlchemy mapping from redefining the same tables.
"""

from __future__ import annotations

from app.ingestion.models import ArticleIndicator, Indicator, IOCType

__all__ = ["ArticleIndicator", "IOCType", "Indicator"]

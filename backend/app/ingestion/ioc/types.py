from __future__ import annotations

from dataclasses import dataclass

from app.ingestion.models import IOCType


@dataclass(frozen=True, slots=True)
class ExtractedIndicator:
    """Normalized in-memory IOC extracted from a raw article."""

    indicator_type: IOCType
    indicator_value: str

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from app.ingestion.models import IOCType


class EnrichmentStatus(StrEnum):
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"


@dataclass(slots=True)
class EnrichmentResult:
    """Stable internal representation independent of provider response formats."""

    indicator_id: int
    indicator_value: str
    indicator_type: IOCType
    provider: str
    status: EnrichmentStatus
    risk_score: float | None = None
    severity: str | None = None
    summary: str | None = None
    normalized_data: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] | list[Any] | None = None
    enriched_at: datetime | None = None
    expires_at: datetime | None = None
    error_message: str | None = None
    cached: bool = False

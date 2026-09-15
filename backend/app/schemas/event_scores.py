from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.schemas.events import EventId
from app.schemas.indicator_scores import JsonScalar
from app.scoring.models import EvidenceStatus, Severity


class EventScoreComponentResponse(BaseModel):
    """One safe, explainable Event Formula v1 component."""

    name: str
    raw_input: dict[str, JsonScalar] | list[JsonScalar]
    normalized_value: JsonScalar
    weight: Decimal
    contribution: Decimal
    freshness_multiplier: Decimal
    status: EvidenceStatus
    provider: str | None
    evidence_at: datetime | None
    explanation: str

    model_config = ConfigDict(extra="forbid")

    @field_validator("evidence_at")
    @classmethod
    def normalize_optional_timestamp(cls, value: datetime | None) -> datetime | None:
        return _utc_timestamp(value)

    @field_serializer("weight", "contribution", "freshness_multiplier", when_used="json")
    def serialize_decimal(self, value: Decimal) -> float:
        return float(value)


class EventScoreResponse(BaseModel):
    """A persisted event score without its canonical evidence document."""

    id: int = Field(gt=0)
    event_id: EventId
    event_key: str
    event_title: str
    score: Decimal
    severity: Severity
    formula_version: str
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    as_of: datetime
    calculated_at: datetime
    components: list[EventScoreComponentResponse]

    model_config = ConfigDict(extra="forbid")

    @field_validator("as_of", "calculated_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        normalized = _utc_timestamp(value)
        if normalized is None:  # pragma: no cover - fields are not optional
            raise ValueError("timestamp is required")
        return normalized

    @field_serializer("score", when_used="json")
    def serialize_score(self, value: Decimal) -> float:
        return float(value)


class EventScorePostResponse(BaseModel):
    """POST result with the authoritative persistence creation outcome."""

    created: bool
    score: EventScoreResponse

    model_config = ConfigDict(extra="forbid")


class EventScoreHistoryResponse(BaseModel):
    """A bounded page of persisted event scores."""

    event_id: EventId
    items: list[EventScoreResponse]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


def _utc_timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "EventScoreComponentResponse",
    "EventScoreHistoryResponse",
    "EventScorePostResponse",
    "EventScoreResponse",
]

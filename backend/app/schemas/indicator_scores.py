from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.ingestion.models import IOCType
from app.scoring.models import EvidenceStatus, Severity

JsonScalar = str | int | bool | None
IndicatorId = Annotated[int, Field(gt=0)]


class ScoreComponentResponse(BaseModel):
    """One safe, explainable Formula v1 component."""

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


class IndicatorScoreResponse(BaseModel):
    """A persisted indicator score without the canonical evidence document."""

    id: int
    indicator_id: IndicatorId
    indicator_type: IOCType
    indicator_value: str
    score: Decimal
    severity: Severity
    formula_version: str
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    as_of: datetime
    calculated_at: datetime
    components: list[ScoreComponentResponse]

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


class IndicatorScorePostResponse(BaseModel):
    """POST result, including Phase 6B's authoritative creation outcome."""

    created: bool
    score: IndicatorScoreResponse

    model_config = ConfigDict(extra="forbid")


class IndicatorScoreHistoryResponse(BaseModel):
    """A bounded page of persisted indicator scores."""

    indicator_id: IndicatorId
    items: list[IndicatorScoreResponse]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class ErrorResponse(BaseModel):
    error: str
    message: str

    model_config = ConfigDict(extra="forbid")


def _utc_timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "ErrorResponse",
    "IndicatorId",
    "IndicatorScoreHistoryResponse",
    "IndicatorScorePostResponse",
    "IndicatorScoreResponse",
    "ScoreComponentResponse",
]

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.ingestion.models import IOCType
from app.scoring.models import Severity

EventId = Annotated[int, Field(gt=0)]


class PersistedScoreSummary(BaseModel):
    """Safe summary of a persisted score; no evidence document is exposed."""

    score: Decimal
    severity: Severity
    formula_version: str
    calculated_at: datetime

    model_config = ConfigDict(extra="forbid")

    @field_validator("calculated_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _utc_timestamp(value)

    @field_serializer("score", when_used="json")
    def serialize_score(self, value: Decimal) -> float:
        return float(value)


class EventSummaryResponse(BaseModel):
    id: EventId
    event_key: str
    title: str
    rule_name: str
    rule_version: str
    created_at: datetime
    updated_at: datetime
    article_count: int = Field(ge=0)
    indicator_count: int = Field(ge=0)
    latest_score: PersistedScoreSummary | None

    model_config = ConfigDict(extra="forbid")

    @field_validator("created_at", "updated_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _utc_timestamp(value)


class EventDetailResponse(EventSummaryResponse):
    """One event without unbounded relationship collections."""


class EventListResponse(BaseModel):
    items: list[EventSummaryResponse]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class EventArticleResponse(BaseModel):
    id: int
    source_id: str
    source_name: str | None
    title: str
    url: str | None
    published_at: datetime | None
    fetched_at: datetime
    author: str | None
    categories: list[str]
    relationship_reason: str
    relationship_rule_name: str
    relationship_rule_version: str
    relationship_created_at: datetime

    model_config = ConfigDict(extra="forbid")

    @field_validator("published_at")
    @classmethod
    def normalize_optional_timestamp(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc_timestamp(value)

    @field_validator("fetched_at", "relationship_created_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _utc_timestamp(value)


class EventArticleListResponse(BaseModel):
    event_id: EventId
    items: list[EventArticleResponse]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class EventIndicatorResponse(BaseModel):
    id: int
    indicator_type: IOCType
    indicator_value: str
    created_at: datetime
    relationship_reason: str
    relationship_rule_name: str
    relationship_rule_version: str
    relationship_created_at: datetime
    latest_score: PersistedScoreSummary | None

    model_config = ConfigDict(extra="forbid")

    @field_validator("created_at", "relationship_created_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _utc_timestamp(value)


class EventIndicatorListResponse(BaseModel):
    event_id: EventId
    items: list[EventIndicatorResponse]
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "EventArticleListResponse",
    "EventArticleResponse",
    "EventDetailResponse",
    "EventId",
    "EventIndicatorListResponse",
    "EventIndicatorResponse",
    "EventListResponse",
    "EventSummaryResponse",
    "PersistedScoreSummary",
]

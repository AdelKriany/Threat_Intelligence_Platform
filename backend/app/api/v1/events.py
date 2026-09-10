from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.exceptions import APIError
from app.database.session import get_db_session
from app.ingestion.ioc.validators import ValidationStatus, validate_indicator
from app.ingestion.models import IOCType
from app.schemas.events import (
    EventArticleListResponse,
    EventDetailResponse,
    EventId,
    EventIndicatorListResponse,
    EventListResponse,
)
from app.schemas.indicator_scores import ErrorResponse
from app.services.event_queries import (
    EventNotFoundError,
    get_event,
    list_event_articles,
    list_event_indicators,
    list_events,
)

router = APIRouter(prefix="/events", tags=["correlated events"])

SessionDependency = Annotated[Session, Depends(get_db_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]

_NOT_FOUND_RESPONSE: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"model": ErrorResponse}
}
_LIST_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse}
}


@router.get(
    "",
    response_model=EventListResponse,
    responses=_LIST_ERROR_RESPONSES,
)
def get_events(
    session: SessionDependency,
    limit: Limit = 20,
    offset: Offset = 0,
    cve: Annotated[str | None, Query(min_length=1)] = None,
    source_name: Annotated[str | None, Query(min_length=1)] = None,
    updated_from: Annotated[datetime | None, Query()] = None,
    updated_to: Annotated[datetime | None, Query()] = None,
) -> EventListResponse:
    """Return persisted correlated events without running correlation or scoring."""

    canonical_cve = _canonical_cve_filter(cve)
    normalized_from = _aware_filter(updated_from, "updated_from")
    normalized_to = _aware_filter(updated_to, "updated_to")
    if (
        normalized_from is not None
        and normalized_to is not None
        and normalized_from > normalized_to
    ):
        raise APIError(
            422,
            "INVALID_EVENT_FILTER",
            "updated_from must be earlier than or equal to updated_to.",
        )
    return list_events(
        session,
        limit=limit,
        offset=offset,
        cve=canonical_cve,
        source_name=source_name,
        updated_from=normalized_from,
        updated_to=normalized_to,
    )


@router.get(
    "/{event_id}",
    response_model=EventDetailResponse,
    responses=_NOT_FOUND_RESPONSE,
)
def get_event_detail(
    event_id: EventId,
    session: SessionDependency,
) -> EventDetailResponse:
    try:
        return get_event(session, event_id)
    except EventNotFoundError as exc:
        raise _not_found() from exc


@router.get(
    "/{event_id}/articles",
    response_model=EventArticleListResponse,
    responses=_NOT_FOUND_RESPONSE,
)
def get_event_articles(
    event_id: EventId,
    session: SessionDependency,
    limit: Limit = 20,
    offset: Offset = 0,
) -> EventArticleListResponse:
    try:
        return list_event_articles(session, event_id, limit=limit, offset=offset)
    except EventNotFoundError as exc:
        raise _not_found() from exc


@router.get(
    "/{event_id}/indicators",
    response_model=EventIndicatorListResponse,
    responses=_NOT_FOUND_RESPONSE,
)
def get_event_indicators(
    event_id: EventId,
    session: SessionDependency,
    limit: Limit = 20,
    offset: Offset = 0,
) -> EventIndicatorListResponse:
    try:
        return list_event_indicators(session, event_id, limit=limit, offset=offset)
    except EventNotFoundError as exc:
        raise _not_found() from exc


def _canonical_cve_filter(value: str | None) -> str | None:
    if value is None:
        return None
    validation = validate_indicator(IOCType.CVE, value)
    if validation.status is not ValidationStatus.VALID or validation.normalized_value != value:
        raise APIError(
            422,
            "INVALID_CVE_FILTER",
            "cve must be a valid canonical uppercase CVE.",
        )
    return value


def _aware_filter(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise APIError(
            422,
            "INVALID_EVENT_FILTER",
            f"{name} must include a timezone offset.",
        )
    return value.astimezone(UTC)


def _not_found() -> APIError:
    return APIError(404, "EVENT_NOT_FOUND", "Correlated event was not found.")


__all__ = [
    "get_event_articles",
    "get_event_detail",
    "get_event_indicators",
    "get_events",
    "router",
]

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.exceptions import APIError
from app.database.session import get_db_session
from app.models.phase6b import CorrelatedEvent
from app.schemas.event_scores import (
    EventScoreHistoryResponse,
    EventScorePostResponse,
    EventScoreResponse,
)
from app.schemas.events import EventId
from app.schemas.indicator_scores import ErrorResponse
from app.scoring.models import ScoringInputError
from app.services.event_score_queries import (
    EventNotFoundError as QueryEventNotFoundError,
)
from app.services.event_score_queries import (
    EventScoreNotFoundError,
    event_score_response,
    get_latest_event_score,
    latest_event_score_calculated_at,
    list_event_score_history,
)
from app.services.event_scoring import (
    AmbiguousEventRelationshipsError,
    InconsistentEventRelationshipsError,
    InvalidEventKeyError,
    InvalidStoredScoreEvidenceError,
    MissingMatchingCVERelationshipError,
    UnsupportedEventError,
    calculate_and_persist_event_score,
)
from app.services.event_scoring import (
    EventNotFoundError as ScoringEventNotFoundError,
)

router = APIRouter(prefix="/events", tags=["event scoring"])
logger = logging.getLogger(__name__)

SessionDependency = Annotated[Session, Depends(get_db_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]

_NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
    status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
}
_POST_RESPONSES: dict[int | str, dict[str, Any]] = {
    **_NOT_FOUND_RESPONSES,
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
}
_UNSCORABLE_ERRORS = (
    UnsupportedEventError,
    InvalidEventKeyError,
    MissingMatchingCVERelationshipError,
    AmbiguousEventRelationshipsError,
    InconsistentEventRelationshipsError,
    InvalidStoredScoreEvidenceError,
    ScoringInputError,
)


@router.post(
    "/{event_id}/score",
    response_model=EventScorePostResponse,
    status_code=status.HTTP_200_OK,
    responses=_POST_RESPONSES,
)
def calculate_event_score(
    event_id: EventId,
    session: SessionDependency,
    force_refresh: bool = Query(default=False),
) -> EventScorePostResponse:
    """Calculate from stored evidence and atomically persist or reuse an event score."""

    try:
        reusable_as_of = (
            None if force_refresh else latest_event_score_calculated_at(session, event_id)
        )
        try:
            persisted = calculate_and_persist_event_score(
                session,
                event_id,
                as_of=reusable_as_of or _utc_now(),
            )
        except ScoringInputError:
            if reusable_as_of is None:
                raise
            # Stored evidence can make the prior calculation context invalid.
            # Phase 9A remains the sole calculator and persister for the retry.
            persisted = calculate_and_persist_event_score(
                session,
                event_id,
                as_of=_utc_now(),
            )
        event = session.get(CorrelatedEvent, event_id)
        if event is None:  # Defensive against an out-of-band delete in this transaction.
            raise ScoringEventNotFoundError
        response = EventScorePostResponse(
            created=persisted.created,
            score=event_score_response(persisted.score_history, event, persisted.components),
        )
        session.commit()
        return response
    except ScoringEventNotFoundError as exc:
        session.rollback()
        raise _event_not_found() from exc
    except _UNSCORABLE_ERRORS as exc:
        session.rollback()
        logger.warning(
            "event score rejected",
            extra={"event_id": event_id, "reason": type(exc).__name__},
        )
        raise APIError(
            422,
            "EVENT_UNSCORABLE",
            "Event cannot be scored from the stored data.",
        ) from exc
    except Exception:
        session.rollback()
        raise


@router.get(
    "/{event_id}/score",
    response_model=EventScoreResponse,
    responses=_NOT_FOUND_RESPONSES,
)
def get_event_score(
    event_id: EventId,
    session: SessionDependency,
) -> EventScoreResponse:
    """Return the latest persisted event score without calculation or mutation."""

    try:
        return get_latest_event_score(session, event_id)
    except QueryEventNotFoundError as exc:
        raise _event_not_found() from exc
    except EventScoreNotFoundError as exc:
        raise APIError(
            404,
            "EVENT_SCORE_NOT_FOUND",
            "Correlated event has no persisted score.",
        ) from exc


@router.get(
    "/{event_id}/score/history",
    response_model=EventScoreHistoryResponse,
    responses=_NOT_FOUND_RESPONSES,
)
def get_event_score_history(
    event_id: EventId,
    session: SessionDependency,
    limit: Limit = 20,
    offset: Offset = 0,
) -> EventScoreHistoryResponse:
    """Return a newest-first bounded page without calculation or mutation."""

    try:
        return list_event_score_history(session, event_id, limit=limit, offset=offset)
    except QueryEventNotFoundError as exc:
        raise _event_not_found() from exc


def _event_not_found() -> APIError:
    return APIError(404, "EVENT_NOT_FOUND", "Correlated event was not found.")


def _utc_now() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "calculate_event_score",
    "get_event_score",
    "get_event_score_history",
    "router",
]

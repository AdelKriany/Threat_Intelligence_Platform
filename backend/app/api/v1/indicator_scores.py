from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, noload, selectinload

from app.core.exceptions import APIError
from app.database.session import get_db_session
from app.ingestion.models import Indicator
from app.models.phase6b import ScoreComponentRecord, ScoreHistory
from app.schemas.indicator_scores import (
    ErrorResponse,
    IndicatorId,
    IndicatorScoreHistoryResponse,
    IndicatorScorePostResponse,
    IndicatorScoreResponse,
    JsonScalar,
    ScoreComponentResponse,
)
from app.scoring.models import EvidenceStatus, ScoringInputError, Severity
from app.services.indicator_scoring import (
    IndicatorNotFoundError,
    calculate_and_persist_indicator_score,
)

router = APIRouter(prefix="/indicators", tags=["indicator scoring"])

SessionDependency = Annotated[Session, Depends(get_db_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]

_NOT_FOUND_RESPONSE: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"model": ErrorResponse}
}
_POST_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    **_NOT_FOUND_RESPONSE,
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ErrorResponse},
    status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
}


@router.post(
    "/{indicator_id}/score",
    response_model=IndicatorScorePostResponse,
    status_code=status.HTTP_200_OK,
    responses=_POST_ERROR_RESPONSES,
)
def calculate_indicator_score(
    indicator_id: IndicatorId,
    session: SessionDependency,
    force_refresh: bool = Query(default=False),
) -> IndicatorScorePostResponse:
    """Calculate from stored evidence and atomically persist or reuse a score.

    ``force_refresh`` never invokes enrichment providers. Phase 6B always loads the
    currently stored evidence; the flag makes that recalculation request explicit.
    Its canonical uniqueness rules remain authoritative for both flag values.
    """

    try:
        reusable_as_of = None if force_refresh else _latest_calculated_at(session, indicator_id)
        try:
            persisted = calculate_and_persist_indicator_score(
                session,
                indicator_id,
                as_of=reusable_as_of or _utc_now(),
            )
        except ScoringInputError:
            if reusable_as_of is None:
                raise
            # Evidence stored after the prior calculation cannot be evaluated in its
            # old time context. Phase 6B remains the sole loader/calculator/persister.
            persisted = calculate_and_persist_indicator_score(
                session,
                indicator_id,
                as_of=_utc_now(),
            )
        indicator = session.get(Indicator, indicator_id)
        if indicator is None:  # Defensive against an out-of-band delete in this transaction.
            raise IndicatorNotFoundError
        response = IndicatorScorePostResponse(
            created=persisted.created,
            score=_score_response(
                persisted.score_history,
                indicator,
                persisted.components,
            ),
        )
        session.commit()
        return response
    except IndicatorNotFoundError as exc:
        session.rollback()
        raise APIError(404, "INDICATOR_NOT_FOUND", "Indicator was not found.") from exc
    except ScoringInputError as exc:
        session.rollback()
        raise APIError(
            422,
            "INDICATOR_UNSCORABLE",
            "Indicator cannot be scored from the stored data.",
        ) from exc
    except Exception:
        session.rollback()
        raise


@router.get(
    "/{indicator_id}/score",
    response_model=IndicatorScoreResponse,
    responses=_NOT_FOUND_RESPONSE,
)
def get_latest_indicator_score(
    indicator_id: IndicatorId,
    session: SessionDependency,
) -> IndicatorScoreResponse:
    """Return the latest persisted score without recalculation or mutation."""

    history = session.scalar(
        _score_query(indicator_id)
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(1)
    )
    if history is None:
        _require_indicator(session, indicator_id)
        raise APIError(404, "SCORE_NOT_FOUND", "Indicator has no persisted score.")
    indicator = cast(Indicator, history.indicator)
    return _score_response(history, indicator, history.components)


@router.get(
    "/{indicator_id}/score/history",
    response_model=IndicatorScoreHistoryResponse,
    responses=_NOT_FOUND_RESPONSE,
)
def get_indicator_score_history(
    indicator_id: IndicatorId,
    session: SessionDependency,
    limit: Limit = 20,
    offset: Offset = 0,
) -> IndicatorScoreHistoryResponse:
    """Return a newest-first, bounded page of persisted score history."""

    indicator = _require_indicator(session, indicator_id)
    predicate = (
        ScoreHistory.target_kind == "indicator",
        ScoreHistory.indicator_id == indicator_id,
    )
    total = session.scalar(select(func.count(ScoreHistory.id)).where(*predicate)) or 0
    histories = session.scalars(
        select(ScoreHistory)
        .options(
            selectinload(ScoreHistory.components),
            noload(ScoreHistory.indicator),
            noload(ScoreHistory.event),
        )
        .where(*predicate)
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return IndicatorScoreHistoryResponse(
        indicator_id=indicator_id,
        items=[_score_response(item, indicator, item.components) for item in histories],
        limit=limit,
        offset=offset,
        total=total,
    )


def _score_query(indicator_id: int) -> Any:
    return (
        select(ScoreHistory)
        .options(
            joinedload(ScoreHistory.indicator),
            selectinload(ScoreHistory.components),
            noload(ScoreHistory.event),
        )
        .where(
            ScoreHistory.target_kind == "indicator",
            ScoreHistory.indicator_id == indicator_id,
        )
    )


def _require_indicator(session: Session, indicator_id: int) -> Indicator:
    indicator = session.get(Indicator, indicator_id)
    if indicator is None:
        raise APIError(404, "INDICATOR_NOT_FOUND", "Indicator was not found.")
    return indicator


def _latest_calculated_at(session: Session, indicator_id: int) -> datetime | None:
    return session.scalar(
        select(ScoreHistory.calculated_at)
        .where(
            ScoreHistory.target_kind == "indicator",
            ScoreHistory.indicator_id == indicator_id,
        )
        .order_by(ScoreHistory.calculated_at.desc(), ScoreHistory.id.desc())
        .limit(1)
    )


def _score_response(
    history: ScoreHistory,
    indicator: Indicator,
    components: list[ScoreComponentRecord] | tuple[ScoreComponentRecord, ...],
) -> IndicatorScoreResponse:
    statuses = _stored_provider_statuses(history.canonical_evidence)
    as_of = _stored_as_of(history.canonical_evidence, history.calculated_at)
    ordered_components = sorted(components, key=lambda item: item.component_name)
    return IndicatorScoreResponse(
        id=history.id,
        indicator_id=cast(int, history.indicator_id),
        indicator_type=indicator.indicator_type,
        indicator_value=indicator.indicator_value,
        score=history.score,
        severity=Severity(history.severity),
        formula_version=history.formula_version,
        evidence_hash=history.evidence_hash,
        as_of=as_of,
        calculated_at=history.calculated_at,
        components=[
            ScoreComponentResponse(
                name=row.component_name,
                raw_input=cast(dict[str, JsonScalar] | list[JsonScalar], row.raw_input),
                normalized_value=cast(JsonScalar, row.normalized_input),
                weight=row.weight,
                contribution=row.contribution,
                freshness_multiplier=row.freshness_multiplier,
                status=_component_status(row, statuses),
                provider=row.provider,
                evidence_at=row.evidence_at,
                explanation=row.explanation,
            )
            for row in ordered_components
        ],
    )


def _stored_provider_statuses(payload: dict[str, Any]) -> dict[str, EvidenceStatus]:
    providers = payload.get("providers", [])
    if not isinstance(providers, list):
        return {}
    statuses: dict[str, EvidenceStatus] = {}
    for item in providers:
        if not isinstance(item, dict):
            continue
        provider = item.get("provider")
        value = item.get("status")
        if isinstance(provider, str) and isinstance(value, str):
            try:
                statuses[provider] = EvidenceStatus(value)
            except ValueError:
                statuses[provider] = EvidenceStatus.INVALID
    return statuses


def _component_status(
    row: ScoreComponentRecord,
    provider_statuses: dict[str, EvidenceStatus],
) -> EvidenceStatus:
    if row.provider is None:
        return EvidenceStatus.USABLE
    status = provider_statuses.get(row.provider, EvidenceStatus.INVALID)
    if status is EvidenceStatus.USABLE and row.freshness_multiplier < Decimal("1"):
        return EvidenceStatus.STALE
    return status


def _stored_as_of(payload: dict[str, Any], fallback: datetime) -> datetime:
    value = payload.get("as_of")
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return fallback


def _utc_now() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "calculate_indicator_score",
    "get_indicator_score_history",
    "get_latest_indicator_score",
    "router",
]

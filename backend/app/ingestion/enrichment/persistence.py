from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import Indicator, IndicatorEnrichment

MAX_ERROR_LENGTH = 1000


def find_current(
    session: Session,
    indicator_id: int,
    provider: str,
    *,
    now: datetime,
) -> IndicatorEnrichment | None:
    record = session.scalar(
        select(IndicatorEnrichment).where(
            IndicatorEnrichment.indicator_id == indicator_id,
            IndicatorEnrichment.provider == provider,
        )
    )
    if record is None or record.expires_at is None:
        return None
    return record if _as_utc(record.expires_at) > _as_utc(now) else None


def upsert_result(session: Session, result: EnrichmentResult) -> IndicatorEnrichment:
    """Create or update the unique indicator/provider result."""

    record = session.scalar(
        select(IndicatorEnrichment).where(
            IndicatorEnrichment.indicator_id == result.indicator_id,
            IndicatorEnrichment.provider == result.provider,
        )
    )
    now = datetime.now(UTC)
    is_new = record is None
    if is_new:
        record = IndicatorEnrichment(
            indicator_id=result.indicator_id,
            provider=result.provider,
            status=result.status.value,
            enriched_at=result.enriched_at or now,
            created_at=now,
            updated_at=now,
        )
    assert record is not None
    _apply_result(record, result, now)
    if is_new:
        try:
            # The savepoint preserves the outer task transaction if another worker
            # inserts this unique indicator/provider pair concurrently.
            with session.begin_nested():
                session.add(record)
                session.flush()
        except IntegrityError:
            record = session.scalar(
                select(IndicatorEnrichment).where(
                    IndicatorEnrichment.indicator_id == result.indicator_id,
                    IndicatorEnrichment.provider == result.provider,
                )
            )
            if record is None:
                raise
            _apply_result(record, result, now)
    session.flush()
    return record


def _apply_result(record: IndicatorEnrichment, result: EnrichmentResult, now: datetime) -> None:
    record.status = result.status.value
    record.risk_score = result.risk_score
    record.severity = result.severity
    record.summary = result.summary
    record.normalized_data = result.normalized_data
    record.raw_response = result.raw_response
    record.error_message = _safe_error(result.error_message)
    record.enriched_at = result.enriched_at or now
    record.expires_at = result.expires_at
    record.updated_at = now


def result_from_record(
    record: IndicatorEnrichment,
    indicator: Indicator,
    *,
    cached: bool = True,
) -> EnrichmentResult:
    try:
        status = EnrichmentStatus(record.status)
    except ValueError:
        status = EnrichmentStatus.FAILED
    return EnrichmentResult(
        indicator_id=indicator.id,
        indicator_value=indicator.indicator_value,
        indicator_type=indicator.indicator_type,
        provider=record.provider,
        status=status,
        risk_score=record.risk_score,
        severity=record.severity,
        summary=record.summary,
        normalized_data=record.normalized_data or {},
        raw_response=record.raw_response,
        error_message=record.error_message,
        enriched_at=record.enriched_at,
        expires_at=record.expires_at,
        cached=cached,
    )


def _safe_error(message: str | None) -> str | None:
    if message is None:
        return None
    return message[:MAX_ERROR_LENGTH]


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

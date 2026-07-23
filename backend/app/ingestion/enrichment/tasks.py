from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, and_, exists, false, or_, select

from app.core.config import settings
from app.database.session import SessionLocal
from app.ingestion.enrichment.registry import ProviderRegistry
from app.ingestion.enrichment.service import EnrichmentService
from app.ingestion.enrichment.types import EnrichmentResult
from app.ingestion.models import Indicator, IndicatorEnrichment
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _serialize(result: EnrichmentResult) -> dict[str, Any]:
    return {
        "indicator_id": result.indicator_id,
        "indicator_value": result.indicator_value,
        "indicator_type": result.indicator_type.value,
        "provider": result.provider,
        "status": result.status.value,
        "risk_score": result.risk_score,
        "severity": result.severity,
        "summary": result.summary,
        "normalized_data": result.normalized_data,
        "error_message": result.error_message,
        "enriched_at": result.enriched_at.isoformat() if result.enriched_at else None,
        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
        "cached": result.cached,
    }


@celery_app.task(
    name="app.ingestion.enrichment.tasks.enrich_indicator_task",
    autoretry_for=(),
)
def enrich_indicator_task(indicator_id: int, force_refresh: bool = False) -> list[dict[str, Any]]:
    """Enrich one indicator. The session is always closed by its context manager."""

    with SessionLocal() as session:
        results = asyncio.run(
            EnrichmentService(session).enrich_indicator(indicator_id, force_refresh=force_refresh)
        )
        return [_serialize(result) for result in results]


@celery_app.task(name="app.ingestion.enrichment.tasks.enrich_article_indicators_task")
def enrich_article_indicators_task(
    raw_article_id: int, force_refresh: bool = False
) -> dict[str, int]:
    with SessionLocal() as session:
        indicator_ids = list(
            session.scalars(
                select(Indicator.id)
                .where(Indicator.raw_article_id == raw_article_id)
                .order_by(Indicator.id)
            )
        )
        enriched = 0
        service = EnrichmentService(session)
        for indicator_id in indicator_ids:
            enriched += len(
                asyncio.run(service.enrich_indicator(indicator_id, force_refresh=force_refresh))
            )
        return {"indicators": len(indicator_ids), "results": enriched}


def build_pending_indicator_query(
    registry: ProviderRegistry,
    *,
    now: datetime,
    limit: int,
    provider_name: str | None = None,
) -> Select[tuple[int]]:
    """Select supported indicators missing a current result, optionally for one provider."""

    conditions = []
    for provider in registry.providers:
        if not provider.enabled or (provider_name is not None and provider.name != provider_name):
            continue
        current_result_exists = exists(
            select(IndicatorEnrichment.id).where(
                IndicatorEnrichment.indicator_id == Indicator.id,
                IndicatorEnrichment.provider == provider.name,
                IndicatorEnrichment.expires_at.is_not(None),
                IndicatorEnrichment.expires_at > now,
            )
        )
        conditions.append(
            and_(
                Indicator.indicator_type.in_(provider.supported_ioc_types),
                ~current_result_exists,
            )
        )
    if not conditions:
        return select(Indicator.id).where(false())
    return select(Indicator.id).where(or_(*conditions)).order_by(Indicator.id).limit(limit)


@celery_app.task(name="app.ingestion.enrichment.tasks.enrich_pending_batch_task")
def enrich_pending_batch_task(
    batch_size: int | None = None,
    provider_name: str | None = None,
) -> dict[str, int]:
    """Refresh a bounded pending/expired batch, optionally restricted to one provider."""

    configured_limit = max(1, settings.enrichment_batch_size)
    limit = max(1, min(batch_size or configured_limit, configured_limit))
    now = datetime.now(UTC)
    registry = ProviderRegistry.from_settings()
    eligible_providers = [
        provider
        for provider in registry.providers
        if provider.enabled and (provider_name is None or provider.name == provider_name)
    ]
    if not eligible_providers:
        logger.warning(
            "No enabled enrichment provider matched provider_name=%s",
            provider_name or "all",
        )
        return {"indicators": 0, "results": 0}

    with SessionLocal() as session:
        indicator_ids = list(
            session.scalars(
                build_pending_indicator_query(
                    registry,
                    now=now,
                    limit=limit,
                    provider_name=provider_name,
                )
            )
        )
        logger.info(
            "Selected enrichment batch provider=%s limit=%s indicators=%s",
            provider_name or "all",
            limit,
            len(indicator_ids),
        )
        result_count = 0
        service = EnrichmentService(session, registry=registry)
        for indicator_id in indicator_ids:
            result_count += len(asyncio.run(service.enrich_indicator(indicator_id)))
        return {"indicators": len(indicator_ids), "results": result_count}

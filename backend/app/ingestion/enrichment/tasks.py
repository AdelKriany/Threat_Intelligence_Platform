from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, and_, exists, false, func, or_, select

from app.core.config import settings
from app.database.session import SessionLocal
from app.ingestion.enrichment.cache import acquire_task_lock, release_task_lock
from app.ingestion.enrichment.exceptions import EnrichmentError
from app.ingestion.enrichment.persistence import upsert_epss_history, upsert_result
from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.providers.cisa_kev import CISAKEVProvider
from app.ingestion.enrichment.providers.epss import EPSSProvider
from app.ingestion.enrichment.registry import ProviderRegistry
from app.ingestion.enrichment.service import EnrichmentService
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import ArticleIndicator, Indicator, IndicatorEnrichment
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
        "error_code": result.error_code,
        "enriched_at": result.enriched_at.isoformat() if result.enriched_at else None,
        "expires_at": result.expires_at.isoformat() if result.expires_at else None,
        "cached": result.cached,
    }


@celery_app.task(
    name="app.ingestion.enrichment.tasks.enrich_indicator_task",
    autoretry_for=(),
)
def enrich_indicator_task(
    indicator_id: int,
    force_refresh: bool = False,
    provider_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Enrich one indicator. The session is always closed by its context manager."""

    with SessionLocal() as session:
        registry = ProviderRegistry.from_settings()
        if provider_names is not None:
            selected = set(provider_names)
            registry = ProviderRegistry(
                provider for provider in registry.providers if provider.name in selected
            )
        results = asyncio.run(
            EnrichmentService(session, registry=registry).enrich_indicator(
                indicator_id, force_refresh=force_refresh
            )
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
                .join(
                    ArticleIndicator,
                    ArticleIndicator.indicator_id == Indicator.id,
                )
                .where(ArticleIndicator.raw_article_id == raw_article_id)
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
    raw_article_id: int | None = None,
) -> Select[tuple[int]]:
    """Select supported indicators missing a current result, optionally for one provider."""

    conditions = []
    for provider in registry.providers:
        if not provider.enabled or (provider_name is not None and provider.name != provider_name):
            continue
        short_failure_statuses = {
            "failed",
            "rate_limited",
            "temporary_failure",
        }
        current_result_exists = exists(
            select(IndicatorEnrichment.id).where(
                IndicatorEnrichment.indicator_id == Indicator.id,
                IndicatorEnrichment.provider == provider.name,
                or_(
                    and_(
                        IndicatorEnrichment.status == "rate_limited",
                        IndicatorEnrichment.updated_at
                        > now - timedelta(seconds=settings.enrichment_rate_limit_retry_seconds),
                    ),
                    and_(
                        IndicatorEnrichment.status.in_(short_failure_statuses - {"rate_limited"}),
                        IndicatorEnrichment.updated_at
                        > now - timedelta(seconds=settings.enrichment_failure_retry_seconds),
                    ),
                    and_(
                        IndicatorEnrichment.status == "not_found",
                        IndicatorEnrichment.updated_at
                        > now - timedelta(seconds=settings.enrichment_not_found_ttl_seconds),
                    ),
                    and_(
                        IndicatorEnrichment.status.not_in(short_failure_statuses | {"not_found"}),
                        IndicatorEnrichment.expires_at.is_not(None),
                        IndicatorEnrichment.expires_at > now,
                    ),
                ),
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
    query = select(Indicator.id)
    if raw_article_id is not None:
        query = query.join(
            ArticleIndicator,
            ArticleIndicator.indicator_id == Indicator.id,
        ).where(ArticleIndicator.raw_article_id == raw_article_id)
    return query.where(or_(*conditions)).order_by(Indicator.id).limit(limit)


def article_has_pending_enrichment(session: Any, raw_article_id: int) -> bool:
    """Return whether an article mentions a canonical IOC needing provider work."""

    registry = ProviderRegistry.from_settings()
    return (
        session.scalar(
            build_pending_indicator_query(
                registry,
                now=datetime.now(UTC),
                limit=1,
                raw_article_id=raw_article_id,
            )
        )
        is not None
    )


@celery_app.task(name="app.ingestion.enrichment.tasks.enrich_pending_batch_task")
def enrich_pending_batch_task(
    batch_size: int | None = None,
    provider_name: str | None = None,
) -> dict[str, int]:
    """Refresh a bounded pending/expired batch, optionally restricted to one provider."""

    configured_limit = max(1, settings.enrichment_batch_size)
    limit = max(1, min(batch_size or configured_limit, configured_limit))
    lock_name = f"pending-{provider_name or 'all'}"
    lock_client, token = acquire_task_lock(lock_name, 1800)
    if token is None:
        return {"indicators": 0, "results": 0, "skipped": 1}
    try:
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
        execution_registry = restrict_registry(registry, provider_name)

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
            service = EnrichmentService(session, registry=execution_registry)
            for indicator_id in indicator_ids:
                result_count += len(asyncio.run(service.enrich_indicator(indicator_id)))
            return {"indicators": len(indicator_ids), "results": result_count}
    finally:
        release_task_lock(lock_client, lock_name, token)


def _provider(registry: ProviderRegistry, name: str) -> EnrichmentProvider | None:
    return next(
        (provider for provider in registry.providers if provider.name == name and provider.enabled),
        None,
    )


def restrict_registry(registry: ProviderRegistry, provider_name: str | None) -> ProviderRegistry:
    """Return only the requested enabled provider, or all enabled providers."""

    return ProviderRegistry(
        provider
        for provider in registry.providers
        if provider.enabled and (provider_name is None or provider.name == provider_name)
    )


def _expiry(result: EnrichmentResult, provider: EnrichmentProvider) -> datetime:
    now = datetime.now(UTC)
    if result.status.value == "rate_limited":
        seconds = settings.enrichment_rate_limit_retry_seconds
    elif result.status.value in {"failed", "temporary_failure"}:
        seconds = settings.enrichment_failure_retry_seconds
    elif result.status.value == "not_found":
        seconds = settings.enrichment_not_found_ttl_seconds
    else:
        seconds = provider.ttl_seconds
    return now + timedelta(seconds=seconds)


def _persist_provider_results(
    session: Any,
    provider: EnrichmentProvider,
    results: list[EnrichmentResult],
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for result in results:
        result.expires_at = _expiry(result, provider)
        upsert_result(session, result)
        upsert_epss_history(session, result)
        counts[result.status.value] += 1
    session.commit()
    return counts


def _controlled_failures(
    indicators: list[Indicator],
    provider: EnrichmentProvider,
    exc: EnrichmentError,
) -> list[EnrichmentResult]:
    return [
        EnrichmentResult(
            indicator_id=indicator.id,
            indicator_value=indicator.indicator_value,
            indicator_type=indicator.indicator_type,
            provider=provider.name,
            status=EnrichmentStatus.TEMPORARY_FAILURE,
            error_code=exc.error_code,
            error_message=str(exc)[:1000],
            enriched_at=datetime.now(UTC),
        )
        for indicator in indicators
    ]


@celery_app.task(name="app.ingestion.enrichment.tasks.refresh_kev_catalog_task")
def refresh_kev_catalog_task(
    batch_size: int | None = None,
    force_catalog_refresh: bool = True,
) -> dict[str, Any]:
    """Fetch KEV once and apply it to a bounded CVE batch."""

    started = time.monotonic()
    lock_name = "cisa-kev-refresh"
    lock_client, token = acquire_task_lock(lock_name, 1800)
    if token is None:
        return {"provider": "cisa_kev", "skipped": "already_running"}
    try:
        registry = ProviderRegistry.from_settings()
        provider = _provider(registry, "cisa_kev")
        if not isinstance(provider, CISAKEVProvider):
            return {"provider": "cisa_kev", "skipped": "disabled"}
        limit = min(batch_size or settings.enrichment_batch_size, settings.enrichment_batch_size)
        with SessionLocal() as session:
            indicators = list(
                session.scalars(
                    select(Indicator)
                    .where(
                        Indicator.id.in_(
                            build_pending_indicator_query(
                                registry,
                                now=datetime.now(UTC),
                                limit=limit,
                                provider_name="cisa_kev",
                            )
                        )
                    )
                    .order_by(Indicator.id)
                )
            )
            try:
                mapped = asyncio.run(
                    provider.enrich_many(
                        [
                            (
                                indicator.id,
                                indicator.indicator_value,
                                indicator.indicator_type,
                            )
                            for indicator in indicators
                        ],
                        force_catalog_refresh=force_catalog_refresh,
                    )
                )
                results = list(mapped.values())
            except EnrichmentError as exc:
                results = _controlled_failures(indicators, provider, exc)
            counts = _persist_provider_results(session, provider, results)
        outcome: dict[str, Any] = {
            "provider": provider.name,
            "indicators": len(indicators),
            **counts,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        logger.info("Phase 5 provider batch completed stats=%s", outcome)
        return outcome
    finally:
        release_task_lock(lock_client, lock_name, token)


@celery_app.task(name="app.ingestion.enrichment.tasks.refresh_epss_batch_task")
def refresh_epss_batch_task(batch_size: int | None = None) -> dict[str, Any]:
    """Fetch EPSS in upstream-safe batches and persist current plus daily history."""

    started = time.monotonic()
    lock_name = "epss-refresh"
    lock_client, token = acquire_task_lock(lock_name, 1800)
    if token is None:
        return {"provider": "epss", "skipped": "already_running"}
    try:
        registry = ProviderRegistry.from_settings()
        provider = _provider(registry, "epss")
        if not isinstance(provider, EPSSProvider):
            return {"provider": "epss", "skipped": "disabled"}
        limit = min(batch_size or settings.enrichment_batch_size, settings.enrichment_batch_size)
        with SessionLocal() as session:
            indicators = list(
                session.scalars(
                    select(Indicator)
                    .where(
                        Indicator.id.in_(
                            build_pending_indicator_query(
                                registry,
                                now=datetime.now(UTC),
                                limit=limit,
                                provider_name="epss",
                            )
                        )
                    )
                    .order_by(Indicator.id)
                )
            )
            try:
                mapped = asyncio.run(
                    provider.enrich_many(
                        [
                            (
                                indicator.id,
                                indicator.indicator_value,
                                indicator.indicator_type,
                            )
                            for indicator in indicators
                        ]
                    )
                )
                results = list(mapped.values())
            except EnrichmentError as exc:
                results = _controlled_failures(indicators, provider, exc)
            counts = _persist_provider_results(session, provider, results)
        outcome = {
            "provider": provider.name,
            "indicators": len(indicators),
            **counts,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        logger.info("Phase 5 provider batch completed stats=%s", outcome)
        return outcome
    finally:
        release_task_lock(lock_client, lock_name, token)


@celery_app.task(name="app.ingestion.enrichment.tasks.phase5_coverage_task")
def phase5_coverage_task() -> dict[str, int]:
    """Return and log compact Phase 5 provider coverage."""

    with SessionLocal() as session:
        stats: dict[str, int] = {}
        for provider_name in ("nvd", "cisa_kev", "epss"):
            stats[provider_name] = int(
                session.scalar(
                    select(func.count(IndicatorEnrichment.id)).where(
                        IndicatorEnrichment.provider == provider_name,
                        IndicatorEnrichment.status == "success",
                    )
                )
                or 0
            )
        logger.info("Phase 5 coverage stats=%s", stats)
        return stats

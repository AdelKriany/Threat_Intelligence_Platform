from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.ingestion.enrichment.exceptions import (
    EnrichmentError,
    ProviderAuthenticationError,
    ProviderRateLimitError,
    ProviderResponseError,
)
from app.ingestion.enrichment.persistence import (
    find_current,
    result_from_record,
    upsert_epss_history,
    upsert_result,
)
from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.registry import ProviderRegistry
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import Indicator

logger = logging.getLogger(__name__)


class EnrichmentService:
    """Orchestrate provider selection, caching, isolation, and persistence."""

    def __init__(
        self,
        session: Session,
        *,
        registry: ProviderRegistry | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        self.session = session
        self.registry = registry or ProviderRegistry.from_settings()
        self.ttl = timedelta(
            seconds=(
                settings.enrichment_ttl_seconds if ttl_seconds is None else max(ttl_seconds, 0)
            )
        )
        self.status_ttls = {
            EnrichmentStatus.RATE_LIMITED.value: settings.enrichment_rate_limit_retry_seconds,
            EnrichmentStatus.TEMPORARY_FAILURE.value: settings.enrichment_failure_retry_seconds,
            EnrichmentStatus.FAILED.value: settings.enrichment_failure_retry_seconds,
            EnrichmentStatus.NOT_FOUND.value: settings.enrichment_not_found_ttl_seconds,
        }

    async def enrich_indicator(
        self,
        indicator_or_id: Indicator | int,
        *,
        force_refresh: bool = False,
    ) -> list[EnrichmentResult]:
        indicator = (
            indicator_or_id
            if isinstance(indicator_or_id, Indicator)
            else self.session.get(Indicator, indicator_or_id)
        )
        if indicator is None:
            return []
        providers = self.registry.for_ioc_type(indicator.indicator_type)
        if not providers:
            return []

        now = datetime.now(UTC)
        results: list[EnrichmentResult] = []
        pending: list[EnrichmentProvider] = []
        for provider in providers:
            current = (
                None
                if force_refresh
                else find_current(
                    self.session,
                    indicator.id,
                    provider.name,
                    now=now,
                    status_ttls=self.status_ttls,
                )
            )
            if current is not None:
                results.append(result_from_record(current, indicator))
            else:
                pending.append(provider)

        if not pending:
            return results

        calls = [self._call_provider(provider, indicator) for provider in pending]
        fresh_results = await asyncio.gather(*calls)
        for result in fresh_results:
            result.expires_at = now + self._ttl_for(result, pending)
            upsert_result(self.session, result)
            upsert_epss_history(self.session, result)
            results.append(result)
        self.session.commit()
        return results

    async def _call_provider(
        self, provider: EnrichmentProvider, indicator: Indicator
    ) -> EnrichmentResult:
        try:
            result = await provider.enrich(
                indicator.id,
                indicator.indicator_value,
                indicator.indicator_type,
            )
            result.indicator_id = indicator.id
            result.indicator_value = indicator.indicator_value
            result.indicator_type = indicator.indicator_type
            result.provider = provider.name
            result.enriched_at = result.enriched_at or datetime.now(UTC)
            return result
        except ProviderAuthenticationError:
            status = EnrichmentStatus.PERMANENT_FAILURE
            safe_message = "provider authentication was rejected"
            error_code = "authentication_error"
        except ProviderRateLimitError:
            status = EnrichmentStatus.RATE_LIMITED
            safe_message = "provider rate limit exceeded"
            error_code = "rate_limited"
        except EnrichmentError as exc:
            status = (
                EnrichmentStatus.PERMANENT_FAILURE
                if isinstance(exc, ProviderResponseError)
                else EnrichmentStatus.TEMPORARY_FAILURE
            )
            safe_message = str(exc) or "provider enrichment failed"
            error_code = exc.error_code
        except Exception:
            logger.exception(
                "Unexpected enrichment failure provider=%s indicator_id=%s",
                provider.name,
                indicator.id,
            )
            status = EnrichmentStatus.TEMPORARY_FAILURE
            safe_message = "unexpected provider failure"
            error_code = "unexpected_failure"
        return EnrichmentResult(
            indicator_id=indicator.id,
            indicator_value=indicator.indicator_value,
            indicator_type=indicator.indicator_type,
            provider=provider.name,
            status=status,
            error_message=safe_message[:1000],
            error_code=error_code,
            enriched_at=datetime.now(UTC),
        )

    def _ttl_for(
        self,
        result: EnrichmentResult,
        providers: list[EnrichmentProvider],
    ) -> timedelta:
        if result.status is EnrichmentStatus.RATE_LIMITED:
            return timedelta(seconds=settings.enrichment_rate_limit_retry_seconds)
        if result.status in {
            EnrichmentStatus.FAILED,
            EnrichmentStatus.TEMPORARY_FAILURE,
        }:
            return timedelta(seconds=settings.enrichment_failure_retry_seconds)
        if result.status is EnrichmentStatus.NOT_FOUND:
            return timedelta(seconds=settings.enrichment_not_found_ttl_seconds)
        provider = next(
            (candidate for candidate in providers if candidate.name == result.provider),
            None,
        )
        return timedelta(seconds=provider.ttl_seconds) if provider else self.ttl

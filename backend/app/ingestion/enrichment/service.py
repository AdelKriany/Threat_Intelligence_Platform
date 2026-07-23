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
)
from app.ingestion.enrichment.persistence import (
    find_current,
    result_from_record,
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
                else find_current(self.session, indicator.id, provider.name, now=now)
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
            result.expires_at = now + self.ttl
            upsert_result(self.session, result)
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
            status = EnrichmentStatus.AUTH_ERROR
            safe_message = "provider authentication was rejected"
        except ProviderRateLimitError:
            status = EnrichmentStatus.RATE_LIMITED
            safe_message = "provider rate limit exceeded"
        except EnrichmentError as exc:
            status = EnrichmentStatus.FAILED
            safe_message = str(exc) or "provider enrichment failed"
        except Exception:
            logger.exception(
                "Unexpected enrichment failure provider=%s indicator_id=%s",
                provider.name,
                indicator.id,
            )
            status = EnrichmentStatus.FAILED
            safe_message = "unexpected provider failure"
        return EnrichmentResult(
            indicator_id=indicator.id,
            indicator_value=indicator.indicator_value,
            indicator_type=indicator.indicator_type,
            provider=provider.name,
            status=status,
            error_message=safe_message[:1000],
            enriched_at=datetime.now(UTC),
        )

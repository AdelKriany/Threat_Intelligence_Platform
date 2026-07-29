from __future__ import annotations

from collections.abc import Iterable

from app.core.config import Settings, settings
from app.ingestion.enrichment.cache import RedisEnrichmentCache
from app.ingestion.enrichment.providers import (
    AbuseIPDBProvider,
    CISAKEVProvider,
    EPSSProvider,
    NVDProvider,
    VirusTotalProvider,
)
from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.models import IOCType


class ProviderRegistry:
    def __init__(self, providers: Iterable[EnrichmentProvider]) -> None:
        self.providers = list(providers)

    @classmethod
    def from_settings(cls, config: Settings = settings) -> ProviderRegistry:
        return cls(
            [
                NVDProvider(
                    enabled=config.enrichment_enabled and config.nvd_enabled,
                    api_key=config.nvd_api_key,
                    timeout=config.enrichment_request_timeout_seconds,
                    max_retries=config.enrichment_max_retries,
                    ttl_seconds=config.enrichment_ttl_seconds,
                    max_retry_delay_seconds=config.enrichment_retry_max_delay_seconds,
                    cache=RedisEnrichmentCache(config.redis_url),
                ),
                CISAKEVProvider(
                    enabled=config.enrichment_enabled and config.cisa_kev_enabled,
                    catalog_url=config.cisa_kev_catalog_url,
                    ttl_seconds=config.cisa_kev_ttl_seconds,
                    timeout=config.enrichment_request_timeout_seconds,
                    max_retries=config.enrichment_max_retries,
                    max_retry_delay_seconds=config.enrichment_retry_max_delay_seconds,
                ),
                EPSSProvider(
                    enabled=config.enrichment_enabled and config.epss_enabled,
                    api_url=config.epss_api_url,
                    batch_size=config.epss_batch_size,
                    ttl_seconds=config.epss_ttl_seconds,
                    timeout=config.enrichment_request_timeout_seconds,
                    max_retries=config.enrichment_max_retries,
                    max_retry_delay_seconds=config.enrichment_retry_max_delay_seconds,
                ),
                AbuseIPDBProvider(
                    enabled=config.enrichment_enabled and config.abuseipdb_enabled,
                    api_key=config.abuseipdb_api_key,
                    timeout=config.enrichment_request_timeout_seconds,
                    max_retries=config.enrichment_max_retries,
                ),
                VirusTotalProvider(
                    enabled=config.enrichment_enabled and config.virustotal_enabled,
                    api_key=config.virustotal_api_key,
                    timeout=config.enrichment_request_timeout_seconds,
                    max_retries=config.enrichment_max_retries,
                ),
            ]
        )

    def for_ioc_type(self, ioc_type: IOCType) -> list[EnrichmentProvider]:
        return [provider for provider in self.providers if provider.supports(ioc_type)]

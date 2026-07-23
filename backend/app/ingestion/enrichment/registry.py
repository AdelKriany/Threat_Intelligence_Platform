from __future__ import annotations

from collections.abc import Iterable

from app.core.config import Settings, settings
from app.ingestion.enrichment.providers import (
    AbuseIPDBProvider,
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

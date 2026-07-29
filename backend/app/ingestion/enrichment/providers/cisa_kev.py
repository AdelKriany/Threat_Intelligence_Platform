from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from app.ingestion.enrichment.cache import AsyncJSONCache, RedisEnrichmentCache
from app.ingestion.enrichment.exceptions import ProviderResponseError, ProviderTemporaryError
from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.ioc.validators import normalize_indicator
from app.ingestion.models import IOCType


@dataclass(frozen=True, slots=True)
class KEVCatalog:
    version: str | None
    date_released: str | None
    entries: dict[str, dict[str, Any]]


class CISAKEVProvider(EnrichmentProvider):
    name = "cisa_kev"
    supported_ioc_types = frozenset({IOCType.CVE})
    cache_key = "cisa-kev:catalog:v1"

    def __init__(
        self,
        *,
        enabled: bool = True,
        catalog_url: str,
        ttl_seconds: int,
        timeout: float = 10.0,
        max_retries: int = 2,
        max_retry_delay_seconds: float = 60.0,
        client: httpx.AsyncClient | None = None,
        cache: AsyncJSONCache | None = None,
        sleep: Any = asyncio.sleep,
    ) -> None:
        super().__init__(
            enabled=enabled,
            timeout=timeout,
            max_retries=max_retries,
            client=client,
            ttl_seconds=ttl_seconds,
            max_retry_delay_seconds=max_retry_delay_seconds,
            sleep=sleep,
        )
        self.catalog_url = catalog_url
        self.cache = cache or RedisEnrichmentCache()

    async def fetch_catalog(self, *, force_refresh: bool = False) -> KEVCatalog:
        if not force_refresh:
            cached = await self.cache.get_json(self.cache_key)
            if cached is not None:
                return self._parse_catalog(cached)

        token = await self.cache.acquire_lock(self.cache_key, min(self.ttl_seconds, 300))
        if token is None:
            for _ in range(5):
                await self._sleep(0.2)
                cached = await self.cache.get_json(self.cache_key)
                if cached is not None:
                    return self._parse_catalog(cached)
            raise ProviderTemporaryError("CISA KEV catalog refresh is already in progress")
        try:
            if not force_refresh:
                cached = await self.cache.get_json(self.cache_key)
                if cached is not None:
                    return self._parse_catalog(cached)
            payload = await self._get_json(self.catalog_url)
            catalog = self._parse_catalog(payload)
            await self.cache.set_json(self.cache_key, payload, self.ttl_seconds)
            return catalog
        finally:
            await self.cache.release_lock(self.cache_key, token)

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        results = await self.enrich_many([(indicator_id, indicator_value, ioc_type)])
        return results[indicator_id]

    async def enrich_many(
        self,
        indicators: list[tuple[int, str, IOCType]],
        *,
        force_catalog_refresh: bool = False,
    ) -> dict[int, EnrichmentResult]:
        catalog = await self.fetch_catalog(force_refresh=force_catalog_refresh)
        return {
            indicator_id: self._result_for(
                indicator_id,
                indicator_value,
                ioc_type,
                catalog,
            )
            for indicator_id, indicator_value, ioc_type in indicators
        }

    def normalize(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        payload: dict[str, Any],
    ) -> EnrichmentResult:
        return self._result_for(
            indicator_id,
            indicator_value,
            ioc_type,
            self._parse_catalog(payload),
        )

    def _parse_catalog(self, payload: dict[str, Any]) -> KEVCatalog:
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ProviderResponseError("CISA KEV catalog is missing vulnerabilities")
        entries: dict[str, dict[str, Any]] = {}
        for raw_entry in vulnerabilities:
            if not isinstance(raw_entry, dict):
                continue
            cve = raw_entry.get("cveID")
            normalized = normalize_indicator(IOCType.CVE, cve) if isinstance(cve, str) else None
            if normalized is not None:
                entries[normalized] = raw_entry
        if vulnerabilities and not entries:
            raise ProviderResponseError("CISA KEV catalog contains no valid CVE entries")
        return KEVCatalog(
            version=_string(payload.get("catalogVersion")),
            date_released=_string(payload.get("dateReleased")),
            entries=entries,
        )

    def _result_for(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        catalog: KEVCatalog,
    ) -> EnrichmentResult:
        normalized_cve = normalize_indicator(IOCType.CVE, indicator_value)
        if normalized_cve is None:
            raise ProviderResponseError("invalid CVE value")
        entry = catalog.entries.get(normalized_cve)
        normalized_data: dict[str, Any] = {
            "cve_id": normalized_cve,
            "known_exploited": entry is not None,
            "catalog_version": catalog.version,
            "catalog_date_released": catalog.date_released,
        }
        if entry is not None:
            normalized_data.update(
                {
                    "vendor_project": _string(entry.get("vendorProject")),
                    "product": _string(entry.get("product")),
                    "vulnerability_name": _string(entry.get("vulnerabilityName")),
                    "date_added": _string(entry.get("dateAdded")),
                    "short_description": _bounded(entry.get("shortDescription"), 4000),
                    "required_action": _bounded(entry.get("requiredAction"), 4000),
                    "due_date": _string(entry.get("dueDate")),
                    "known_ransomware_campaign_use": _string(
                        entry.get("knownRansomwareCampaignUse")
                    ),
                    "notes": _bounded(entry.get("notes"), 4000),
                }
            )
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=normalized_cve,
            indicator_type=ioc_type,
            provider=self.name,
            status=EnrichmentStatus.SUCCESS,
            summary=(
                "Listed in the CISA Known Exploited Vulnerabilities catalog"
                if entry is not None
                else "Not listed in the CISA Known Exploited Vulnerabilities catalog"
            ),
            normalized_data=normalized_data,
            enriched_at=datetime.now(UTC),
        )


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _bounded(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) else None

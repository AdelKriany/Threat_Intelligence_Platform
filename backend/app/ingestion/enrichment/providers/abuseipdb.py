from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import IOCType


class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    supported_ioc_types = frozenset({IOCType.IPV4, IOCType.IPV6})
    api_url = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        *,
        api_key: str | None,
        enabled: bool = True,
        timeout: float = 10.0,
        max_retries: int = 2,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            enabled=enabled and bool(api_key),
            timeout=timeout,
            max_retries=max_retries,
            client=client,
        )
        self._api_key = api_key

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        payload = await self._get_json(
            self.api_url,
            headers={"Key": self._api_key or "", "Accept": "application/json"},
            params={"ipAddress": indicator_value, "maxAgeInDays": 90, "verbose": ""},
        )
        return self.normalize(indicator_id, indicator_value, ioc_type, payload)

    def normalize(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        payload: dict[str, Any],
    ) -> EnrichmentResult:
        data = payload.get("data")
        if not isinstance(data, dict):
            return EnrichmentResult(
                indicator_id=indicator_id,
                indicator_value=indicator_value,
                indicator_type=ioc_type,
                provider=self.name,
                status=EnrichmentStatus.NOT_FOUND,
                raw_response=payload,
                enriched_at=datetime.now(UTC),
            )
        score = _score(data.get("abuseConfidenceScore"))
        normalized = {
            "ip_address": data.get("ipAddress") or indicator_value,
            "abuse_confidence_score": score,
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=indicator_value,
            indicator_type=ioc_type,
            provider=self.name,
            status=EnrichmentStatus.SUCCESS,
            risk_score=score,
            severity=_severity(score),
            summary=f"AbuseIPDB confidence score: {score}" if score is not None else None,
            normalized_data=normalized,
            raw_response=payload,
            enriched_at=datetime.now(UTC),
        )


def _score(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return min(max(float(value), 0.0), 100.0)
    return None


def _severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"

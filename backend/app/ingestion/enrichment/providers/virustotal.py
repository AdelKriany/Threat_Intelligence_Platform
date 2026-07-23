from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

import httpx

from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import IOCType


class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    supported_ioc_types = frozenset(
        {
            IOCType.IPV4,
            IOCType.IPV6,
            IOCType.DOMAIN,
            IOCType.URL,
            IOCType.MD5,
            IOCType.SHA1,
            IOCType.SHA256,
        }
    )
    api_base_url = "https://www.virustotal.com/api/v3"

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

    @staticmethod
    def url_identifier(value: str) -> str:
        """Return VirusTotal's unpadded URL-safe base64 identifier."""

        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        collection, object_id = self._lookup_target(indicator_value, ioc_type)
        payload = await self._get_json(
            f"{self.api_base_url}/{collection}/{object_id}",
            headers={"x-apikey": self._api_key or ""},
        )
        return self.normalize(indicator_id, indicator_value, ioc_type, payload)

    def _lookup_target(self, value: str, ioc_type: IOCType) -> tuple[str, str]:
        if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
            return "ip_addresses", value
        if ioc_type is IOCType.DOMAIN:
            return "domains", value
        if ioc_type is IOCType.URL:
            return "urls", self.url_identifier(value)
        if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
            return "files", value
        raise ValueError(f"unsupported IOC type for VirusTotal: {ioc_type.value}")

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
        attributes = data.get("attributes")
        attributes = attributes if isinstance(attributes, dict) else {}
        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        malicious = _integer(stats.get("malicious")) + _integer(stats.get("suspicious"))
        total = sum(_integer(value) for value in stats.values())
        risk_score = min((malicious / total) * 100, 100.0) if total else None
        categories = attributes.get("categories")
        if not isinstance(categories, (dict, list)):
            categories = {}
        normalized = {
            "analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags") if isinstance(attributes.get("tags"), list) else [],
            "categories": categories,
            "last_analysis_date": attributes.get("last_analysis_date"),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "meaningful_name": attributes.get("meaningful_name"),
            "names": attributes.get("names") if isinstance(attributes.get("names"), list) else [],
            "object_id": data.get("id"),
        }
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=indicator_value,
            indicator_type=ioc_type,
            provider=self.name,
            status=EnrichmentStatus.SUCCESS,
            risk_score=risk_score,
            severity=_severity(risk_score),
            summary=(f"{malicious} of {total} engines flagged this indicator" if total else None),
            normalized_data=normalized,
            raw_response=payload,
            enriched_at=datetime.now(UTC),
        )


def _integer(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 50:
        return "critical"
    if score >= 20:
        return "high"
    if score > 0:
        return "medium"
    return "clean"

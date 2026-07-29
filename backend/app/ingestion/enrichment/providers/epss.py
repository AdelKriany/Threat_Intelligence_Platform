from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from app.ingestion.enrichment.exceptions import ProviderResponseError
from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.ioc.validators import normalize_indicator
from app.ingestion.models import IOCType


@dataclass(frozen=True, slots=True)
class EPSSRecord:
    cve: str
    probability: Decimal
    percentile: Decimal
    model_date: str | None


class EPSSProvider(EnrichmentProvider):
    name = "epss"
    supported_ioc_types = frozenset({IOCType.CVE})

    def __init__(
        self,
        *,
        enabled: bool = True,
        api_url: str,
        batch_size: int,
        ttl_seconds: int,
        timeout: float = 10.0,
        max_retries: int = 2,
        max_retry_delay_seconds: float = 60.0,
        client: httpx.AsyncClient | None = None,
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
        self.api_url = api_url
        self.batch_size = max(1, min(batch_size, 100))

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        results = await self.enrich_many([(indicator_id, indicator_value, ioc_type)])
        return results[indicator_id]

    async def enrich_many(
        self, indicators: list[tuple[int, str, IOCType]]
    ) -> dict[int, EnrichmentResult]:
        results: dict[int, EnrichmentResult] = {}
        for offset in range(0, len(indicators), self.batch_size):
            chunk = indicators[offset : offset + self.batch_size]
            normalized: dict[str, list[tuple[int, str, IOCType]]] = {}
            for item in chunk:
                cve = normalize_indicator(IOCType.CVE, item[1])
                if cve is None:
                    results[item[0]] = self._missing_result(*item, invalid=True)
                else:
                    normalized.setdefault(cve, []).append(item)
            if not normalized:
                continue
            payload = await self._get_json(
                self.api_url,
                params={"cve": ",".join(normalized)},
            )
            records = self._parse_records(payload)
            for cve, items in normalized.items():
                record = records.get(cve)
                for item in items:
                    results[item[0]] = (
                        self._result_for(*item, record)
                        if record is not None
                        else self._missing_result(*item)
                    )
        return results

    def normalize(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        payload: dict[str, Any],
    ) -> EnrichmentResult:
        normalized_cve = normalize_indicator(IOCType.CVE, indicator_value)
        records = self._parse_records(payload)
        record = records.get(normalized_cve or "")
        return (
            self._result_for(indicator_id, indicator_value, ioc_type, record)
            if record is not None
            else self._missing_result(
                indicator_id,
                indicator_value,
                ioc_type,
                invalid=normalized_cve is None,
            )
        )

    def _parse_records(self, payload: dict[str, Any]) -> dict[str, EPSSRecord]:
        data = payload.get("data")
        if not isinstance(data, list):
            raise ProviderResponseError("EPSS response is missing data")
        records: dict[str, EPSSRecord] = {}
        for raw in data:
            if not isinstance(raw, dict):
                continue
            cve_value = raw.get("cve")
            cve = (
                normalize_indicator(IOCType.CVE, cve_value) if isinstance(cve_value, str) else None
            )
            if cve is None or cve in records:
                continue
            probability = _probability(raw.get("epss"))
            percentile = _probability(raw.get("percentile"))
            if probability is None or percentile is None:
                continue
            model_date = raw.get("date") or raw.get("created")
            records[cve] = EPSSRecord(
                cve=cve,
                probability=probability,
                percentile=percentile,
                model_date=model_date if isinstance(model_date, str) else None,
            )
        return records

    def _result_for(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        record: EPSSRecord,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=record.cve,
            indicator_type=ioc_type,
            provider=self.name,
            status=EnrichmentStatus.SUCCESS,
            summary=f"EPSS probability {record.probability}",
            normalized_data={
                "cve": record.cve,
                "epss": str(record.probability),
                "percentile": str(record.percentile),
                "model_date": record.model_date,
                "fetched_at": datetime.now(UTC).isoformat(),
            },
            enriched_at=datetime.now(UTC),
        )

    def _missing_result(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        *,
        invalid: bool = False,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=indicator_value,
            indicator_type=ioc_type,
            provider=self.name,
            status=(EnrichmentStatus.PERMANENT_FAILURE if invalid else EnrichmentStatus.NOT_FOUND),
            normalized_data={"cve": indicator_value.upper()},
            error_code="invalid_cve" if invalid else None,
            error_message="invalid CVE value" if invalid else None,
            enriched_at=datetime.now(UTC),
        )


def _probability(value: Any) -> Decimal | None:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if Decimal("0") <= parsed <= Decimal("1") else None

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import httpx

from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import IOCType


class NVDProvider(EnrichmentProvider):
    name = "nvd"
    supported_ioc_types = frozenset({IOCType.CVE})
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        *,
        enabled: bool = True,
        api_key: str | None = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(enabled=enabled, timeout=timeout, max_retries=max_retries, client=client)
        self._api_key = api_key

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        headers = {"apiKey": self._api_key} if self._api_key else None
        payload = await self._get_json(
            self.api_url,
            headers=headers,
            params={"cveId": indicator_value},
        )
        return self.normalize(indicator_id, indicator_value, ioc_type, payload)

    def normalize(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        payload: dict[str, Any],
    ) -> EnrichmentResult:
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return EnrichmentResult(
                indicator_id=indicator_id,
                indicator_value=indicator_value,
                indicator_type=ioc_type,
                provider=self.name,
                status=EnrichmentStatus.NOT_FOUND,
                raw_response=payload,
                enriched_at=datetime.now(UTC),
            )
        item = (
            cast(dict[str, Any], vulnerabilities[0]) if isinstance(vulnerabilities[0], dict) else {}
        )
        raw_cve = item.get("cve")
        cve = cast(dict[str, Any], raw_cve) if isinstance(raw_cve, dict) else {}
        raw_descriptions = cve.get("descriptions")
        descriptions = (
            cast(list[Any], raw_descriptions) if isinstance(raw_descriptions, list) else []
        )
        description = next(
            (
                entry.get("value")
                for entry in descriptions
                if isinstance(entry, dict)
                and entry.get("lang") == "en"
                and isinstance(entry.get("value"), str)
            ),
            None,
        )
        raw_metrics = cve.get("metrics")
        metrics = cast(dict[str, Any], raw_metrics) if isinstance(raw_metrics, dict) else {}
        metric: dict[str, Any] = {}
        cvss_version: str | None = None
        for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            candidates = cast(Any, metrics.get(metric_name))
            if isinstance(candidates, list) and candidates:
                chosen = next(
                    (
                        candidate
                        for candidate in candidates
                        if isinstance(candidate, dict) and candidate.get("type") == "Primary"
                    ),
                    candidates[0],
                )
                metric = cast(dict[str, Any], chosen) if isinstance(chosen, dict) else {}
                cvss_version = metric_name.removeprefix("cvssMetricV")
                break
        raw_cvss_data = metric.get("cvssData")
        cvss_data = cast(dict[str, Any], raw_cvss_data) if isinstance(raw_cvss_data, dict) else {}
        score = _number(cvss_data.get("baseScore"))
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        raw_references = cve.get("references")
        references = cast(list[Any], raw_references) if isinstance(raw_references, list) else []
        reference_urls = [
            entry["url"]
            for entry in references[:100]
            if isinstance(entry, dict) and isinstance(entry.get("url"), str)
        ]
        affected_cpes: list[str] = []
        configurations = cve.get("configurations")
        if isinstance(configurations, list):
            for configuration in configurations[:100]:
                if not isinstance(configuration, dict):
                    continue
                nodes = configuration.get("nodes", [])
                if not isinstance(nodes, list):
                    continue
                for node in nodes[:100]:
                    if not isinstance(node, dict):
                        continue
                    matches = node.get("cpeMatch", [])
                    if not isinstance(matches, list):
                        continue
                    for match in matches[:100]:
                        if isinstance(match, dict) and isinstance(match.get("criteria"), str):
                            affected_cpes.append(match["criteria"])
        normalized = {
            "cve_id": cve.get("id") or indicator_value,
            "description": description,
            "cvss_version": cvss_data.get("version") or cvss_version,
            "cvss_score": score,
            "severity": severity,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "reference_urls": reference_urls,
            "affected_cpes": affected_cpes[:500],
        }
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=indicator_value,
            indicator_type=ioc_type,
            provider=self.name,
            status=EnrichmentStatus.SUCCESS,
            risk_score=min(score * 10, 100.0) if score is not None else None,
            severity=str(severity).lower() if severity else None,
            summary=description,
            normalized_data=normalized,
            raw_response=payload,
            enriched_at=datetime.now(UTC),
        )


def _number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None

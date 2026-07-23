from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import httpx

from app.ingestion.enrichment.exceptions import (
    ProviderAuthenticationError,
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderTemporaryError,
)
from app.ingestion.enrichment.types import EnrichmentResult
from app.ingestion.models import IOCType


class EnrichmentProvider(ABC):
    """HTTP provider contract with bounded, status-aware request handling."""

    name: ClassVar[str]
    supported_ioc_types: ClassVar[frozenset[IOCType]]
    max_response_bytes: ClassVar[int] = 2_000_000

    def __init__(
        self,
        *,
        enabled: bool,
        timeout: float,
        max_retries: int,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._enabled = enabled
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self._client = client

    @property
    def enabled(self) -> bool:
        return self._enabled

    def supports(self, ioc_type: IOCType) -> bool:
        return self.enabled and ioc_type in self.supported_ioc_types

    @abstractmethod
    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        """Fetch and normalize one IOC."""

    @abstractmethod
    def normalize(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        payload: dict[str, Any],
    ) -> EnrichmentResult:
        """Normalize an already-decoded provider payload."""

    async def _get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str | int] | None = None,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                if self._client is not None:
                    response = await self._client.get(
                        url, headers=headers, params=params, timeout=self.timeout
                    )
                else:
                    async with httpx.AsyncClient(
                        timeout=self.timeout, follow_redirects=False
                    ) as client:
                        response = await client.get(url, headers=headers, params=params)
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(min(0.25 * (2**attempt), 1.0))
                    continue
                raise ProviderTemporaryError("provider request timed out or failed") from exc

            if response.status_code in {401, 403}:
                raise ProviderAuthenticationError("provider authentication was rejected")
            if response.status_code == 429:
                raise ProviderRateLimitError("provider rate limit exceeded")
            if 500 <= response.status_code:
                if attempt < self.max_retries:
                    await asyncio.sleep(min(0.25 * (2**attempt), 1.0))
                    continue
                raise ProviderTemporaryError(f"provider unavailable (HTTP {response.status_code})")
            if response.status_code == 404:
                return {}
            if response.status_code >= 400:
                raise ProviderResponseError(
                    f"provider rejected request (HTTP {response.status_code})"
                )

            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.max_response_bytes:
                        raise ProviderResponseError("provider response exceeded size limit")
                except ValueError:
                    pass
            if len(response.content) > self.max_response_bytes:
                raise ProviderResponseError("provider response exceeded size limit")
            try:
                payload = response.json()
            except (ValueError, TypeError) as exc:
                raise ProviderResponseError("provider returned malformed JSON") from exc
            if not isinstance(payload, dict):
                raise ProviderResponseError("provider returned an unexpected payload")
            return payload

        raise ProviderTemporaryError("provider request failed") from last_error

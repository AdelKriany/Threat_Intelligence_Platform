from __future__ import annotations

import asyncio
import random
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
        ttl_seconds: int = 86400,
        max_retry_delay_seconds: float = 60.0,
        sleep: Any = asyncio.sleep,
    ) -> None:
        self._enabled = enabled
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self._client = client
        self.ttl_seconds = ttl_seconds
        self.max_retry_delay_seconds = max_retry_delay_seconds
        self._sleep = sleep

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
        expected_content_types: tuple[str, ...] = ("application/json",),
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
                    await self._sleep(self._backoff(attempt))
                    continue
                raise ProviderTemporaryError("provider request timed out or failed") from exc

            if response.status_code in {401, 403}:
                raise ProviderAuthenticationError("provider authentication was rejected")
            if response.status_code == 429:
                retry_after = self._retry_after(response)
                if attempt < self.max_retries:
                    await self._sleep(
                        min(
                            retry_after if retry_after is not None else self._backoff(attempt),
                            self.max_retry_delay_seconds,
                        )
                    )
                    continue
                raise ProviderRateLimitError(
                    "provider rate limit exceeded",
                    retry_after=retry_after,
                )
            if 500 <= response.status_code:
                if attempt < self.max_retries:
                    await self._sleep(self._backoff(attempt))
                    continue
                raise ProviderTemporaryError(f"provider unavailable (HTTP {response.status_code})")
            if response.status_code == 404:
                return {}
            if response.status_code >= 400:
                raise ProviderResponseError(
                    f"provider rejected request (HTTP {response.status_code})"
                )

            content_type = response.headers.get("content-type", "").lower()
            if expected_content_types and not any(
                expected in content_type for expected in expected_content_types
            ):
                raise ProviderResponseError("provider returned an unexpected content type")

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

    def _backoff(self, attempt: int) -> float:
        base = min(0.5 * (2**attempt), self.max_retry_delay_seconds)
        return min(base + random.uniform(0, base * 0.25), self.max_retry_delay_seconds)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        value = response.headers.get("retry-after")
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            return None

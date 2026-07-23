from __future__ import annotations

import asyncio
import logging

import httpx

from app.ingestion.registry import FeedSource

logger = logging.getLogger(__name__)


class RSSClient:
    """Asynchronous RSS feed fetcher with retries and timeout handling."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 3,
        user_agent: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )

    async def fetch(self, source: FeedSource) -> str:
        """Fetch a single RSS feed and return its raw XML content."""

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
            "Accept-Language": "en-US,en;q=0.5",
        }

        last_error: Exception | None = None

        # Reuse the same HTTP client across all retry attempts
        async with httpx.AsyncClient(timeout=self.timeout) as client:

            for attempt in range(1, self.max_retries + 1):
                try:
                    logger.info(
                        "Fetching feed '%s' (attempt %d/%d)",
                        source.name,
                        attempt,
                        self.max_retries,
                    )

                    response = await client.get(source.url, headers=headers)
                    response.raise_for_status()

                    logger.info("Successfully fetched '%s'", source.name)

                    return response.text

                except (
                    httpx.HTTPError,
                    httpx.TimeoutException,
                ) as exc:

                    last_error = exc

                    logger.warning(
                        "Feed fetch failed | Feed='%s' | Attempt=%d/%d | Reason=%s",
                        source.name,
                        attempt,
                        self.max_retries,
                        str(exc),
                    )

                    if attempt < self.max_retries:
                        await asyncio.sleep(0.5 * attempt)

        # Final log after all retries have failed
        logger.error(
            "\n"
            "==================== Feed Fetch Failed ====================\n"
            "Feed   : %s\n"
            "URL    : %s\n"
            "Reason : %s\n"
            "Retries: %d/%d\n"
            "Action : Skipping feed (handled by caller)\n"
            "===========================================================\n",
            source.name,
            source.url,
            last_error,
            self.max_retries,
            self.max_retries,
        )

        raise RuntimeError(
            f"Unable to fetch '{source.name}' after {self.max_retries} attempts."
        ) from last_error

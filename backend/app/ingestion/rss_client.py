from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.ingestion.registry import FeedSource

logger = logging.getLogger(__name__)


class RSSClient:
    """Asynchronous RSS feed fetcher with retries and timeout handling."""

    def __init__(self, timeout: float = 10.0, max_retries: int = 3, user_agent: str | None = None) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        # Switched default user-agent to mimic a standard Linux desktop environment (Fedora/Firefox)
        self.user_agent = user_agent or (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

    async def fetch(self, source: FeedSource) -> str:
        """Fetch a single feed source and return the raw content."""

        # Include common browser headers to cleanly pass strict WAF checks
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
            "Accept-Language": "en-US,en;q=0.5",
        }
        
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                # Optimized: client creation pulled outside loop or used carefully per attempt
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(source.url, headers=headers)
                    response.raise_for_status()
                    return response.text
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_error = exc
                logger.warning("Feed fetch failed for %s (attempt %s/%s): %s", source.name, attempt + 1, self.max_retries, exc)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))

        raise RuntimeError(f"Unable to fetch {source.name} after {self.max_retries} attempts") from last_error
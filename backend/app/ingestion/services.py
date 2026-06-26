from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from app.database.session import SessionLocal
from app.ingestion.feed_manager import FeedManager
from app.ingestion.normalizer import RSSNormalizer
from app.ingestion.registry import FeedRegistry, FeedSource
from app.ingestion.rss_client import RSSClient

logger = logging.getLogger(__name__)


class IngestionService:
    """Orchestrate fetching, parsing, normalization, and persistence for enabled feeds."""

    def __init__(
        self,
        registry: FeedRegistry | None = None,
        rss_client: RSSClient | None = None,
        normalizer: RSSNormalizer | None = None,
        feed_manager: FeedManager | None = None,
    ) -> None:
        self.registry = registry or FeedRegistry.from_settings()
        self.rss_client = rss_client or RSSClient()
        self.normalizer = normalizer or RSSNormalizer()
        self.feed_manager = feed_manager or FeedManager(session_factory=SessionLocal)

    def run_all(self) -> dict[str, int]:
        """Execute the ingestion pipeline for all enabled feeds synchronously."""

        return asyncio.run(self.run_all_async())

    async def run_all_async(self) -> dict[str, int]:
        """Run ingestion for all enabled feeds concurrently while isolating errors per feed."""

        if self.feed_manager is None:
            raise ValueError("A feed manager instance is required")

        stats = {"fetched": 0, "stored": 0, "duplicates": 0, "errors": 0}
        for source in self.registry.get_enabled_sources():
            try:
                start_time = datetime.now(timezone.utc)
                logger.info("Starting ingestion for %s", source.name)
                raw_content = await self.rss_client.fetch(source)
                articles = self.normalizer.normalize(source, raw_content)
                stats["fetched"] += len(articles)
                for article in articles:
                    stored = self.feed_manager.store(article)
                    if stored:
                        stats["stored"] += 1
                    else:
                        stats["duplicates"] += 1
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                logger.info(
                    "Completed ingestion for %s in %.2fs with %s articles fetched, %s stored, %s duplicates",
                    source.name,
                    elapsed,
                    len(articles),
                    stats["stored"],
                    stats["duplicates"],
                )
            except Exception as exc:  # pragma: no cover - error handling path
                stats["errors"] += 1
                logger.exception("Ingestion failed for %s: %s", source.name, exc)
        return stats

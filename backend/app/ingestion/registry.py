from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any


@dataclass(slots=True)
class FeedSource:
    """Configuration for a single ingestion source."""

    name: str
    url: str
    poll_interval_minutes: int
    source_type: str = "rss"
    enabled: bool = True


class FeedRegistry:
    """Registry for all configured feed sources."""

    def __init__(self, sources: list[FeedSource] | None = None) -> None:
        self._sources = list(sources or [])

    @classmethod
    def from_settings(cls) -> "FeedRegistry":
        """Build the registry from environment configuration or defaults."""

        configured = os.getenv("INGESTION_FEEDS_JSON", "")
        if configured:
            payload = json.loads(configured)
            sources = [FeedSource(**item) for item in payload]
            return cls(sources)
        return cls(cls.default_sources())

    @classmethod
    def default_sources(cls) -> list[FeedSource]:
        """Provide sensible default RSS feeds for the initial platform."""

        return [
            FeedSource(
                name="The Hacker News",
                url="https://feeds.feedburner.com/TheHackersNews",
                poll_interval_minutes=30,
            ),
            FeedSource(
                name="BleepingComputer",
                url="https://www.bleepingcomputer.com/feed/",
                poll_interval_minutes=30,
            ),
            FeedSource(
                name="CISA Alerts",
                url="https://www.cisa.gov/uscert/ncas/alerts.xml",
                poll_interval_minutes=60,
            ),
            FeedSource(
                name="Microsoft Security Blog",
                url="https://www.microsoft.com/en-us/security/blog/feed/",
                poll_interval_minutes=60,
            ),
            FeedSource(
                name="Cisco Talos",
                url="https://talosintelligence.com/feed2.xml",
                poll_interval_minutes=60,
            ),
        ]

    def get_enabled_sources(self) -> list[FeedSource]:
        """Return only enabled sources."""

        return [source for source in self._sources if source.enabled]

    def add_source(self, source: FeedSource) -> None:
        """Register a new source."""

        self._sources.append(source)

    def to_dict(self) -> list[dict[str, Any]]:
        """Serialize feed sources for testing or diagnostics."""

        return [
            {
                "name": source.name,
                "url": source.url,
                "poll_interval_minutes": source.poll_interval_minutes,
                "source_type": source.source_type,
                "enabled": source.enabled,
            }
            for source in self._sources
        ]

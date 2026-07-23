from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from app.ingestion.models import NormalizedArticle
from app.ingestion.registry import FeedSource


class BaseRSSClient(ABC):
    """Interface for fetching raw feed content from a source."""

    @abstractmethod
    async def fetch(self, source: FeedSource) -> str:
        """Retrieve raw content for a feed source."""


class BaseNormalizer(ABC):
    """Interface for converting raw feed payloads into normalized articles."""

    @abstractmethod
    def normalize(self, source: FeedSource, raw_content: str) -> list[NormalizedArticle]:
        """Normalize raw content into domain objects."""


class BaseFeedManager(ABC):
    """Interface for storing normalized articles."""

    @abstractmethod
    def store(self, article: NormalizedArticle) -> tuple[bool, int]:
        """Persist a normalized article if it is new."""


class RSSClientProtocol(Protocol):
    """Protocol for RSS clients consumed by ingestion service."""

    async def fetch(self, source: FeedSource) -> str:
        """Retrieve raw content for a feed source."""

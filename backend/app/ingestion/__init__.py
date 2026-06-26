"""Ingestion engine package for ThreatLens."""

from app.ingestion.feed_manager import FeedManager
from app.ingestion.models import NormalizedArticle
from app.ingestion.registry import FeedRegistry, FeedSource
from app.ingestion.services import IngestionService

__all__ = [
    "FeedManager",
    "FeedRegistry",
    "FeedSource",
    "IngestionService",
    "NormalizedArticle",
]

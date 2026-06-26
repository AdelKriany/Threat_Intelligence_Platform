from __future__ import annotations

import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser

from app.ingestion.models import NormalizedArticle
from app.ingestion.registry import FeedSource

logger = logging.getLogger(__name__)


class RSSNormalizer:
    """Normalize RSS/Atom content into a common article shape."""

    def normalize(self, source: FeedSource, raw_content: str) -> list[NormalizedArticle]:
        """Parse feed content and return normalized article objects."""

        parsed = feedparser.parse(raw_content)
        articles: list[NormalizedArticle] = []
        for entry in parsed.entries:
            published_at = self._coerce_datetime(entry.get("published")) or self._coerce_datetime(entry.get("updated"))
            title = self._safe_text(entry.get("title"))
            description = self._safe_text(entry.get("summary") or entry.get("description"))
            url = self._safe_text(entry.get("link"))
            author = self._safe_text(entry.get("author"))
            categories = [self._safe_text(tag.get("term")) for tag in entry.get("tags", []) if self._safe_text(tag.get("term"))]
            articles.append(
                NormalizedArticle(
                    source_id=source.name,
                    title=title or "Untitled article",
                    description=description,
                    url=url,
                    published_at=published_at,
                    author=author,
                    categories=categories,
                    source_name=source.name,
                    raw_content=raw_content,
                )
            )
        return articles

    def _coerce_datetime(self, value: Any) -> datetime | None:
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
            parsed = parsedate_to_datetime(value)
            if parsed is not None:
                return parsed
            return None
        return None

    def _safe_text(self, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value.strip() or None
        return str(value)

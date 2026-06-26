from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ingestion.models import NormalizedArticle, RawArticle
from app.ingestion.registry import FeedSource

logger = logging.getLogger(__name__)


class FeedManager:
    """Persistence and duplicate management for ingested articles."""

    def __init__(self, session_factory: Any) -> None:
        self.session_factory = session_factory

    def store(self, article: NormalizedArticle) -> bool:
        """Persist a normalized article if it is not a duplicate."""

        content_hash = self._content_hash(article)
        with self.session_factory() as session:
            existing = session.scalar(select(RawArticle).where(RawArticle.content_hash == content_hash))
            if existing is not None:
                return False

            raw_article = RawArticle(
                source_id=article.source_id,
                source_name=article.source_name,
                title=article.title,
                description=article.description,
                url=article.url,
                published_at=article.published_at,
                fetched_at=datetime.now(timezone.utc),
                raw_content=article.raw_content,
                content_hash=content_hash,
                author=article.author,
                categories=",".join(article.categories) if article.categories else None,
                created_at=datetime.now(timezone.utc),
            )
            session.add(raw_article)
            session.commit()
            return True

    def _content_hash(self, article: NormalizedArticle) -> str:
        seed = article.url or article.title or article.description or ""
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def count(self) -> int:
        """Return the number of stored raw articles."""

        with self.session_factory() as session:
            result = session.scalar(select(func.count(RawArticle.id)))
            return int(result or 0)

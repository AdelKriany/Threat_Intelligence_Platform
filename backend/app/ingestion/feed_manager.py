from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from app.ingestion.ioc.extractor import IOCExtractionService
from app.ingestion.ioc.persistence import persist_indicators
from app.ingestion.models import NormalizedArticle, RawArticle

logger = logging.getLogger(__name__)


class FeedManager:
    """Persistence and duplicate management for ingested articles."""

    def __init__(
        self,
        session_factory: Any,
        ioc_extractor: IOCExtractionService | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.ioc_extractor = ioc_extractor or IOCExtractionService()

    def store(self, article: NormalizedArticle) -> tuple[bool, int]:
        """Persist a normalized article if it is not a duplicate.

        Returns a tuple containing whether the article was stored and the number of IOC
        records extracted for that article.
        """

        content_hash = self._content_hash(article)
        with self.session_factory() as session:
            existing = session.scalar(
                select(RawArticle).where(RawArticle.content_hash == content_hash)
            )
            if existing is not None:
                logger.info("Skipped duplicate article content_hash=%s", content_hash)
                return False, 0

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
            # Flush and commit first so raw article persistence is isolated from IOC failures.
            session.flush()
            raw_article_id = raw_article.id
            session.commit()
            logger.info("Stored article id=%s", raw_article_id)

            try:
                extracted_indicators = self.ioc_extractor.extract(raw_article)
            except Exception:
                logger.exception("IOC extraction failed for raw_article_id=%s", raw_article_id)
                return True, 0

            logger.info(
                "Extracted %d IOCs for raw_article_id=%s",
                len(extracted_indicators),
                raw_article_id,
            )

            if not extracted_indicators:
                return True, 0

            try:
                persisted_count = persist_indicators(session, raw_article_id, extracted_indicators)
                session.commit()
            except Exception:
                session.rollback()
                logger.exception(
                    "Indicator persistence failed for raw_article_id=%s", raw_article_id
                )
                return True, 0

            logger.info(
                "Persisted %d indicators for raw_article_id=%s", persisted_count, raw_article_id
            )

            return True, persisted_count

    def _content_hash(self, article: NormalizedArticle) -> str:
        seed = article.url or article.title or article.description or ""
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def count(self) -> int:
        """Return the number of stored raw articles."""

        with self.session_factory() as session:
            result = session.scalar(select(func.count(RawArticle.id)))
            return int(result or 0)

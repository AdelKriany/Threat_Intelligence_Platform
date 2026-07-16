from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion.ioc.types import ExtractedIndicator
from app.ingestion.models import Indicator, RawArticle


def persist_indicators(
    session: Session,
    raw_article: RawArticle,
    extracted_indicators: Iterable[ExtractedIndicator],
) -> int:
    """Persist non-duplicate extracted indicators for one article."""

    existing = {
        (indicator_type, indicator_value)
        for indicator_type, indicator_value in session.execute(
            select(Indicator.indicator_type, Indicator.indicator_value).where(
                Indicator.raw_article_id == raw_article.id
            )
        )
    }

    created_count = 0
    for extracted in extracted_indicators:
        key = (extracted.indicator_type, extracted.indicator_value)
        if key in existing:
            continue

        session.add(
            Indicator(
                raw_article_id=raw_article.id,
                indicator_type=extracted.indicator_type,
                indicator_value=extracted.indicator_value,
            )
        )
        existing.add(key)
        created_count += 1

    return created_count

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.ingestion.ioc.types import ExtractedIndicator
from app.ingestion.models import Indicator, IOCType


def persist_indicators(
    session: Session,
    raw_article_id: int,
    extracted_indicators: Iterable[ExtractedIndicator],
) -> int:
    """Persist non-duplicate extracted indicators for one article."""

    seen: set[tuple[IOCType, str]] = set()
    indicators_to_add: list[Indicator] = []
    created_count = 0
    for extracted in extracted_indicators:
        key = (extracted.indicator_type, extracted.indicator_value)
        if key in seen:
            continue

        indicators_to_add.append(
            Indicator(
                raw_article_id=raw_article_id,
                indicator_type=extracted.indicator_type,
                indicator_value=extracted.indicator_value,
            )
        )
        seen.add(key)
        created_count += 1

    if indicators_to_add:
        session.add_all(indicators_to_add)

    return created_count

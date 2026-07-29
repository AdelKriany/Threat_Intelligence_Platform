from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select, tuple_
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.ingestion.ioc.types import ExtractedIndicator
from app.ingestion.ioc.validators import normalize_indicator
from app.ingestion.models import ArticleIndicator, Indicator, IOCType


def persist_indicators(
    session: Session,
    raw_article_id: int,
    extracted_indicators: Iterable[ExtractedIndicator],
) -> int:
    """Atomically upsert canonical indicators and unique article associations."""

    identities: set[tuple[IOCType, str]] = set()
    for extracted in extracted_indicators:
        normalized = normalize_indicator(
            extracted.indicator_type,
            extracted.indicator_value,
        )
        if normalized is not None:
            identities.add((extracted.indicator_type, normalized))
    if not identities:
        return 0

    values = [
        {"indicator_type": indicator_type, "indicator_value": indicator_value}
        for indicator_type, indicator_value in sorted(
            identities, key=lambda item: (item[0].value, item[1])
        )
    ]
    dialect_name = session.get_bind().dialect.name
    if dialect_name == "postgresql":
        pg_indicator_insert = postgresql_insert(Indicator).values(values)
        session.execute(
            pg_indicator_insert.on_conflict_do_nothing(constraint="uq_indicators_type_value")
        )
    elif dialect_name == "sqlite":
        sqlite_indicator_insert = sqlite_insert(Indicator).values(values)
        session.execute(
            sqlite_indicator_insert.on_conflict_do_nothing(
                index_elements=["indicator_type", "indicator_value"]
            )
        )
    else:
        # Tests and production use SQLite and PostgreSQL respectively. This fallback
        # retains correctness for other dialects in single-writer environments.
        existing = set(
            session.execute(
                select(Indicator.indicator_type, Indicator.indicator_value).where(
                    tuple_(Indicator.indicator_type, Indicator.indicator_value).in_(identities)
                )
            )
        )
        session.add_all(
            Indicator(indicator_type=indicator_type, indicator_value=indicator_value)
            for indicator_type, indicator_value in identities - existing
        )
        session.flush()

    canonical_rows = session.execute(
        select(Indicator.id, Indicator.indicator_type, Indicator.indicator_value).where(
            tuple_(Indicator.indicator_type, Indicator.indicator_value).in_(identities)
        )
    ).all()
    association_values = [
        {"raw_article_id": raw_article_id, "indicator_id": indicator_id}
        for indicator_id, _indicator_type, _indicator_value in canonical_rows
    ]
    if not association_values:
        return 0

    if dialect_name == "postgresql":
        pg_association_insert = postgresql_insert(ArticleIndicator).values(association_values)
        result = session.execute(
            pg_association_insert.on_conflict_do_nothing(
                index_elements=["raw_article_id", "indicator_id"]
            )
        )
    elif dialect_name == "sqlite":
        sqlite_association_insert = sqlite_insert(ArticleIndicator).values(association_values)
        result = session.execute(
            sqlite_association_insert.on_conflict_do_nothing(
                index_elements=["raw_article_id", "indicator_id"]
            )
        )
    else:
        existing_ids = set(
            session.scalars(
                select(ArticleIndicator.indicator_id).where(
                    ArticleIndicator.raw_article_id == raw_article_id,
                    ArticleIndicator.indicator_id.in_(
                        value["indicator_id"] for value in association_values
                    ),
                )
            )
        )
        missing = [
            value for value in association_values if value["indicator_id"] not in existing_ids
        ]
        session.add_all(ArticleIndicator(**value) for value in missing)
        return len(missing)

    return max(int(getattr(result, "rowcount", 0) or 0), 0)

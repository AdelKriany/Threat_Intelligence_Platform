from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.enrichment.registry import ProviderRegistry
from app.ingestion.enrichment.tasks import article_has_pending_enrichment
from app.ingestion.ioc.persistence import persist_indicators
from app.ingestion.ioc.types import ExtractedIndicator
from app.ingestion.models import (
    ArticleIndicator,
    Indicator,
    IndicatorEnrichment,
    IOCType,
    RawArticle,
)


@pytest.fixture()
def canonical_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _article(session: Session, suffix: str) -> RawArticle:
    article = RawArticle(
        source_id=suffix,
        title=suffix,
        fetched_at=datetime.now(UTC),
        content_hash=f"canonical-{suffix}",
    )
    session.add(article)
    session.flush()
    return article


def test_same_cve_has_one_canonical_row_and_two_mentions(
    canonical_factory: sessionmaker[Session],
) -> None:
    with canonical_factory() as session:
        first = _article(session, "first")
        second = _article(session, "second")
        extracted = [ExtractedIndicator(IOCType.CVE, "cve-2026-12345")]

        assert persist_indicators(session, first.id, extracted) == 1
        assert persist_indicators(session, second.id, extracted) == 1
        session.commit()

        indicator = session.scalar(select(Indicator))
        assert indicator is not None
        assert indicator.indicator_value == "CVE-2026-12345"
        assert {article.id for article in indicator.articles} == {first.id, second.id}
        assert session.scalar(select(func.count(ArticleIndicator.indicator_id))) == 2


def test_duplicate_extraction_is_idempotent_per_article(
    canonical_factory: sessionmaker[Session],
) -> None:
    with canonical_factory() as session:
        article = _article(session, "duplicate")
        extracted = [
            ExtractedIndicator(IOCType.CVE, "CVE-2026-12345"),
            ExtractedIndicator(IOCType.CVE, "cve-2026-12345"),
        ]

        assert persist_indicators(session, article.id, extracted) == 1
        assert persist_indicators(session, article.id, extracted) == 0
        session.commit()
        assert session.scalar(select(func.count(Indicator.id))) == 1
        assert session.scalar(select(func.count(ArticleIndicator.indicator_id))) == 1


def test_indicator_type_is_part_of_canonical_identity(
    canonical_factory: sessionmaker[Session],
) -> None:
    with canonical_factory() as session:
        session.add_all(
            [
                Indicator(indicator_type=IOCType.DOMAIN, indicator_value="example.test"),
                Indicator(indicator_type=IOCType.URL, indicator_value="example.test"),
            ]
        )
        session.commit()
        assert session.scalar(select(func.count(Indicator.id))) == 2


def test_database_enforces_canonical_and_association_uniqueness(
    canonical_factory: sessionmaker[Session],
) -> None:
    with canonical_factory() as session:
        article = _article(session, "constraints")
        indicator = Indicator(
            indicator_type=IOCType.CVE,
            indicator_value="CVE-2026-12345",
        )
        session.add(indicator)
        session.flush()
        session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))
        session.commit()

        session.add(
            Indicator(
                indicator_type=IOCType.CVE,
                indicator_value="CVE-2026-12345",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))
        with pytest.raises(IntegrityError):
            session.commit()


def test_deleting_article_preserves_indicator_shared_by_another_article(
    canonical_factory: sessionmaker[Session],
) -> None:
    with canonical_factory() as session:
        first = _article(session, "delete-first")
        second = _article(session, "delete-second")
        extracted = [ExtractedIndicator(IOCType.CVE, "CVE-2026-12345")]
        persist_indicators(session, first.id, extracted)
        persist_indicators(session, second.id, extracted)
        session.commit()

        session.delete(first)
        session.commit()

        indicator = session.scalar(select(Indicator))
        assert indicator is not None
        assert [article.id for article in indicator.articles] == [second.id]
        assert session.scalar(select(func.count(ArticleIndicator.indicator_id))) == 1


def test_current_shared_indicator_does_not_need_duplicate_dispatch(
    canonical_factory: sessionmaker[Session],
) -> None:
    with canonical_factory() as session:
        article = _article(session, "current")
        persist_indicators(
            session,
            article.id,
            [ExtractedIndicator(IOCType.CVE, "CVE-2026-12345")],
        )
        session.flush()
        indicator = session.scalar(select(Indicator))
        assert indicator is not None
        now = datetime.now(UTC)
        providers = ProviderRegistry.from_settings().for_ioc_type(IOCType.CVE)
        session.add_all(
            IndicatorEnrichment(
                indicator_id=indicator.id,
                provider=provider.name,
                status="success",
                normalized_data={},
                enriched_at=now,
                expires_at=now + timedelta(hours=1),
            )
            for provider in providers
        )
        session.commit()

        assert article_has_pending_enrichment(session, article.id) is False

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.models import (
    ArticleIndicator,
    Indicator,
    IndicatorEnrichment,
    IOCType,
    RawArticle,
)
from app.models.phase6b import (
    CorrelatedEvent,
    EventArticle,
    EventIndicator,
    ScoreHistory,
)
from app.services.cve_correlation import (
    RELATIONSHIP_REASON,
    RULE_NAME,
    RULE_VERSION,
    CorrelationIndicatorNotFoundError,
    CorrelationInvariantError,
    InvalidCVEIndicatorError,
    UnsupportedCorrelationIndicatorError,
    correlate_cve_indicator,
)

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


@pytest.fixture()
def correlation_database() -> Generator[tuple[Engine, sessionmaker[Session]], None, None]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine, sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def _indicator(session: Session, value: str, ioc_type: IOCType = IOCType.CVE) -> Indicator:
    indicator = Indicator(indicator_type=ioc_type, indicator_value=value)
    session.add(indicator)
    session.flush()
    return indicator


def _article(session: Session, suffix: str) -> RawArticle:
    article = RawArticle(
        source_id=f"correlation-{suffix}",
        source_name=f"Source {suffix}",
        title=f"Article {suffix}",
        fetched_at=NOW,
        content_hash=f"correlation-{suffix}",
    )
    session.add(article)
    session.flush()
    return article


def _link(session: Session, article: RawArticle, *indicators: Indicator) -> None:
    session.add_all(
        ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id)
        for indicator in indicators
    )


def test_multiple_articles_create_one_event_and_fixed_relationship_metadata(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71001")
        first = _article(session, "one")
        second = _article(session, "two")
        _link(session, first, indicator)
        _link(session, second, indicator)
        session.commit()

        result = correlate_cve_indicator(session, indicator.id, as_of=NOW)
        session.commit()

        assert result.event_created is True
        assert result.indicator_link_created is True
        assert result.article_link_ids_created == (first.id, second.id)
        assert result.article_links_created == 2
        assert result.event.event_key == "cve:CVE-2026-71001"
        assert result.event.title == "CVE-2026-71001 vulnerability"
        assert result.event.rule_name == RULE_NAME == "shared-cve"
        assert result.event.rule_version == RULE_VERSION == "v1"
        indicator_link = session.scalar(select(EventIndicator))
        assert indicator_link is not None
        assert indicator_link.reason == RELATIONSHIP_REASON == "shared_canonical_cve"
        assert indicator_link.rule_name == RULE_NAME
        assert indicator_link.rule_version == RULE_VERSION
        article_links = tuple(
            session.scalars(select(EventArticle).order_by(EventArticle.article_id))
        )
        assert [link.article_id for link in article_links] == [first.id, second.id]
        assert {link.reason for link in article_links} == {RELATIONSHIP_REASON}
        assert {link.rule_name for link in article_links} == {RULE_NAME}
        assert {link.rule_version for link in article_links} == {RULE_VERSION}


def test_repeated_calls_reuse_event_and_all_links(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71002")
        article = _article(session, "repeat")
        _link(session, article, indicator)
        session.commit()

        first = correlate_cve_indicator(session, indicator.id, as_of=NOW)
        session.commit()
        original_updated_at = first.event.updated_at
        second = correlate_cve_indicator(session, indicator.id, as_of=NOW + timedelta(hours=1))
        session.commit()

        assert second.event.id == first.event.id
        assert second.event_created is False
        assert second.indicator_link_created is False
        assert second.article_link_ids_created == ()
        assert second.event.updated_at == original_updated_at
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 1
        assert session.scalar(select(func.count()).select_from(EventIndicator)) == 1
        assert session.scalar(select(func.count()).select_from(EventArticle)) == 1


def test_new_article_is_added_to_existing_event_and_advances_updated_at(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71003")
        first = _article(session, "existing")
        _link(session, first, indicator)
        session.commit()
        created = correlate_cve_indicator(session, indicator.id, as_of=NOW)
        session.commit()

        second = _article(session, "new")
        _link(session, second, indicator)
        session.commit()
        later = NOW + timedelta(days=1)
        extended = correlate_cve_indicator(session, indicator.id, as_of=later)
        session.commit()

        assert extended.event.id == created.event.id
        assert extended.event_created is False
        assert extended.indicator_link_created is False
        assert extended.article_link_ids_created == (second.id,)
        assert extended.event.updated_at == later
        assert session.scalar(select(func.count()).select_from(EventArticle)) == 2


def test_one_article_with_multiple_cves_links_to_separate_events(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        first_cve = _indicator(session, "CVE-2026-71004")
        second_cve = _indicator(session, "CVE-2026-71005")
        article = _article(session, "multi")
        _link(session, article, first_cve, second_cve)
        session.commit()

        first = correlate_cve_indicator(session, first_cve.id, as_of=NOW)
        second = correlate_cve_indicator(session, second_cve.id, as_of=NOW)
        session.commit()

        assert first.event.id != second.event.id
        assert {first.event.event_key, second.event.event_key} == {
            "cve:CVE-2026-71004",
            "cve:CVE-2026-71005",
        }
        links = tuple(session.scalars(select(EventArticle)))
        assert len(links) == 2
        assert {link.event_id for link in links} == {first.event.id, second.event.id}
        assert {link.article_id for link in links} == {article.id}


def test_valid_cve_without_articles_creates_event_and_indicator_link(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71006")
        session.commit()

        result = correlate_cve_indicator(session, indicator.id, as_of=NOW)
        session.commit()

        assert result.event_created is True
        assert result.indicator_link_created is True
        assert result.article_link_ids_created == ()
        assert session.scalar(select(func.count()).select_from(EventArticle)) == 0
        assert session.scalar(select(func.count()).select_from(EventIndicator)) == 1


def test_missing_indicator_is_explicit(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session, pytest.raises(CorrelationIndicatorNotFoundError):
        correlate_cve_indicator(session, 999_999, as_of=NOW)


def test_non_cve_indicator_is_explicit(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "example.com", IOCType.DOMAIN)
        session.commit()
        with pytest.raises(UnsupportedCorrelationIndicatorError):
            correlate_cve_indicator(session, indicator.id, as_of=NOW)
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 0


@pytest.mark.parametrize("value", ["cve-2026-71007", "CVE-26-7", "not-a-cve"])
def test_invalid_or_noncanonical_cve_is_explicit(
    correlation_database: tuple[Engine, sessionmaker[Session]],
    value: str,
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, value)
        session.commit()
        with pytest.raises(InvalidCVEIndicatorError):
            correlate_cve_indicator(session, indicator.id, as_of=NOW)
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 0


def test_existing_event_with_incompatible_metadata_is_not_modified(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71008")
        event_row = CorrelatedEvent(
            event_key="cve:CVE-2026-71008",
            title="Wrong title",
            rule_name="other-rule",
            rule_version="v9",
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(event_row)
        session.commit()

        with pytest.raises(CorrelationInvariantError):
            correlate_cve_indicator(session, indicator.id, as_of=NOW)
        session.rollback()

        stored = session.get(CorrelatedEvent, event_row.id)
        assert stored is not None
        assert stored.title == "Wrong title"
        assert session.scalar(select(func.count()).select_from(EventIndicator)) == 0


def test_caller_rollback_removes_only_correlation_changes(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71009")
        article = _article(session, "rollback")
        _link(session, article, indicator)
        session.commit()
        indicator_id = indicator.id
        article_id = article.id

        correlate_cve_indicator(session, indicator_id, as_of=NOW)
        session.rollback()

        assert session.get(Indicator, indicator_id) is not None
        assert session.get(RawArticle, article_id) is not None
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 0
        assert session.scalar(select(func.count()).select_from(EventIndicator)) == 0
        assert session.scalar(select(func.count()).select_from(EventArticle)) == 0


def test_correlation_preserves_existing_enrichment_and_score_history(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = correlation_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-71012")
        enrichment = IndicatorEnrichment(
            indicator_id=indicator.id,
            provider="nvd",
            status="success",
            normalized_data={"cvss_score": 8.0},
            enriched_at=NOW,
            expires_at=NOW + timedelta(days=1),
        )
        score = ScoreHistory(
            target_kind="indicator",
            indicator_id=indicator.id,
            event_id=None,
            score=Decimal("42.00"),
            severity="medium",
            formula_version="phase6b-v1",
            evidence_hash="a" * 64,
            canonical_evidence={"existing": True},
            calculated_at=NOW,
        )
        session.add_all([enrichment, score])
        session.commit()
        enrichment_id = enrichment.id
        score_id = score.id

        correlate_cve_indicator(session, indicator.id, as_of=NOW)
        session.commit()

        assert session.get(IndicatorEnrichment, enrichment_id) is not None
        assert session.get(ScoreHistory, score_id) is not None
        assert session.scalar(select(func.count()).select_from(IndicatorEnrichment)) == 1
        assert session.scalar(select(func.count()).select_from(ScoreHistory)) == 1


def test_query_count_is_constant_in_article_count(
    correlation_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    engine, factory = correlation_database
    with factory() as session:
        one_article = _indicator(session, "CVE-2026-71010")
        first = _article(session, "query-one")
        _link(session, first, one_article)
        three_articles = _indicator(session, "CVE-2026-71011")
        for suffix in ("query-two", "query-three", "query-four"):
            _link(session, _article(session, suffix), three_articles)
        session.commit()

        statements: list[str] = []

        @event.listens_for(engine, "before_cursor_execute")
        def _record_statement(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(statement)

        correlate_cve_indicator(session, one_article.id, as_of=NOW)
        one_count = len(statements)
        session.commit()
        statements.clear()
        correlate_cve_indicator(session, three_articles.id, as_of=NOW)
        three_count = len(statements)

        assert one_count == three_count == 6

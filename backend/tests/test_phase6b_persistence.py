from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import create_engine, event, func, insert, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.models import Indicator, IOCType, RawArticle
from app.models.phase6b import (
    CorrelatedEvent,
    EventArticle,
    EventIndicator,
    ScoreComponentRecord,
    ScoreHistory,
    _utc_now,
)

NOW = datetime(2026, 8, 17, 12, tzinfo=UTC)


@pytest.fixture()
def phase6b_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _seed_targets(
    session: Session, suffix: str = "one"
) -> tuple[RawArticle, Indicator, CorrelatedEvent]:
    article = RawArticle(
        source_id=f"phase6b-{suffix}",
        title=f"Article {suffix}",
        fetched_at=NOW,
        content_hash=f"phase6b-{suffix}",
    )
    indicator = Indicator(
        indicator_type=IOCType.CVE,
        indicator_value=f"CVE-2026-{10000 + len(suffix)}",
    )
    correlated_event = CorrelatedEvent(
        event_key=f"cve:{indicator.indicator_value}:{suffix}",
        title=f"Event {suffix}",
        rule_name="shared-cve",
        rule_version="v1",
    )
    session.add_all([article, indicator, correlated_event])
    session.flush()
    return article, indicator, correlated_event


def _score(
    *,
    target_kind: str,
    indicator_id: int | None = None,
    event_id: int | None = None,
    evidence_hash: str = "a" * 64,
    formula_version: str = "phase6b-v1",
    score: Decimal = Decimal("42.25"),
) -> ScoreHistory:
    return ScoreHistory(
        target_kind=target_kind,
        indicator_id=indicator_id,
        event_id=event_id,
        score=score,
        severity="medium",
        formula_version=formula_version,
        evidence_hash=evidence_hash,
        canonical_evidence={"provider": {"value": "0.125"}, "sources": ["alpha", "beta"]},
        calculated_at=NOW,
    )


def test_phase6b_tables_columns_foreign_keys_and_indexes_exist(
    phase6b_factory: sessionmaker[Session],
) -> None:
    inspector = inspect(phase6b_factory.kw["bind"])
    assert {
        "correlated_events",
        "event_articles",
        "event_indicators",
        "score_history",
        "score_components",
    }.issubset(inspector.get_table_names())
    assert {column["name"] for column in inspector.get_columns("score_history")} == {
        "id",
        "target_kind",
        "indicator_id",
        "event_id",
        "score",
        "severity",
        "formula_version",
        "evidence_hash",
        "canonical_evidence",
        "calculated_at",
    }
    assert {index["name"] for index in inspector.get_indexes("score_history")} == {
        "ix_score_history_event_calculated_at",
        "ix_score_history_indicator_calculated_at",
        "ix_score_history_ranked",
        "uq_score_history_event_evidence",
        "uq_score_history_indicator_evidence",
    }
    assert {index["name"] for index in inspector.get_indexes("event_articles")} == {
        "ix_event_articles_article_event"
    }
    assert {index["name"] for index in inspector.get_indexes("event_indicators")} == {
        "ix_event_indicators_indicator_rule_event"
    }
    for table_name in ("event_articles", "event_indicators", "score_history", "score_components"):
        assert all(
            foreign_key["options"].get("ondelete") == "CASCADE"
            for foreign_key in inspector.get_foreign_keys(table_name)
        )


def test_event_and_relationship_uniqueness_rolls_back_cleanly(
    phase6b_factory: sessionmaker[Session],
) -> None:
    with phase6b_factory() as session:
        article, indicator, correlated_event = _seed_targets(session)
        session.add_all(
            [
                EventArticle(
                    event_id=correlated_event.id,
                    article_id=article.id,
                    reason="shared_canonical_cve",
                    rule_name="shared-cve",
                    rule_version="v1",
                ),
                EventIndicator(
                    event_id=correlated_event.id,
                    indicator_id=indicator.id,
                    reason="shared_canonical_cve",
                    rule_name="shared-cve",
                    rule_version="v1",
                ),
            ]
        )
        session.commit()

        session.add(
            CorrelatedEvent(
                event_key=correlated_event.event_key,
                title="Duplicate",
                rule_name="shared-cve",
                rule_version="v1",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 1

        with pytest.raises(IntegrityError):
            session.execute(
                insert(EventArticle).values(
                    event_id=correlated_event.id,
                    article_id=article.id,
                    reason="duplicate",
                    rule_name="shared-cve",
                    rule_version="v1",
                )
            )
        session.rollback()

        with pytest.raises(IntegrityError):
            session.execute(
                insert(EventIndicator).values(
                    event_id=correlated_event.id,
                    indicator_id=indicator.id,
                    reason="duplicate",
                    rule_name="shared-cve",
                    rule_version="v1",
                )
            )
        session.rollback()
        assert session.scalar(select(func.count(EventArticle.event_id))) == 1
        assert session.scalar(select(func.count(EventIndicator.event_id))) == 1


@pytest.mark.parametrize(
    "score",
    [Decimal("-0.01"), Decimal("100.01")],
)
def test_score_bounds_are_database_enforced(
    phase6b_factory: sessionmaker[Session], score: Decimal
) -> None:
    with phase6b_factory() as session:
        _, indicator, _ = _seed_targets(session)
        session.add(_score(target_kind="indicator", indicator_id=indicator.id, score=score))
        with pytest.raises(IntegrityError):
            session.commit()


@pytest.mark.parametrize("evidence_hash", ["a" * 63, "A" * 64, "g" * 64])
def test_sha256_hash_representation_is_database_enforced(
    phase6b_factory: sessionmaker[Session], evidence_hash: str
) -> None:
    with phase6b_factory() as session:
        _, indicator, _ = _seed_targets(session)
        session.add(
            _score(
                target_kind="indicator",
                indicator_id=indicator.id,
                evidence_hash=evidence_hash,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


@pytest.mark.parametrize(
    ("target_kind", "indicator", "event_target"),
    [
        ("unknown", True, False),
        ("indicator", False, False),
        ("indicator", True, True),
        ("indicator", False, True),
        ("event", False, False),
        ("event", True, True),
        ("event", True, False),
    ],
)
def test_target_kind_and_exactly_one_target_are_database_enforced(
    phase6b_factory: sessionmaker[Session],
    target_kind: str,
    indicator: bool,
    event_target: bool,
) -> None:
    with phase6b_factory() as session:
        _, indicator_row, correlated_event = _seed_targets(session)
        session.add(
            _score(
                target_kind=target_kind,
                indicator_id=indicator_row.id if indicator else None,
                event_id=correlated_event.id if event_target else None,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_idempotency_is_per_target_and_formula_version(
    phase6b_factory: sessionmaker[Session],
) -> None:
    with phase6b_factory() as session:
        _, first_indicator, first_event = _seed_targets(session, "first")
        _, second_indicator, second_event = _seed_targets(session, "second")
        shared_hash = "b" * 64
        session.add_all(
            [
                _score(
                    target_kind="indicator",
                    indicator_id=first_indicator.id,
                    evidence_hash=shared_hash,
                ),
                _score(
                    target_kind="indicator",
                    indicator_id=second_indicator.id,
                    evidence_hash=shared_hash,
                ),
                _score(target_kind="event", event_id=first_event.id, evidence_hash=shared_hash),
                _score(target_kind="event", event_id=second_event.id, evidence_hash=shared_hash),
                _score(
                    target_kind="indicator",
                    indicator_id=first_indicator.id,
                    evidence_hash=shared_hash,
                    formula_version="phase6b-v2",
                ),
                _score(
                    target_kind="event",
                    event_id=first_event.id,
                    evidence_hash=shared_hash,
                    formula_version="phase6b-v2",
                ),
            ]
        )
        session.commit()
        assert session.scalar(select(func.count(ScoreHistory.id))) == 6

        session.add(
            _score(
                target_kind="indicator",
                indicator_id=first_indicator.id,
                evidence_hash=shared_hash,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.add(_score(target_kind="event", event_id=first_event.id, evidence_hash=shared_hash))
        with pytest.raises(IntegrityError):
            session.commit()


def test_component_decimal_json_and_unique_name_round_trip(
    phase6b_factory: sessionmaker[Session],
) -> None:
    with phase6b_factory() as session:
        _, indicator, _ = _seed_targets(session)
        score = _score(target_kind="indicator", indicator_id=indicator.id)
        score.components.append(
            ScoreComponentRecord(
                component_name="epss_probability",
                raw_input={"probability": "0.1234567"},
                normalized_input="0.1234567",
                weight=Decimal("15.000000"),
                contribution=Decimal("1.851850"),
                freshness_multiplier=Decimal("1.000000"),
                explanation="Exact EPSS contribution",
                provider="epss",
                evidence_at=NOW,
            )
        )
        session.add(score)
        session.commit()
        session.expire_all()

        stored = session.scalar(select(ScoreHistory))
        assert stored is not None
        assert stored.score == Decimal("42.25")
        assert stored.canonical_evidence == {
            "provider": {"value": "0.125"},
            "sources": ["alpha", "beta"],
        }
        assert stored.components[0].weight == Decimal("15.000000")
        assert stored.components[0].contribution == Decimal("1.851850")
        assert stored.components[0].raw_input == {"probability": "0.1234567"}
        assert stored.components[0].normalized_input == "0.1234567"

        with pytest.raises(IntegrityError):
            session.execute(
                insert(ScoreComponentRecord).values(
                    score_history_id=stored.id,
                    component_name="epss_probability",
                    raw_input={},
                    normalized_input="0",
                    weight=Decimal("0"),
                    contribution=Decimal("0"),
                    freshness_multiplier=Decimal("0"),
                    explanation="duplicate",
                )
            )


def test_owned_cascades_and_relationship_deletion_preserve_endpoints(
    phase6b_factory: sessionmaker[Session],
) -> None:
    with phase6b_factory() as session:
        article, indicator, correlated_event = _seed_targets(session)
        article_link = EventArticle(
            event=correlated_event,
            article=article,
            reason="shared_canonical_cve",
            rule_name="shared-cve",
            rule_version="v1",
        )
        indicator_link = EventIndicator(
            event=correlated_event,
            indicator=indicator,
            reason="shared_canonical_cve",
            rule_name="shared-cve",
            rule_version="v1",
        )
        event_score = _score(target_kind="event", event_id=correlated_event.id)
        event_score.components.append(
            ScoreComponentRecord(
                component_name="independent_sources",
                raw_input={"count": 2},
                normalized_input="0.25",
                weight=Decimal("10"),
                contribution=Decimal("2.5"),
                freshness_multiplier=Decimal("1"),
                explanation="sources",
            )
        )
        session.add_all([article_link, indicator_link, event_score])
        session.commit()

        session.delete(article_link)
        session.commit()
        assert session.get(RawArticle, article.id) is not None
        assert session.get(Indicator, indicator.id) is not None
        assert session.get(CorrelatedEvent, correlated_event.id) is not None

        session.delete(correlated_event)
        session.commit()
        assert session.get(RawArticle, article.id) is not None
        assert session.get(Indicator, indicator.id) is not None
        assert session.scalar(select(func.count(EventIndicator.event_id))) == 0
        assert session.scalar(select(func.count(ScoreHistory.id))) == 0
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 0


def test_deleting_article_or_indicator_removes_only_owned_links_and_scores(
    phase6b_factory: sessionmaker[Session],
) -> None:
    with phase6b_factory() as session:
        article, indicator, correlated_event = _seed_targets(session)
        session.add_all(
            [
                EventArticle(
                    event_id=correlated_event.id,
                    article_id=article.id,
                    reason="shared_canonical_cve",
                    rule_name="shared-cve",
                    rule_version="v1",
                ),
                EventIndicator(
                    event_id=correlated_event.id,
                    indicator_id=indicator.id,
                    reason="shared_canonical_cve",
                    rule_name="shared-cve",
                    rule_version="v1",
                ),
                _score(target_kind="indicator", indicator_id=indicator.id),
                _score(target_kind="event", event_id=correlated_event.id, evidence_hash="c" * 64),
            ]
        )
        session.commit()

        session.delete(article)
        session.commit()
        assert session.get(CorrelatedEvent, correlated_event.id) is not None
        assert session.get(Indicator, indicator.id) is not None
        assert session.scalar(select(func.count(EventArticle.event_id))) == 0

        session.delete(indicator)
        session.commit()
        assert session.get(CorrelatedEvent, correlated_event.id) is not None
        assert session.scalar(select(func.count(EventIndicator.event_id))) == 0
        assert session.scalar(select(func.count(ScoreHistory.id))) == 1
        remaining = session.scalar(select(ScoreHistory))
        assert remaining is not None and remaining.event_id == correlated_event.id


def test_timestamps_are_created_as_utc_and_relationship_cascades_are_not_destructive(
    phase6b_factory: sessionmaker[Session],
) -> None:
    assert _utc_now().tzinfo is UTC
    with phase6b_factory() as session:
        article, indicator, correlated_event = _seed_targets(session)
        session.flush()
        assert correlated_event.created_at.tzinfo is UTC
        assert correlated_event.updated_at.tzinfo is UTC

        assert "delete" not in EventArticle.article.property.cascade
        assert "delete" not in EventArticle.event.property.cascade
        assert "delete" not in EventIndicator.indicator.property.cascade
        assert "delete" not in EventIndicator.event.property.cascade
        assert "delete" not in ScoreHistory.indicator.property.cascade
        assert "delete" not in ScoreHistory.event.property.cascade
        assert CorrelatedEvent.article_links.property.lazy == "selectin"
        assert CorrelatedEvent.indicator_links.property.lazy == "selectin"
        assert CorrelatedEvent.scores.property.lazy == "selectin"
        assert ScoreHistory.components.property.lazy == "selectin"
        assert article.id is not None and indicator.id is not None

from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from threading import Barrier

import pytest
from alembic import command
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    create_guarded_test_engine,
    guarded_truncate_scoring_rows,
    run_guarded_alembic_command,
)
from app.ingestion.models import (
    ArticleIndicator,
    Indicator,
    IndicatorEnrichment,
    IOCType,
    RawArticle,
)
from app.models.phase6b import ScoreComponentRecord, ScoreHistory
from app.scoring.engine import calculate_score
from app.scoring.evidence_snapshot import build_evidence_snapshot
from app.services.indicator_scoring import (
    calculate_and_persist_indicator_score,
    load_indicator_scoring_evidence,
)

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


@pytest.fixture(scope="module")
def postgres_scoring(
    phase6b_postgres_database: OwnedDisposablePostgres,
) -> Generator[tuple[Engine, sessionmaker[Session]], None, None]:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield engine, factory
    finally:
        # This fixture commits from independent sessions to exercise real contention.
        # Cleanup remains guarded by both the URL allowlist and connection identity.
        guarded_truncate_scoring_rows(engine)
        engine.dispose()


def _cve(session: Session, suffix: str) -> Indicator:
    indicator = Indicator(
        indicator_type=IOCType.CVE,
        indicator_value=f"CVE-2026-{suffix}",
    )
    session.add(indicator)
    session.flush()
    return indicator


def test_postgres_atomic_persistence_jsonb_decimal_reuse_append_and_rollback(
    postgres_scoring: tuple[Engine, sessionmaker[Session]],
) -> None:
    engine, factory = postgres_scoring
    with factory() as session:
        indicator = _cve(session, "71001")
        article = RawArticle(
            source_id="postgres-score-a",
            source_name="Source A",
            title="PostgreSQL scoring",
            fetched_at=NOW,
            content_hash="postgres-score-a",
        )
        session.add(article)
        session.flush()
        session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))
        session.add_all(
            [
                IndicatorEnrichment(
                    indicator_id=indicator.id,
                    provider="nvd",
                    status="success",
                    normalized_data={"cvss_score": 8.0},
                    enriched_at=NOW - timedelta(hours=1),
                    expires_at=NOW + timedelta(hours=1),
                ),
                IndicatorEnrichment(
                    indicator_id=indicator.id,
                    provider="cisa_kev",
                    status="success",
                    normalized_data={"known_exploited": True},
                    enriched_at=NOW - timedelta(hours=1),
                    expires_at=NOW + timedelta(hours=1),
                ),
                IndicatorEnrichment(
                    indicator_id=indicator.id,
                    provider="epss",
                    status="success",
                    normalized_data={"epss": "0.1", "percentile": "0.2"},
                    enriched_at=NOW - timedelta(hours=1),
                    expires_at=NOW + timedelta(hours=1),
                ),
            ]
        )
        session.commit()

        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        snapshot = build_evidence_snapshot(evidence)
        created = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert created.created is True
        assert created.score_history.score == Decimal("61.50")
        session.flush()

        with engine.connect() as observer:
            assert (
                observer.scalar(
                    select(func.count(ScoreHistory.id)).where(
                        ScoreHistory.indicator_id == indicator.id
                    )
                )
                == 0
            )
        session.commit()

        session.expire_all()
        stored = session.get(ScoreHistory, created.score_history.id)
        assert stored is not None
        assert stored.canonical_evidence == snapshot.payload()
        assert stored.score == Decimal("61.50")
        assert stored.calculated_at.utcoffset() == timedelta(0)
        reused = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert reused.created is False
        assert reused.score_history.id == stored.id
        assert len(reused.components) == 5

        second_article = RawArticle(
            source_id="postgres-score-b",
            source_name="Source B",
            title="Changed evidence",
            fetched_at=NOW,
            content_hash="postgres-score-b",
        )
        session.add(second_article)
        session.flush()
        session.add(ArticleIndicator(raw_article_id=second_article.id, indicator_id=indicator.id))
        changed = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert changed.created is True
        assert changed.score_history.id != stored.id
        assert changed.score_history.score == Decimal("64.00")
        session.commit()
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.indicator_id == indicator.id)
            )
            == 2
        )

    with factory() as session:
        rollback_indicator = _cve(session, "71002")
        session.commit()
        rollback_indicator_id = rollback_indicator.id
        calculate_and_persist_indicator_score(session, rollback_indicator.id, as_of=NOW)
        session.rollback()
    with factory() as session:
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(
                    ScoreHistory.indicator_id == rollback_indicator_id
                )
            )
            == 0
        )


def test_postgres_concurrent_idempotency_preserves_unrelated_caller_work(
    postgres_scoring: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = postgres_scoring
    with factory() as session:
        indicator = Indicator(
            indicator_type=IOCType.EMAIL,
            indicator_value="concurrency@example.com",
        )
        session.add(indicator)
        session.commit()
        indicator_id = indicator.id

    barrier = Barrier(2, timeout=10)

    def worker(number: int) -> tuple[int, bool, str]:
        with factory() as session:
            evidence = load_indicator_scoring_evidence(session, indicator_id, as_of=NOW)
            snapshot = build_evidence_snapshot(evidence)
            score_result = calculate_score(evidence)
            unrelated = RawArticle(
                source_id=f"concurrency-{number}",
                title=f"Unrelated {number}",
                fetched_at=NOW,
                content_hash=f"concurrency-{number}",
            )
            session.add(unrelated)
            barrier.wait()
            persisted = calculate_and_persist_indicator_score(session, indicator_id, as_of=NOW)
            assert persisted.evidence_hash == snapshot.evidence_hash
            assert persisted.score_history.score == score_result.final_score
            session.commit()
            return persisted.score_history.id, persisted.created, persisted.evidence_hash

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(worker, (1, 2)))

    assert results[0][0] == results[1][0]
    assert sorted(result[1] for result in results) == [False, True]
    assert results[0][2] == results[1][2]
    with factory() as session:
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.indicator_id == indicator_id)
            )
            == 1
        )
        score_id = session.scalar(
            select(ScoreHistory.id).where(ScoreHistory.indicator_id == indicator_id)
        )
        assert (
            session.scalar(
                select(func.count(ScoreComponentRecord.component_name)).where(
                    ScoreComponentRecord.score_history_id == score_id
                )
            )
            == 1
        )
        assert (
            session.scalar(
                select(func.count(RawArticle.id)).where(
                    RawArticle.source_id.in_(("concurrency-1", "concurrency-2"))
                )
            )
            == 2
        )

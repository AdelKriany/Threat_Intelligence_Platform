from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest
from alembic import command
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    create_guarded_test_engine,
    run_guarded_alembic_command,
)
from app.ingestion.models import ArticleIndicator, Indicator, IOCType, RawArticle
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator
from app.services import cve_correlation as correlation_service
from app.services.cve_correlation import CVECorrelationResult

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


def test_concurrent_correlation_creates_one_event_and_preserves_caller_work(
    phase6b_postgres_database: OwnedDisposablePostgres,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        indicator = Indicator(
            indicator_type=IOCType.CVE,
            indicator_value="CVE-2026-72001",
        )
        session.add(indicator)
        session.flush()
        articles = [
            RawArticle(
                source_id=f"correlation-source-{number}",
                source_name=f"Source {number}",
                title=f"CVE report {number}",
                fetched_at=NOW,
                content_hash=f"correlation-source-{number}",
            )
            for number in (1, 2)
        ]
        session.add_all(articles)
        session.flush()
        session.add_all(
            ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id)
            for article in articles
        )
        session.commit()
        indicator_id = indicator.id

    barrier = Barrier(2, timeout=10)
    real_insert_event = correlation_service._insert_event

    def synchronized_insert_event(
        session: Session,
        *,
        event_key: str,
        title: str,
        as_of: datetime,
    ) -> bool:
        barrier.wait()
        return real_insert_event(
            session,
            event_key=event_key,
            title=title,
            as_of=as_of,
        )

    monkeypatch.setattr(correlation_service, "_insert_event", synchronized_insert_event)

    def worker(number: int) -> tuple[int, bool, bool, tuple[int, ...]]:
        with factory() as session:
            session.add(
                RawArticle(
                    source_id=f"correlation-unrelated-{number}",
                    title=f"Unrelated caller work {number}",
                    fetched_at=NOW,
                    content_hash=f"correlation-unrelated-{number}",
                )
            )
            result: CVECorrelationResult = correlation_service.correlate_cve_indicator(
                session,
                indicator_id,
                as_of=NOW,
            )
            session.commit()
            return (
                result.event.id,
                result.event_created,
                result.indicator_link_created,
                result.article_link_ids_created,
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(worker, (1, 2)))

        assert results[0][0] == results[1][0]
        assert sorted(result[1] for result in results) == [False, True]
        assert sorted(result[2] for result in results) == [False, True]
        assert sorted(len(result[3]) for result in results) == [0, 2]
        with factory() as session:
            event_id = results[0][0]
            assert (
                session.scalar(
                    select(func.count(CorrelatedEvent.id)).where(
                        CorrelatedEvent.event_key == "cve:CVE-2026-72001"
                    )
                )
                == 1
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(EventIndicator)
                    .where(EventIndicator.event_id == event_id)
                )
                == 1
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(EventArticle)
                    .where(EventArticle.event_id == event_id)
                )
                == 2
            )
            assert (
                session.scalar(
                    select(func.count(RawArticle.id)).where(
                        RawArticle.source_id.in_(
                            ("correlation-unrelated-1", "correlation-unrelated-2")
                        )
                    )
                )
                == 2
            )
    finally:
        engine.dispose()

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
from app.services import cve_correlation_backfill as backfill_service
from app.services.cve_correlation_backfill import CVECorrelationBackfillResult

NOW = datetime(2026, 9, 8, 16, tzinfo=UTC)


def test_postgres_backfill_is_bounded_idempotent_and_concurrent(
    phase6b_postgres_database: OwnedDisposablePostgres,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        indicators = [
            Indicator(indicator_type=IOCType.CVE, indicator_value=f"CVE-2026-{number}")
            for number in (81001, 81002, 81003)
        ]
        invalid = Indicator(indicator_type=IOCType.CVE, indicator_value="cve-2026-81004")
        session.add_all([*indicators, invalid])
        session.flush()
        for number, indicator in enumerate(indicators, start=1):
            article = RawArticle(
                source_id=f"backfill-postgres-{number}",
                title=f"PostgreSQL backfill article {number}",
                fetched_at=NOW,
                content_hash=f"backfill-postgres-{number}",
            )
            session.add(article)
            session.flush()
            session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))
        session.commit()
        second_id = indicators[1].id

    with factory() as session:
        dry_run = backfill_service.backfill_cve_correlations(
            session,
            apply=False,
            limit=2,
            as_of=NOW,
        )
        session.rollback()
        assert dry_run.events_would_create == 2
        assert session.scalar(select(func.count(CorrelatedEvent.id))) == 0

    barrier = Barrier(2, timeout=10)
    real_build_plan = backfill_service._build_plan

    def synchronized_build_plan(
        session: Session,
        *,
        limit: int,
        after_id: int,
    ) -> object:
        plan = real_build_plan(session, limit=limit, after_id=after_id)
        barrier.wait()
        return plan

    monkeypatch.setattr(backfill_service, "_build_plan", synchronized_build_plan)

    def worker(number: int) -> CVECorrelationBackfillResult:
        with factory() as session:
            session.add(
                RawArticle(
                    source_id=f"backfill-unrelated-{number}",
                    title=f"Unrelated backfill caller work {number}",
                    fetched_at=NOW,
                    content_hash=f"backfill-unrelated-{number}",
                )
            )
            result = backfill_service.backfill_cve_correlations(
                session,
                apply=True,
                limit=2,
                as_of=NOW,
            )
            session.commit()
            return result

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            concurrent = list(executor.map(worker, (1, 2)))

        assert sum(result.events_created for result in concurrent) == 2
        assert sum(result.indicator_links_created for result in concurrent) == 2
        assert sum(result.article_links_created for result in concurrent) == 2

        monkeypatch.setattr(backfill_service, "_build_plan", real_build_plan)
        with factory() as session:
            final = backfill_service.backfill_cve_correlations(
                session,
                apply=True,
                limit=10,
                after_id=second_id,
                as_of=NOW,
            )
            session.commit()

            assert final.scanned == 2
            assert final.eligible == 1
            assert final.invalid_skipped == 1
            assert final.events_created == 1
            assert session.scalar(select(func.count(CorrelatedEvent.id))) == 3
            assert session.scalar(select(func.count()).select_from(EventIndicator)) == 3
            assert session.scalar(select(func.count()).select_from(EventArticle)) == 3
            assert (
                session.scalar(
                    select(func.count(RawArticle.id)).where(
                        RawArticle.source_id.in_(("backfill-unrelated-1", "backfill-unrelated-2"))
                    )
                )
                == 2
            )
    finally:
        engine.dispose()

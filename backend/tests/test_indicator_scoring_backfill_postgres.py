from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
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
from app.ingestion.models import Indicator, IOCType, RawArticle
from app.models.phase6b import ScoreHistory
from app.services import indicator_scoring_backfill as backfill_service
from app.services.indicator_scoring import PersistedIndicatorScore
from app.services.indicator_scoring_backfill import IndicatorScoreBackfillResult

NOW = datetime(2026, 10, 7, 12, tzinfo=UTC)


def test_postgres_backfill_dry_run_and_concurrent_apply_are_idempotent(
    phase6b_postgres_database: OwnedDisposablePostgres,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        with factory() as session:
            indicator = Indicator(
                indicator_type=IOCType.EMAIL,
                indicator_value="phase10a-concurrency@example.com",
                created_at=NOW,
            )
            session.add(indicator)
            session.commit()
            indicator_id = indicator.id
            after_id = indicator_id - 1

        with factory() as session:
            dry_run = backfill_service.backfill_indicator_scores(
                session,
                apply=False,
                limit=1,
                after_id=after_id,
                as_of=NOW,
            )
            assert dry_run.scores_would_create == 1
            assert dry_run.scores_created == 0
            assert (
                session.scalar(
                    select(func.count(ScoreHistory.id)).where(
                        ScoreHistory.target_kind == "indicator",
                        ScoreHistory.indicator_id == indicator_id,
                    )
                )
                == 0
            )
            session.rollback()

        barrier = Barrier(2, timeout=10)
        real_service = backfill_service.calculate_and_persist_indicator_score

        def synchronized_score(
            session: Session,
            target_id: int,
            *,
            as_of: datetime,
        ) -> PersistedIndicatorScore:
            barrier.wait()
            return real_service(session, target_id, as_of=as_of)

        monkeypatch.setattr(
            backfill_service,
            "calculate_and_persist_indicator_score",
            synchronized_score,
        )

        def worker(number: int) -> IndicatorScoreBackfillResult:
            with factory() as session:
                session.add(
                    RawArticle(
                        source_id=f"phase10a-unrelated-{number}",
                        title=f"Unrelated caller work {number}",
                        fetched_at=NOW,
                        content_hash=f"phase10a-unrelated-{number}",
                    )
                )
                result = backfill_service.backfill_indicator_scores(
                    session,
                    apply=True,
                    limit=1,
                    after_id=after_id,
                    as_of=NOW,
                )
                session.commit()
                return result

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(worker, (1, 2)))

        assert sum(result.scores_created for result in results) == 1
        assert sum(result.scores_reused for result in results) == 1
        assert all(result.scanned == result.scoreable == 1 for result in results)

        monkeypatch.setattr(
            backfill_service,
            "calculate_and_persist_indicator_score",
            real_service,
        )
        with factory() as session:
            repeated = backfill_service.backfill_indicator_scores(
                session,
                apply=True,
                limit=1,
                after_id=after_id,
                as_of=NOW + timedelta(days=1),
            )
            session.commit()
            assert repeated.scores_created == 0
            assert repeated.scores_reused == 1
            assert (
                session.scalar(
                    select(func.count(ScoreHistory.id)).where(
                        ScoreHistory.target_kind == "indicator",
                        ScoreHistory.indicator_id == indicator_id,
                    )
                )
                == 1
            )
            assert (
                session.scalar(
                    select(func.count(RawArticle.id)).where(
                        RawArticle.source_id.in_(("phase10a-unrelated-1", "phase10a-unrelated-2"))
                    )
                )
                == 2
            )
    finally:
        engine.dispose()

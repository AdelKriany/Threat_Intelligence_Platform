from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
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
from app.models.phase6b import (
    CorrelatedEvent,
    EventArticle,
    EventIndicator,
    ScoreComponentRecord,
    ScoreHistory,
)
from app.services import event_scoring_backfill as backfill_service
from app.services.event_scoring import PersistedEventScore
from app.services.event_scoring_backfill import EventScoreBackfillResult

NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)


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
            cve = "CVE-2026-98001"
            indicator = Indicator(indicator_type=IOCType.CVE, indicator_value=cve, created_at=NOW)
            event_row = CorrelatedEvent(
                event_key=f"cve:{cve}",
                title=f"{cve} vulnerability",
                rule_name="shared-cve",
                rule_version="v1",
                created_at=NOW,
                updated_at=NOW,
            )
            session.add_all([indicator, event_row])
            session.flush()
            session.add(
                EventIndicator(
                    event_id=event_row.id,
                    indicator_id=indicator.id,
                    reason="shared_canonical_cve",
                    rule_name="shared-cve",
                    rule_version="v1",
                    created_at=NOW,
                )
            )
            for position, source_name in enumerate(("Source A", "Source B"), start=1):
                article = RawArticle(
                    source_id=f"event-score-backfill-pg-source-{position}",
                    source_name=source_name,
                    title="PostgreSQL backfill evidence",
                    fetched_at=NOW,
                    content_hash=f"event-score-backfill-pg-source-{position}",
                )
                session.add(article)
                session.flush()
                session.add(
                    EventArticle(
                        event_id=event_row.id,
                        article_id=article.id,
                        reason="shared_canonical_cve",
                        rule_name="shared-cve",
                        rule_version="v1",
                        created_at=NOW,
                    )
                )
            session.add(
                ScoreHistory(
                    target_kind="indicator",
                    indicator_id=indicator.id,
                    event_id=None,
                    score=Decimal("80.00"),
                    severity="critical",
                    formula_version="phase6b-v1",
                    evidence_hash="c" * 64,
                    canonical_evidence={"not_loaded": True},
                    calculated_at=NOW,
                )
            )
            session.commit()
            event_id = event_row.id
            after_id = event_id - 1

        with factory() as session:
            dry_run = backfill_service.backfill_event_scores(
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
                        ScoreHistory.target_kind == "event",
                        ScoreHistory.event_id == event_id,
                    )
                )
                == 0
            )
            session.rollback()

        barrier = Barrier(2, timeout=10)
        real_service = backfill_service.calculate_and_persist_event_score

        def synchronized_score(
            session: Session,
            target_id: int,
            *,
            as_of: datetime,
        ) -> PersistedEventScore:
            barrier.wait()
            return real_service(session, target_id, as_of=as_of)

        monkeypatch.setattr(
            backfill_service,
            "calculate_and_persist_event_score",
            synchronized_score,
        )

        def worker(number: int) -> EventScoreBackfillResult:
            with factory() as session:
                session.add(
                    RawArticle(
                        source_id=f"event-score-backfill-pg-unrelated-{number}",
                        title=f"Unrelated caller work {number}",
                        fetched_at=NOW,
                        content_hash=f"event-score-backfill-pg-unrelated-{number}",
                    )
                )
                result = backfill_service.backfill_event_scores(
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
            "calculate_and_persist_event_score",
            real_service,
        )
        with factory() as session:
            repeated = backfill_service.backfill_event_scores(
                session,
                apply=True,
                limit=1,
                after_id=after_id,
                as_of=NOW + timedelta(days=1),
            )
            session.commit()
            assert repeated.scores_created == 0
            assert repeated.scores_reused == 1
            score_id = session.scalar(
                select(ScoreHistory.id).where(
                    ScoreHistory.target_kind == "event",
                    ScoreHistory.event_id == event_id,
                )
            )
            assert score_id is not None
            assert (
                session.scalar(
                    select(func.count(ScoreHistory.id)).where(
                        ScoreHistory.target_kind == "event",
                        ScoreHistory.event_id == event_id,
                    )
                )
                == 1
            )
            assert (
                session.scalar(
                    select(func.count(ScoreComponentRecord.component_name)).where(
                        ScoreComponentRecord.score_history_id == score_id
                    )
                )
                == 2
            )
            assert (
                session.scalar(
                    select(func.count(RawArticle.id)).where(
                        RawArticle.source_id.in_(
                            (
                                "event-score-backfill-pg-unrelated-1",
                                "event-score-backfill-pg-unrelated-2",
                            )
                        )
                    )
                )
                == 2
            )
    finally:
        engine.dispose()

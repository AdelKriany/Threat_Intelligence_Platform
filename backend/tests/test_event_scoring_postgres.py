from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
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
from app.ingestion.models import Indicator, IOCType, RawArticle
from app.models.phase6b import (
    CorrelatedEvent,
    EventArticle,
    EventIndicator,
    ScoreComponentRecord,
    ScoreHistory,
)
from app.scoring.event_models import EventScoreResult
from app.scoring.evidence_snapshot import CanonicalEvidenceSnapshot
from app.services import event_scoring as event_scoring_service
from app.services.event_scoring import PersistedEventScore

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


@pytest.fixture(scope="module")
def postgres_event_scoring(
    phase6b_postgres_database: OwnedDisposablePostgres,
) -> Generator[tuple[Engine, sessionmaker[Session]], None, None]:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield engine, factory
    finally:
        guarded_truncate_scoring_rows(engine)
        engine.dispose()


def test_postgres_concurrent_event_score_is_idempotent_and_preserves_caller_work(
    postgres_event_scoring: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = postgres_event_scoring
    with factory() as session:
        cve = "CVE-2026-93001"
        indicator = Indicator(indicator_type=IOCType.CVE, indicator_value=cve, created_at=NOW)
        event = CorrelatedEvent(
            event_key=f"cve:{cve}",
            title=f"{cve} vulnerability",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
            updated_at=NOW,
        )
        session.add_all([indicator, event])
        session.flush()
        session.add(
            EventIndicator(
                event_id=event.id,
                indicator_id=indicator.id,
                reason="shared_canonical_cve",
                rule_name="shared-cve",
                rule_version="v1",
                created_at=NOW,
            )
        )
        for sequence, source_name in enumerate(("Source A", "Source B"), start=1):
            article = RawArticle(
                source_id=f"event-score-evidence-{sequence}",
                source_name=source_name,
                title="Event score evidence",
                fetched_at=NOW,
                content_hash=f"event-score-evidence-{sequence}",
            )
            session.add(article)
            session.flush()
            session.add(
                EventArticle(
                    event_id=event.id,
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
                evidence_hash="a" * 64,
                canonical_evidence={"not_loaded_by_event_scorer": True},
                calculated_at=NOW,
            )
        )
        session.commit()
        event_id = event.id

    barrier = Barrier(2, timeout=10)
    real_persist = event_scoring_service.persist_event_score

    def synchronized_persist(
        session: Session,
        *,
        event_id: int,
        result: EventScoreResult,
        snapshot: CanonicalEvidenceSnapshot,
    ) -> PersistedEventScore:
        barrier.wait()
        return real_persist(
            session,
            event_id=event_id,
            result=result,
            snapshot=snapshot,
        )

    monkeypatch.setattr(event_scoring_service, "persist_event_score", synchronized_persist)

    def worker(number: int) -> tuple[int, bool, str]:
        with factory() as session:
            session.add(
                RawArticle(
                    source_id=f"event-score-unrelated-{number}",
                    title=f"Unrelated caller work {number}",
                    fetched_at=NOW,
                    content_hash=f"event-score-unrelated-{number}",
                )
            )
            persisted = event_scoring_service.calculate_and_persist_event_score(
                session, event_id, as_of=NOW
            )
            session.commit()
            return (
                persisted.score_history.id,
                persisted.created,
                persisted.evidence_hash,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(worker, (1, 2)))

    assert results[0][0] == results[1][0]
    assert sorted(result[1] for result in results) == [False, True]
    assert results[0][2] == results[1][2]
    with factory() as session:
        event_score_id = results[0][0]
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
                    ScoreComponentRecord.score_history_id == event_score_id
                )
            )
            == 2
        )
        assert (
            session.scalar(
                select(func.count(RawArticle.id)).where(
                    RawArticle.source_id.in_(("event-score-unrelated-1", "event-score-unrelated-2"))
                )
            )
            == 2
        )

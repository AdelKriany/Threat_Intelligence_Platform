from __future__ import annotations

import asyncio
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
from threading import Barrier, Lock
from typing import Any

import httpx
import pytest
from alembic import command
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1 import event_scores as score_api
from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    create_guarded_test_engine,
    run_guarded_alembic_command,
)
from app.database.session import get_db_session
from app.ingestion.models import Indicator, IOCType, RawArticle
from app.main import create_app
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

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)


def _post(app: FastAPI, event_id: int) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.post(f"/api/v1/events/{event_id}/score")

    return asyncio.run(send())


def test_concurrent_post_returns_one_score_and_preserves_unrelated_work(
    phase6b_postgres_database: OwnedDisposablePostgres,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        with factory() as session:
            cve = "CVE-2026-96001"
            indicator = Indicator(
                indicator_type=IOCType.CVE,
                indicator_value=cve,
                created_at=NOW,
            )
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
                    source_id=f"event-score-post-api-source-{position}",
                    source_name=source_name,
                    title="PostgreSQL API evidence",
                    fetched_at=NOW,
                    content_hash=f"event-score-post-api-source-{position}",
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
                    evidence_hash="b" * 64,
                    canonical_evidence={"not_loaded_by_event_scorer": True},
                    calculated_at=NOW,
                )
            )
            session.commit()
            event_id = event_row.id

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
        monkeypatch.setattr(score_api, "_utc_now", lambda: NOW)

        application = create_app()
        sequence_lock = Lock()
        request_sequence = iter((1, 2))

        def override_session() -> Generator[Session, None, None]:
            with sequence_lock:
                number = next(request_sequence)
            with factory() as session:
                session.add(
                    RawArticle(
                        source_id=f"event-score-post-api-unrelated-{number}",
                        title=f"Unrelated request work {number}",
                        fetched_at=NOW,
                        content_hash=f"event-score-post-api-unrelated-{number}",
                    )
                )
                yield session

        application.dependency_overrides[get_db_session] = override_session
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = list(executor.map(lambda _: _post(application, event_id), (1, 2)))
        finally:
            application.dependency_overrides.clear()

        assert all(response.status_code == 200 for response in responses)
        payloads: list[dict[str, Any]] = [response.json() for response in responses]
        assert sorted(payload["created"] for payload in payloads) == [False, True]
        assert payloads[0]["score"]["id"] == payloads[1]["score"]["id"]
        assert payloads[0]["score"]["evidence_hash"] == payloads[1]["score"]["evidence_hash"]

        with factory() as session:
            score_id = payloads[0]["score"]["id"]
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
                                "event-score-post-api-unrelated-1",
                                "event-score-post-api-unrelated-2",
                            )
                        )
                    )
                )
                == 2
            )
    finally:
        engine.dispose()

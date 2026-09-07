from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest
from alembic import command
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1 import indicator_scores as score_api
from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    create_guarded_test_engine,
    guarded_truncate_scoring_rows,
    run_guarded_alembic_command,
)
from app.ingestion.models import Indicator, IOCType
from app.models.phase6b import ScoreComponentRecord, ScoreHistory
from app.schemas.indicator_scores import IndicatorScorePostResponse
from app.services.indicator_scoring import PersistedIndicatorScore

NOW = datetime(2026, 8, 28, 12, tzinfo=UTC)


@pytest.fixture(scope="module")
def postgres_api_database(
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


def test_concurrent_post_returns_one_canonical_database_record(
    postgres_api_database: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = postgres_api_database
    with factory() as session:
        indicator = Indicator(
            indicator_type=IOCType.EMAIL,
            indicator_value="phase6c-concurrency@example.com",
        )
        session.add(indicator)
        session.commit()
        indicator_id = indicator.id

    monkeypatch.setattr(score_api, "_utc_now", lambda: NOW)
    real_service = score_api.calculate_and_persist_indicator_score
    barrier = Barrier(2, timeout=10)

    def synchronized_service(
        session: Session,
        target_id: int,
        *,
        as_of: datetime,
    ) -> PersistedIndicatorScore:
        barrier.wait()
        return real_service(session, target_id, as_of=as_of)

    monkeypatch.setattr(
        score_api,
        "calculate_and_persist_indicator_score",
        synchronized_service,
    )

    def request() -> IndicatorScorePostResponse:
        with factory() as session:
            return score_api.calculate_indicator_score(
                indicator_id=indicator_id,
                session=session,
                force_refresh=True,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _position: request(), range(2)))

    assert responses[0].score.id == responses[1].score.id
    assert sorted(response.created for response in responses) == [False, True]
    with factory() as session:
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.indicator_id == indicator_id)
            )
            == 1
        )
        assert (
            session.scalar(
                select(func.count(ScoreComponentRecord.component_name)).join(ScoreHistory)
            )
            == 1
        )

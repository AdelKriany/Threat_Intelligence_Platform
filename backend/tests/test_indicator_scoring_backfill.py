from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from io import StringIO

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.models import ArticleIndicator, Indicator, IOCType, RawArticle
from app.models.phase6b import ScoreComponentRecord, ScoreHistory
from app.scoring.models import ScoringInputError
from app.services import indicator_scoring_backfill as backfill_service
from app.services.indicator_scoring import (
    IndicatorNotFoundError,
    calculate_and_persist_indicator_score,
)
from app.services.indicator_scoring_backfill import (
    MAX_LIMIT,
    backfill_indicator_scores,
    main,
)

NOW = datetime(2026, 10, 7, 12, tzinfo=UTC)


class TrackingSession(Session):
    commits = 0
    rollbacks = 0

    def commit(self) -> None:
        TrackingSession.commits += 1
        super().commit()

    def rollback(self) -> None:
        TrackingSession.rollbacks += 1
        super().rollback()


@pytest.fixture()
def backfill_database() -> Generator[tuple[Engine, sessionmaker[TrackingSession]], None, None]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _foreign_keys(connection: object, _record: object) -> None:
        connection.isolation_level = None  # type: ignore[attr-defined]
        cursor = connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _begin_transaction(connection: object) -> None:
        connection.exec_driver_sql("BEGIN")  # type: ignore[attr-defined]

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, class_=TrackingSession, expire_on_commit=False)
    TrackingSession.commits = 0
    TrackingSession.rollbacks = 0
    try:
        yield engine, factory
    finally:
        engine.dispose()


def _indicator(session: Session, suffix: str, *, sources: int = 2) -> Indicator:
    indicator = Indicator(
        indicator_type=IOCType.EMAIL,
        indicator_value=f"analyst-{suffix}@example.com",
        created_at=NOW,
    )
    session.add(indicator)
    session.flush()
    for position in range(sources):
        article = RawArticle(
            source_id=f"indicator-score-backfill-{suffix}-{position}",
            source_name=f"Source {position}",
            title="Indicator scoring evidence",
            fetched_at=NOW,
            content_hash=f"indicator-score-backfill-{suffix}-{position}",
        )
        session.add(article)
        session.flush()
        session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))
    session.flush()
    return indicator


def _indicator_score_count(session: Session) -> int:
    return (
        session.scalar(
            select(func.count(ScoreHistory.id)).where(ScoreHistory.target_kind == "indicator")
        )
        or 0
    )


def test_dry_run_forecasts_create_and_reuse_without_durable_writes(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        new = _indicator(session, "new")
        existing = _indicator(session, "existing")
        session.commit()
        calculate_and_persist_indicator_score(session, existing.id, as_of=NOW)
        session.commit()
        before_scores = _indicator_score_count(session)
        before_components = session.scalar(select(func.count()).select_from(ScoreComponentRecord))

        result = backfill_indicator_scores(
            session,
            apply=False,
            limit=10,
            as_of=NOW + timedelta(days=1),
        )

        assert result.mode == "dry-run"
        assert result.scanned == result.scoreable == 2
        assert result.scores_would_create == 1
        assert result.scores_would_reuse == 1
        assert result.scores_created == result.scores_reused == 0
        assert [item.indicator_id for item in result.items] == [new.id, existing.id]
        assert [item.outcome for item in result.items] == ["would_create", "would_reuse"]
        assert _indicator_score_count(session) == before_scores == 1
        assert (
            session.scalar(select(func.count()).select_from(ScoreComponentRecord))
            == before_components
        )


def test_apply_is_bounded_cursor_paginated_and_idempotent(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        indicators = [_indicator(session, suffix) for suffix in ("one", "two", "three")]
        session.commit()

        first = backfill_indicator_scores(session, apply=True, limit=2, as_of=NOW)
        session.commit()
        assert first.scanned == first.scoreable == 2
        assert first.has_more is True
        assert first.next_after_id == indicators[1].id
        assert first.scores_created == 2

        repeated = backfill_indicator_scores(
            session,
            apply=True,
            limit=2,
            as_of=NOW + timedelta(days=1),
        )
        session.commit()
        assert repeated.scores_created == 0
        assert repeated.scores_reused == 2

        final = backfill_indicator_scores(
            session,
            apply=True,
            limit=2,
            after_id=first.next_after_id or 0,
            as_of=NOW,
        )
        session.commit()
        assert final.scanned == 1
        assert final.first_scanned_id == final.last_scanned_id == indicators[2].id
        assert final.has_more is False and final.next_after_id is None
        assert final.scores_created == 1
        assert _indicator_score_count(session) == 3


def test_classifies_disappearing_and_unscorable_indicators(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = backfill_database
    with factory() as session:
        missing = _indicator(session, "missing")
        unscorable = _indicator(session, "unscorable")
        session.commit()

        def classify(session: Session, indicator_id: int, *, as_of: datetime) -> object:
            if indicator_id == missing.id:
                raise IndicatorNotFoundError("removed concurrently")
            if indicator_id == unscorable.id:
                raise ScoringInputError("invalid stored evidence")
            raise AssertionError("unexpected candidate")

        monkeypatch.setattr(
            backfill_service,
            "calculate_and_persist_indicator_score",
            classify,
        )
        result = backfill_indicator_scores(session, apply=False, limit=10, as_of=NOW)

        assert result.scanned == 2
        assert result.scoreable == 0
        assert (result.missing, result.unscorable) == (1, 1)
        assert [item.outcome for item in result.items] == ["missing", "unscorable"]


def test_core_leaves_atomic_page_transaction_to_caller(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        _indicator(session, "rollback-one")
        _indicator(session, "rollback-two")
        session.commit()

        result = backfill_indicator_scores(session, apply=True, limit=10, as_of=NOW)
        assert result.scores_created == 2
        session.rollback()
        assert _indicator_score_count(session) == 0
        assert session.scalar(select(func.count()).select_from(ScoreComponentRecord)) == 0


def test_cli_defaults_to_dry_run_and_apply_commits_once(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        indicator = _indicator(session, "cli")
        session.commit()
    TrackingSession.commits = 0

    dry_stdout = StringIO()
    assert main([], session_factory=factory, clock=lambda: NOW, stdout=dry_stdout) == 0
    dry = json.loads(dry_stdout.getvalue())
    assert dry["mode"] == "dry-run"
    assert dry["scores_would_create"] == 1
    assert dry["scores_created"] == 0
    assert TrackingSession.commits == 0

    apply_stdout = StringIO()
    assert (
        main(
            ["--apply", "--limit", "1", "--after-id", str(indicator.id - 1)],
            session_factory=factory,
            clock=lambda: NOW,
            stdout=apply_stdout,
        )
        == 0
    )
    applied = json.loads(apply_stdout.getvalue())
    assert applied["scores_created"] == 1
    assert TrackingSession.commits == 1


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--limit", "0"], "limit must be between"),
        (["--limit", str(MAX_LIMIT + 1)], "limit must be between"),
        (["--after-id", "-1"], "after_id must be non-negative"),
    ],
)
def test_cli_rejects_unsafe_bounds(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
    arguments: list[str],
    message: str,
) -> None:
    _, factory = backfill_database
    stderr = StringIO()
    assert main(arguments, session_factory=factory, clock=lambda: NOW, stderr=stderr) == 2
    assert message in stderr.getvalue()


def test_cli_rolls_back_the_whole_page_on_unexpected_failure(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = backfill_database
    with factory() as session:
        _indicator(session, "failure-one")
        _indicator(session, "failure-two")
        session.commit()
    real_service = backfill_service.calculate_and_persist_indicator_score
    calls = 0

    def fail_second(session: Session, indicator_id: int, *, as_of: datetime) -> object:
        nonlocal calls
        calls += 1
        persisted = real_service(session, indicator_id, as_of=as_of)
        if calls == 2:
            raise RuntimeError("page failed")
        return persisted

    monkeypatch.setattr(
        backfill_service,
        "calculate_and_persist_indicator_score",
        fail_second,
    )
    stderr = StringIO()
    assert (
        main(
            ["--apply", "--limit", "2"],
            session_factory=factory,
            clock=lambda: NOW,
            stderr=stderr,
        )
        == 2
    )
    assert "RuntimeError" in stderr.getvalue()
    with factory() as session:
        assert _indicator_score_count(session) == 0


def test_apply_delegates_only_to_indicator_scoring_boundary(
    backfill_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = backfill_database
    with factory() as session:
        _indicator(session, "boundary")
        session.commit()
    from app.ingestion.enrichment.service import EnrichmentService
    from app.services import cve_correlation, event_scoring

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("forbidden boundary invoked")

    monkeypatch.setattr(cve_correlation, "correlate_cve_indicator", forbidden)
    monkeypatch.setattr(event_scoring, "calculate_and_persist_event_score", forbidden)
    monkeypatch.setattr(EnrichmentService, "enrich_indicator", forbidden)

    with factory() as session:
        result = backfill_indicator_scores(session, apply=True, limit=1, as_of=NOW)
        session.commit()
    assert result.scores_created == 1

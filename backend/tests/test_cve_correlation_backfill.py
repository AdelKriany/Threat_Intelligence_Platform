from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime
from io import StringIO

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.models import ArticleIndicator, Indicator, IOCType, RawArticle
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator
from app.services.cve_correlation import correlate_cve_indicator
from app.services.cve_correlation_backfill import (
    MAX_LIMIT,
    backfill_cve_correlations,
    main,
)

NOW = datetime(2026, 9, 8, 15, tzinfo=UTC)


@pytest.fixture()
def backfill_database() -> Generator[tuple[Engine, sessionmaker[Session]], None, None]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine, sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def _indicator(session: Session, value: str, ioc_type: IOCType = IOCType.CVE) -> Indicator:
    indicator = Indicator(indicator_type=ioc_type, indicator_value=value)
    session.add(indicator)
    session.flush()
    return indicator


def _article(session: Session, suffix: str, indicator: Indicator) -> RawArticle:
    article = RawArticle(
        source_id=f"backfill-{suffix}",
        title=f"Backfill article {suffix}",
        fetched_at=NOW,
        content_hash=f"backfill-{suffix}",
    )
    session.add(article)
    session.flush()
    session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))
    return article


def _counts(session: Session) -> tuple[int, int, int]:
    return (
        session.scalar(select(func.count(CorrelatedEvent.id))) or 0,
        session.scalar(select(func.count()).select_from(EventIndicator)) or 0,
        session.scalar(select(func.count()).select_from(EventArticle)) or 0,
    )


def test_dry_run_forecasts_changes_without_writing(
    backfill_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        existing = _indicator(session, "CVE-2026-80001")
        old_article = _article(session, "existing-old", existing)
        empty = _indicator(session, "CVE-2026-80002")
        _indicator(session, "cve-2026-80003")
        _indicator(session, "example.com", IOCType.DOMAIN)
        session.commit()
        correlate_cve_indicator(session, existing.id, as_of=NOW)
        session.commit()
        new_article = _article(session, "existing-new", existing)
        session.commit()
        before = _counts(session)

        result = backfill_cve_correlations(
            session,
            apply=False,
            limit=10,
            after_id=0,
            as_of=NOW,
        )

        assert result.mode == "dry-run"
        assert result.scanned == 3
        assert result.eligible == 2
        assert result.invalid_skipped == 1
        assert result.has_more is False
        assert result.next_after_id is None
        assert result.events_would_create == 1
        assert result.indicator_links_would_create == 1
        assert result.article_links_would_create == 1
        assert result.events_created == 0
        assert result.indicator_links_created == 0
        assert result.article_links_created == 0
        assert _counts(session) == before == (1, 1, 1)
        assert session.get(RawArticle, old_article.id) is not None
        assert session.get(RawArticle, new_article.id) is not None
        assert session.get(Indicator, empty.id) is not None


def test_apply_is_bounded_paginated_and_idempotent(
    backfill_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        indicators = [_indicator(session, f"CVE-2026-{number}") for number in (80010, 80011, 80012)]
        for number, indicator in enumerate(indicators, start=1):
            _article(session, f"page-{number}", indicator)
        session.commit()

        first = backfill_cve_correlations(
            session,
            apply=True,
            limit=2,
            after_id=0,
            as_of=NOW,
        )
        session.commit()

        assert first.scanned == first.eligible == 2
        assert first.has_more is True
        assert first.next_after_id == indicators[1].id
        assert (
            first.events_created,
            first.indicator_links_created,
            first.article_links_created,
        ) == (
            2,
            2,
            2,
        )
        assert _counts(session) == (2, 2, 2)

        repeated = backfill_cve_correlations(
            session,
            apply=True,
            limit=2,
            after_id=0,
            as_of=NOW,
        )
        session.commit()
        assert (
            repeated.events_created,
            repeated.indicator_links_created,
            repeated.article_links_created,
        ) == (
            0,
            0,
            0,
        )

        final = backfill_cve_correlations(
            session,
            apply=True,
            limit=2,
            after_id=first.next_after_id or 0,
            as_of=NOW,
        )
        session.commit()
        assert final.scanned == final.eligible == 1
        assert final.has_more is False
        assert final.next_after_id is None
        assert (
            final.events_created,
            final.indicator_links_created,
            final.article_links_created,
        ) == (
            1,
            1,
            1,
        )
        assert _counts(session) == (3, 3, 3)


def test_invalid_cves_are_skipped_non_cves_are_excluded_and_empty_cve_is_eligible(
    backfill_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        empty = _indicator(session, "CVE-2026-80020")
        _indicator(session, "CVE-26-2")
        _indicator(session, "192.0.2.1", IOCType.IPV4)
        session.commit()

        result = backfill_cve_correlations(
            session,
            apply=True,
            limit=10,
            as_of=NOW,
        )
        session.commit()

        assert result.scanned == 2
        assert result.eligible == 1
        assert result.invalid_skipped == 1
        assert result.events_created == 1
        assert result.article_links_created == 0
        assert session.scalar(select(CorrelatedEvent.event_key)) == "cve:CVE-2026-80020"
        assert session.scalar(select(EventIndicator.indicator_id)) == empty.id


def test_core_leaves_transaction_control_to_caller(
    backfill_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-80030")
        _article(session, "rollback", indicator)
        session.commit()

        result = backfill_cve_correlations(session, apply=True, limit=10, as_of=NOW)
        assert result.events_created == 1
        session.rollback()

        assert _counts(session) == (0, 0, 0)
        assert session.get(Indicator, indicator.id) is not None


def test_cli_defaults_to_dry_run_and_apply_commits(
    backfill_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = backfill_database
    with factory() as session:
        indicator = _indicator(session, "CVE-2026-80040")
        _article(session, "cli", indicator)
        session.commit()

    dry_stdout = StringIO()
    assert main([], session_factory=factory, clock=lambda: NOW, stdout=dry_stdout) == 0
    dry_summary = json.loads(dry_stdout.getvalue())
    assert dry_summary["mode"] == "dry-run"
    assert dry_summary["events_would_create"] == 1
    assert dry_summary["events_created"] == 0
    with factory() as session:
        assert _counts(session) == (0, 0, 0)

    apply_stdout = StringIO()
    assert (
        main(
            ["--apply", "--limit", "1", "--after-id", "0"],
            session_factory=factory,
            clock=lambda: NOW,
            stdout=apply_stdout,
        )
        == 0
    )
    apply_summary = json.loads(apply_stdout.getvalue())
    assert apply_summary["mode"] == "apply"
    assert apply_summary["events_created"] == 1
    with factory() as session:
        assert _counts(session) == (1, 1, 1)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--limit", "0"], "limit must be between"),
        (["--limit", str(MAX_LIMIT + 1)], "limit must be between"),
        (["--after-id", "-1"], "after_id must be non-negative"),
    ],
)
def test_cli_rejects_unsafe_bounds(
    backfill_database: tuple[Engine, sessionmaker[Session]],
    arguments: list[str],
    message: str,
) -> None:
    _, factory = backfill_database
    stderr = StringIO()

    assert main(arguments, session_factory=factory, clock=lambda: NOW, stderr=stderr) == 2
    assert message in stderr.getvalue()


def test_dry_run_query_count_is_constant_in_page_size(
    backfill_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    engine, factory = backfill_database
    with factory() as session:
        indicators = [_indicator(session, f"CVE-2026-{number}") for number in (80050, 80051, 80052)]
        for number, indicator in enumerate(indicators, start=1):
            _article(session, f"queries-{number}", indicator)
        session.commit()
        statements: list[str] = []

        @event.listens_for(engine, "before_cursor_execute")
        def _record_statement(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(statement)

        backfill_cve_correlations(session, apply=False, limit=1, as_of=NOW)
        one_count = len(statements)
        session.rollback()
        statements.clear()
        backfill_cve_correlations(session, apply=False, limit=3, as_of=NOW)
        three_count = len(statements)

        assert one_count == three_count == 3

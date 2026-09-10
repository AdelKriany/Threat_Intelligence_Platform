from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.session import get_db_session
from app.ingestion.models import Indicator, IndicatorEnrichment, IOCType, RawArticle
from app.main import create_app
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator, ScoreHistory

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


@pytest.fixture()
def api_database() -> Generator[tuple[Engine, sessionmaker[Session]], None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        dbapi_connection.isolation_level = None  # type: ignore[attr-defined]
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _begin_transaction(connection: object) -> None:
        connection.exec_driver_sql("BEGIN")  # type: ignore[attr-defined]

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield engine, factory
    finally:
        engine.dispose()


@pytest.fixture()
def app(api_database: tuple[Engine, sessionmaker[Session]]) -> Generator[FastAPI, None, None]:
    _, factory = api_database
    application = create_app()

    def override_session() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    application.dependency_overrides[get_db_session] = override_session
    try:
        yield application
    finally:
        application.dependency_overrides.clear()


def _request(app: FastAPI, path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(path)

    return asyncio.run(send())


def _event(session: Session, suffix: int, *, updated_at: datetime | None = None) -> CorrelatedEvent:
    cve = f"CVE-2026-{82000 + suffix}"
    row = CorrelatedEvent(
        event_key=f"cve:{cve}",
        title=f"{cve} vulnerability",
        rule_name="shared-cve",
        rule_version="v1",
        created_at=NOW - timedelta(days=1),
        updated_at=updated_at or NOW,
    )
    session.add(row)
    session.flush()
    return row


def _indicator(
    session: Session,
    event_row: CorrelatedEvent,
    value: str,
    *,
    ioc_type: IOCType = IOCType.CVE,
) -> Indicator:
    row = Indicator(indicator_type=ioc_type, indicator_value=value, created_at=NOW)
    session.add(row)
    session.flush()
    session.add(
        EventIndicator(
            event_id=event_row.id,
            indicator_id=row.id,
            reason="shared_canonical_cve",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
        )
    )
    return row


def _article(
    session: Session,
    event_row: CorrelatedEvent,
    suffix: str,
    *,
    source_name: str = "Source A",
    published_at: datetime | None = NOW,
    fetched_at: datetime = NOW,
) -> RawArticle:
    row = RawArticle(
        source_id=f"api-{suffix}",
        source_name=source_name,
        title=f"Article {suffix}",
        url=f"https://example.test/{suffix}",
        published_at=published_at,
        fetched_at=fetched_at,
        author="ThreatLens",
        categories="vulnerability, security",
        raw_content="must never be exposed",
        content_hash=f"api-{suffix}",
    )
    session.add(row)
    session.flush()
    session.add(
        EventArticle(
            event_id=event_row.id,
            article_id=row.id,
            reason="shared_canonical_cve",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
        )
    )
    return row


def _score(
    session: Session,
    *,
    sequence: int,
    calculated_at: datetime,
    score: Decimal,
    event_id: int | None = None,
    indicator_id: int | None = None,
) -> ScoreHistory:
    row = ScoreHistory(
        target_kind="event" if event_id is not None else "indicator",
        event_id=event_id,
        indicator_id=indicator_id,
        score=score,
        severity="critical" if score >= 80 else "medium",
        formula_version="persisted-v1",
        evidence_hash=f"{sequence:064x}",
        canonical_evidence={"private": "must never be exposed"},
        calculated_at=calculated_at,
    )
    session.add(row)
    session.flush()
    return row


def test_empty_event_list(
    app: FastAPI,
) -> None:
    response = _request(app, "/api/v1/events")

    assert response.status_code == 200
    assert response.json() == {"items": [], "limit": 20, "offset": 0, "total": 0}


def test_event_list_paginates_counts_and_orders_deterministically(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    with factory() as session:
        first = _event(session, 1, updated_at=NOW - timedelta(hours=1))
        second = _event(session, 2, updated_at=NOW)
        third = _event(session, 3, updated_at=NOW)
        _indicator(session, third, "CVE-2026-82003")
        _article(session, third, "list")
        session.commit()

    response = _request(app, "/api/v1/events?limit=2&offset=1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 3
    assert payload["limit"] == 2
    assert payload["offset"] == 1
    assert [item["id"] for item in payload["items"]] == [second.id, first.id]
    assert payload["items"][0]["article_count"] == 0
    assert payload["items"][0]["indicator_count"] == 0


def test_event_detail_has_counts_score_summary_and_no_relationship_collections(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    with factory() as session:
        event_row = _event(session, 4)
        _indicator(session, event_row, "CVE-2026-82004")
        _article(session, event_row, "detail-one")
        _article(session, event_row, "detail-two")
        older = _score(
            session,
            sequence=1,
            event_id=event_row.id,
            calculated_at=NOW,
            score=Decimal("20"),
        )
        latest = _score(
            session,
            sequence=2,
            event_id=event_row.id,
            calculated_at=NOW,
            score=Decimal("90"),
        )
        session.commit()
        assert latest.id > older.id

    response = _request(app, f"/api/v1/events/{event_row.id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["article_count"] == 2
    assert payload["indicator_count"] == 1
    assert payload["latest_score"] == {
        "score": 90.0,
        "severity": "critical",
        "formula_version": "persisted-v1",
        "calculated_at": "2026-09-10T12:00:00Z",
    }
    assert "articles" not in payload
    assert "indicators" not in payload
    assert "canonical_evidence" not in response.text


def test_event_articles_paginate_and_use_published_then_fetched_timestamp(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    with factory() as session:
        event_row = _event(session, 5)
        published = _article(
            session,
            event_row,
            "published",
            published_at=NOW - timedelta(hours=3),
            fetched_at=NOW,
        )
        fallback = _article(
            session,
            event_row,
            "fallback",
            published_at=None,
            fetched_at=NOW - timedelta(hours=2),
        )
        session.commit()

    response = _request(app, f"/api/v1/events/{event_row.id}/articles?limit=1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert [item["id"] for item in payload["items"]] == [fallback.id]
    assert fallback.id != published.id
    item = payload["items"][0]
    assert item["categories"] == ["vulnerability", "security"]
    assert item["relationship_reason"] == "shared_canonical_cve"
    assert "raw_content" not in response.text


def test_event_indicators_paginate_order_and_select_latest_score_by_id_tie_breaker(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    with factory() as session:
        event_row = _event(session, 6)
        cve = _indicator(session, event_row, "CVE-2026-82006")
        domain = _indicator(session, event_row, "example.test", ioc_type=IOCType.DOMAIN)
        _score(
            session,
            sequence=3,
            indicator_id=cve.id,
            calculated_at=NOW,
            score=Decimal("30"),
        )
        latest = _score(
            session,
            sequence=4,
            indicator_id=cve.id,
            calculated_at=NOW,
            score=Decimal("85"),
        )
        session.commit()

    response = _request(app, f"/api/v1/events/{event_row.id}/indicators?limit=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert [item["id"] for item in payload["items"]] == [cve.id, domain.id]
    assert payload["items"][0]["latest_score"]["score"] == 85.0
    assert payload["items"][0]["latest_score"]["calculated_at"] == "2026-09-10T12:00:00Z"
    assert payload["items"][1]["latest_score"] is None
    assert latest.id > 0
    assert "canonical_evidence" not in response.text


@pytest.mark.parametrize("suffix", ["", "/articles", "/indicators"])
def test_missing_event_errors_are_stable(app: FastAPI, suffix: str) -> None:
    response = _request(app, f"/api/v1/events/999{suffix}")

    assert response.status_code == 404
    assert response.json() == {
        "error": "EVENT_NOT_FOUND",
        "message": "Correlated event was not found.",
    }


def test_cve_and_source_filters_are_exact_and_do_not_duplicate_events(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    with factory() as session:
        matched = _event(session, 7)
        other = _event(session, 8)
        _indicator(session, matched, "CVE-2026-82007")
        _indicator(session, other, "CVE-2026-82008")
        _article(session, matched, "source-one", source_name="Exact Source")
        _article(session, matched, "source-two", source_name="Exact Source")
        _article(session, other, "source-three", source_name="Other Source")
        session.commit()

    cve = _request(app, "/api/v1/events?cve=CVE-2026-82007")
    source = _request(app, "/api/v1/events?source_name=Exact%20Source")

    assert cve.json()["total"] == 1
    assert [item["id"] for item in cve.json()["items"]] == [matched.id]
    assert source.json()["total"] == 1
    assert [item["id"] for item in source.json()["items"]] == [matched.id]


def test_updated_filters_are_inclusive_and_invalid_ranges_are_stable(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    with factory() as session:
        matched = _event(session, 9, updated_at=NOW)
        _event(session, 10, updated_at=NOW - timedelta(days=2))
        session.commit()

    timestamp = "2026-09-10T12:00:00%2B00:00"
    exact = _request(
        app,
        f"/api/v1/events?updated_from={timestamp}&updated_to={timestamp}",
    )
    reversed_range = _request(
        app,
        "/api/v1/events?updated_from=2026-09-11T00:00:00%2B00:00"
        "&updated_to=2026-09-10T00:00:00%2B00:00",
    )
    naive = _request(app, "/api/v1/events?updated_from=2026-09-10T00:00:00")

    assert exact.json()["total"] == 1
    assert exact.json()["items"][0]["id"] == matched.id
    assert reversed_range.status_code == 422
    assert reversed_range.json()["error"] == "INVALID_EVENT_FILTER"
    assert naive.status_code == 422
    assert naive.json()["error"] == "INVALID_EVENT_FILTER"


@pytest.mark.parametrize("value", ["cve-2026-82001", "CVE-26-1", "not-a-cve"])
def test_invalid_cve_filters_are_stable(app: FastAPI, value: str) -> None:
    response = _request(app, f"/api/v1/events?cve={value}")

    assert response.status_code == 422
    assert response.json()["error"] == "INVALID_CVE_FILTER"


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/events?limit=0",
        "/api/v1/events?limit=101",
        "/api/v1/events?offset=-1",
        "/api/v1/events/0",
        "/api/v1/events/1/articles?limit=0",
        "/api/v1/events/1/indicators?offset=-1",
    ],
)
def test_path_and_pagination_validation(app: FastAPI, path: str) -> None:
    assert _request(app, path).status_code == 422


def test_get_endpoints_do_not_write_or_expose_enrichment_payloads(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    with factory() as session:
        event_row = _event(session, 11)
        indicator = _indicator(session, event_row, "CVE-2026-82011")
        _article(session, event_row, "readonly")
        session.add(
            IndicatorEnrichment(
                indicator_id=indicator.id,
                provider="nvd",
                status="success",
                normalized_data={"safe": True},
                raw_response={"token": "must-never-leak"},
                enriched_at=NOW,
            )
        )
        session.commit()
        before = _database_counts(session)

    def forbidden_commit(_session: Session) -> None:
        pytest.fail("read-only event endpoints must not commit")

    monkeypatch.setattr(Session, "commit", forbidden_commit)

    responses = [
        _request(app, "/api/v1/events"),
        _request(app, f"/api/v1/events/{event_row.id}"),
        _request(app, f"/api/v1/events/{event_row.id}/articles"),
        _request(app, f"/api/v1/events/{event_row.id}/indicators"),
    ]

    assert all(response.status_code == 200 for response in responses)
    assert all("must-never-leak" not in response.text for response in responses)
    with factory() as session:
        assert _database_counts(session) == before


def test_query_counts_are_bounded_as_pages_grow(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    engine, factory = api_database
    with factory() as session:
        event_row = _event(session, 12)
        for position in range(4):
            _indicator(
                session,
                event_row,
                f"CVE-2026-{82120 + position}",
            )
            _article(session, event_row, f"query-{position}")
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
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    try:
        _request(app, "/api/v1/events?limit=1")
        list_one = len(statements)
        statements.clear()
        _request(app, "/api/v1/events?limit=100")
        list_many = len(statements)
        statements.clear()
        _request(app, f"/api/v1/events/{event_row.id}/indicators?limit=1")
        indicators_one = len(statements)
        statements.clear()
        _request(app, f"/api/v1/events/{event_row.id}/indicators?limit=100")
        indicators_many = len(statements)
    finally:
        event.remove(engine, "before_cursor_execute", _record_statement)

    assert list_one == list_many == 2
    assert indicators_one == indicators_many == 2


def _database_counts(session: Session) -> tuple[int, ...]:
    return (
        session.scalar(select(func.count(CorrelatedEvent.id))) or 0,
        session.scalar(select(func.count()).select_from(EventArticle)) or 0,
        session.scalar(select(func.count()).select_from(EventIndicator)) or 0,
        session.scalar(select(func.count(ScoreHistory.id))) or 0,
        session.scalar(select(func.count(IndicatorEnrichment.id))) or 0,
    )

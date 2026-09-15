from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1 import event_scores as score_api
from app.database.base import Base
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

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)


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
def api_database() -> Generator[tuple[Engine, sessionmaker[TrackingSession]], None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        dbapi_connection.isolation_level = None  # type: ignore[attr-defined]
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
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


@pytest.fixture()
def app(
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[FastAPI, None, None]:
    _, factory = api_database
    application = create_app()

    def override_session() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    application.dependency_overrides[get_db_session] = override_session
    monkeypatch.setattr(score_api, "_utc_now", lambda: NOW)
    try:
        yield application
    finally:
        application.dependency_overrides.clear()


def _request(
    app: FastAPI,
    method: str,
    path: str,
    *,
    raise_app_exceptions: bool = True,
) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path)

    return asyncio.run(send())


def _event(
    factory: sessionmaker[TrackingSession],
    suffix: str,
    *,
    rule_version: str = "v1",
    with_relationship: bool = True,
    member_score: Decimal | None = Decimal("80.00"),
    sources: tuple[str | None, ...] = ("Source A", "Source B"),
) -> int:
    with factory() as session:
        cve = f"CVE-2026-{suffix}"
        event_row = CorrelatedEvent(
            event_key=f"cve:{cve}",
            title=f"{cve} vulnerability",
            rule_name="shared-cve",
            rule_version=rule_version,
            created_at=NOW,
            updated_at=NOW,
        )
        indicator = Indicator(indicator_type=IOCType.CVE, indicator_value=cve, created_at=NOW)
        session.add_all([event_row, indicator])
        session.flush()
        if with_relationship:
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
        if member_score is not None:
            session.add(
                ScoreHistory(
                    target_kind="indicator",
                    indicator_id=indicator.id,
                    event_id=None,
                    score=member_score,
                    severity="critical",
                    formula_version="phase6b-v1",
                    evidence_hash=f"{int(suffix):064x}",
                    canonical_evidence={"provider_secret": "must-never-leak"},
                    calculated_at=NOW,
                )
            )
        for position, source_name in enumerate(sources):
            article = RawArticle(
                source_id=f"event-score-api-{suffix}-{position}",
                source_name=source_name,
                title="Event scoring source",
                fetched_at=NOW,
                content_hash=f"event-score-api-{suffix}-{position}",
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
        session.commit()
        return event_row.id


def _stored_event_score(
    session: Session,
    event_id: int,
    *,
    sequence: int,
    calculated_at: datetime,
    score: Decimal,
    member_status: str = "present",
) -> ScoreHistory:
    row = ScoreHistory(
        target_kind="event",
        event_id=event_id,
        indicator_id=None,
        score=score,
        severity="critical" if score >= 75 else "high",
        formula_version="phase9a-event-v1",
        evidence_hash=f"{sequence:064x}",
        canonical_evidence={
            "as_of": calculated_at.isoformat().replace("+00:00", "Z"),
            "member_indicator_score": {"status": member_status},
            "provider_secret": "must-never-leak",
        },
        calculated_at=calculated_at,
        components=[
            ScoreComponentRecord(
                component_name=name,
                raw_input={"score": "80.00"} if name.startswith("member") else {"count": 2},
                normalized_input="0.8" if name.startswith("member") else "0.25",
                weight=Decimal("90") if name.startswith("member") else Decimal("10"),
                contribution=Decimal("72") if name.startswith("member") else Decimal("2.5"),
                freshness_multiplier=Decimal("1"),
                explanation=f"Safe explanation for {name}",
                provider=None,
                evidence_at=NOW if name.startswith("member") else None,
            )
            for name in ("independent_sources", "member_indicator_score")
        ],
    )
    session.add(row)
    session.flush()
    return row


def test_post_creates_then_default_reuses_complete_safe_score(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95001")
    TrackingSession.commits = 0

    first = _request(app, "POST", f"/api/v1/events/{event_id}/score")
    second = _request(app, "POST", f"/api/v1/events/{event_id}/score")

    assert first.status_code == second.status_code == 200
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert second.json()["score"]["id"] == first.json()["score"]["id"]
    score = first.json()["score"]
    assert score["event_id"] == event_id
    assert score["event_key"] == "cve:CVE-2026-95001"
    assert score["event_title"] == "CVE-2026-95001 vulnerability"
    assert score["score"] == 74.5
    assert score["severity"] == "high"
    assert score["formula_version"] == "phase9a-event-v1"
    assert len(score["evidence_hash"]) == 64
    assert score["as_of"] == "2026-09-11T12:00:00Z"
    assert [item["name"] for item in score["components"]] == [
        "member_indicator_score",
        "independent_sources",
    ]
    assert score["components"][0]["status"] == "usable"
    assert score["components"][1]["contribution"] == 2.5
    assert TrackingSession.commits == 2
    assert "canonical_evidence" not in first.text
    assert "provider_secret" not in first.text


def test_force_refresh_uses_current_time_and_still_obeys_hash_idempotency(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95002")
    first = _request(app, "POST", f"/api/v1/events/{event_id}/score")
    monkeypatch.setattr(score_api, "_utc_now", lambda: NOW + timedelta(days=1))

    default_reuse = _request(app, "POST", f"/api/v1/events/{event_id}/score")
    forced = _request(app, "POST", f"/api/v1/events/{event_id}/score?force_refresh=true")
    forced_same_time = _request(app, "POST", f"/api/v1/events/{event_id}/score?force_refresh=true")

    assert first.json()["created"] is True
    assert default_reuse.json()["created"] is False
    assert default_reuse.json()["score"]["id"] == first.json()["score"]["id"]
    assert forced.json()["created"] is True
    assert forced.json()["score"]["as_of"] == "2026-09-12T12:00:00Z"
    assert forced_same_time.json()["created"] is False
    assert forced_same_time.json()["score"]["id"] == forced.json()["score"]["id"]


def test_post_missing_member_exposes_missing_status_and_source_only_score(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95003", member_score=None, sources=("a", "b", "c"))

    response = _request(app, "POST", f"/api/v1/events/{event_id}/score")

    assert response.status_code == 200
    assert response.json()["score"]["score"] == 5.0
    components = response.json()["score"]["components"]
    assert components[0]["status"] == "missing"
    assert components[0]["contribution"] == 0.0
    assert components[1]["raw_input"] == {"count": 3}
    assert components[1]["normalized_value"] == "0.5"


def test_post_commits_once_and_rolls_back_partial_rows_on_failure(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95004")
    real_service = score_api.calculate_and_persist_event_score
    TrackingSession.commits = 0
    TrackingSession.rollbacks = 0

    def fail_after_flush(session: Session, target_id: int, *, as_of: datetime) -> None:
        real_service(session, target_id, as_of=as_of)
        raise RuntimeError("private database details must not escape")

    monkeypatch.setattr(score_api, "calculate_and_persist_event_score", fail_after_flush)
    response = _request(
        app,
        "POST",
        f"/api/v1/events/{event_id}/score",
        raise_app_exceptions=False,
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": "Internal Server Error",
        "message": "An unexpected error occurred.",
    }
    assert "private" not in response.text
    assert TrackingSession.commits == 0
    assert TrackingSession.rollbacks == 1
    with factory() as session:
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.event_id == event_id)
            )
            == 0
        )
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 0


def test_post_maps_missing_and_unscorable_events_without_internal_details(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = api_database
    unsupported = _event(factory, "95005", rule_version="v2")
    missing_relation = _event(factory, "95006", with_relationship=False)
    invalid_key = _event(factory, "95016")
    with factory() as session:
        event_row = session.get(CorrelatedEvent, invalid_key)
        assert event_row is not None
        event_row.event_key = "not-a-cve-event"
        session.commit()
    TrackingSession.rollbacks = 0

    missing = _request(app, "POST", "/api/v1/events/999/score")
    unsupported_response = _request(app, "POST", f"/api/v1/events/{unsupported}/score")
    relationship_response = _request(app, "POST", f"/api/v1/events/{missing_relation}/score")
    key_response = _request(app, "POST", f"/api/v1/events/{invalid_key}/score")

    assert missing.json() == {
        "error": "EVENT_NOT_FOUND",
        "message": "Correlated event was not found.",
    }
    for response in (unsupported_response, relationship_response, key_response):
        assert response.status_code == 422
        assert response.json() == {
            "error": "EVENT_UNSCORABLE",
            "message": "Event cannot be scored from the stored data.",
        }
        assert "CVE-2026" not in response.text
    assert TrackingSession.rollbacks == 4
    with factory() as session:
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.target_kind == "event")
            )
            == 0
        )


def test_post_maps_ambiguous_and_invalid_member_score_to_unscorable(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = api_database
    ambiguous = _event(factory, "95007")
    invalid_member = _event(factory, "95008")
    with factory() as session:
        other = Indicator(indicator_type=IOCType.CVE, indicator_value="CVE-2026-95999")
        session.add(other)
        session.flush()
        session.add(
            EventIndicator(
                event_id=ambiguous,
                indicator_id=other.id,
                reason="shared_canonical_cve",
                rule_name="shared-cve",
                rule_version="v1",
                created_at=NOW,
            )
        )
        member = session.scalar(
            select(ScoreHistory)
            .join(EventIndicator, EventIndicator.indicator_id == ScoreHistory.indicator_id)
            .where(EventIndicator.event_id == invalid_member)
        )
        assert member is not None
        member.severity = "low"
        session.commit()

    for event_id in (ambiguous, invalid_member):
        response = _request(app, "POST", f"/api/v1/events/{event_id}/score")
        assert response.status_code == 422
        assert response.json()["error"] == "EVENT_UNSCORABLE"


def test_post_does_not_convert_unrelated_integrity_error_into_success(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95009")

    def unrelated_failure(*args: object, **kwargs: object) -> None:
        raise IntegrityError("private insert", {}, RuntimeError("unrelated constraint"))

    monkeypatch.setattr(score_api, "calculate_and_persist_event_score", unrelated_failure)
    response = _request(
        app,
        "POST",
        f"/api/v1/events/{event_id}/score",
        raise_app_exceptions=False,
    )
    assert response.status_code == 500
    assert response.json()["error"] == "Internal Server Error"
    assert "constraint" not in response.text


def test_latest_uses_timestamp_and_id_tie_breaker_and_never_scores(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95010")
    with factory() as session:
        older = _stored_event_score(
            session, event_id, sequence=1, calculated_at=NOW, score=Decimal("70")
        )
        latest = _stored_event_score(
            session, event_id, sequence=2, calculated_at=NOW, score=Decimal("90")
        )
        session.commit()
        assert latest.id > older.id
    monkeypatch.setattr(
        score_api,
        "calculate_and_persist_event_score",
        lambda *args, **kwargs: pytest.fail("GET must not score"),
    )

    response = _request(app, "GET", f"/api/v1/events/{event_id}/score")

    assert response.status_code == 200
    assert response.json()["id"] == latest.id
    assert response.json()["score"] == 90.0
    assert [item["name"] for item in response.json()["components"]] == [
        "member_indicator_score",
        "independent_sources",
    ]


def test_latest_distinguishes_missing_event_from_missing_score(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95011")
    no_score = _request(app, "GET", f"/api/v1/events/{event_id}/score")
    no_event = _request(app, "GET", "/api/v1/events/999/score")
    assert no_score.json()["error"] == "EVENT_SCORE_NOT_FOUND"
    assert no_event.json()["error"] == "EVENT_NOT_FOUND"


def test_history_orders_pages_counts_and_handles_empty_and_missing(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95012")
    empty_id = _event(factory, "95013")
    with factory() as session:
        first = _stored_event_score(
            session,
            event_id,
            sequence=3,
            calculated_at=NOW - timedelta(days=1),
            score=Decimal("70"),
        )
        tied_first = _stored_event_score(
            session, event_id, sequence=4, calculated_at=NOW, score=Decimal("80")
        )
        tied_latest = _stored_event_score(
            session, event_id, sequence=5, calculated_at=NOW, score=Decimal("90")
        )
        session.commit()
    monkeypatch.setattr(
        score_api,
        "calculate_and_persist_event_score",
        lambda *args, **kwargs: pytest.fail("GET must not score"),
    )

    page = _request(app, "GET", f"/api/v1/events/{event_id}/score/history?limit=1&offset=1")
    empty = _request(app, "GET", f"/api/v1/events/{empty_id}/score/history")
    missing = _request(app, "GET", "/api/v1/events/999/score/history")
    invalid = _request(app, "GET", f"/api/v1/events/{event_id}/score/history?limit=101")

    assert page.status_code == 200
    assert page.json()["total"] == 3
    assert [item["id"] for item in page.json()["items"]] == [tied_first.id]
    assert tied_latest.id > tied_first.id > first.id
    assert empty.json() == {"event_id": empty_id, "items": [], "limit": 20, "offset": 0, "total": 0}
    assert missing.json()["error"] == "EVENT_NOT_FOUND"
    assert invalid.status_code == 422
    assert "provider_secret" not in page.text


def test_get_query_counts_are_bounded_and_endpoints_do_not_write(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
) -> None:
    engine, factory = api_database
    event_id = _event(factory, "95014")
    with factory() as session:
        for sequence in range(10, 15):
            _stored_event_score(
                session,
                event_id,
                sequence=sequence,
                calculated_at=NOW + timedelta(seconds=sequence),
                score=Decimal("80"),
            )
        session.commit()
    statements: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def record(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    TrackingSession.commits = 0
    try:
        latest = _request(app, "GET", f"/api/v1/events/{event_id}/score")
        latest_queries = len(statements)
        statements.clear()
        history = _request(app, "GET", f"/api/v1/events/{event_id}/score/history?limit=5")
        history_queries = len(statements)
        statements.clear()
        short_history = _request(app, "GET", f"/api/v1/events/{event_id}/score/history?limit=1")
        short_history_queries = len(statements)
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert latest.status_code == history.status_code == short_history.status_code == 200
    assert latest_queries == 2
    assert history_queries == short_history_queries == 3
    assert TrackingSession.commits == 0


def test_route_registration_openapi_and_positive_ids_are_stable(app: FastAPI) -> None:
    schema = app.openapi()
    paths = schema["paths"]
    assert "post" in paths["/api/v1/events/{event_id}/score"]
    assert "get" in paths["/api/v1/events/{event_id}/score"]
    assert "get" in paths["/api/v1/events/{event_id}/score/history"]
    assert paths["/api/v1/events/{event_id}/score"]["post"]["responses"]["200"]["content"]
    assert paths["/api/v1/events/{event_id}/score"]["post"]["responses"]["422"]["content"]
    assert paths["/api/v1/events/{event_id}/score"]["get"]["responses"]["404"]["content"]
    for path in ("/api/v1/events/0/score", "/api/v1/events/0/score/history"):
        assert _request(app, "GET", path).status_code == 422


def test_post_does_not_invoke_correlation_indicator_scoring_or_enrichment(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[TrackingSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    event_id = _event(factory, "95015")
    from app.ingestion.enrichment import service as enrichment_service
    from app.services import cve_correlation, indicator_scoring

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("forbidden boundary invoked")

    monkeypatch.setattr(cve_correlation, "correlate_cve_indicator", forbidden)
    monkeypatch.setattr(indicator_scoring, "calculate_and_persist_indicator_score", forbidden)
    monkeypatch.setattr(enrichment_service.EnrichmentService, "enrich_indicator", forbidden)

    response = _request(app, "POST", f"/api/v1/events/{event_id}/score")
    assert response.status_code == 200

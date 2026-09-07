from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.v1 import indicator_scores as score_api
from app.database.base import Base
from app.database.session import get_db_session
from app.ingestion.models import Indicator, IndicatorEnrichment, IOCType
from app.main import create_app
from app.models.phase6b import ScoreComponentRecord, ScoreHistory

NOW = datetime(2026, 8, 28, 12, tzinfo=UTC)


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
def app(
    api_database: tuple[Engine, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch
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


def _indicator(
    factory: sessionmaker[Session],
    *,
    ioc_type: IOCType = IOCType.CVE,
    value: str = "CVE-2026-12345",
) -> int:
    with factory() as session:
        indicator = Indicator(indicator_type=ioc_type, indicator_value=value)
        session.add(indicator)
        session.commit()
        return indicator.id


def _enrichment(
    factory: sessionmaker[Session],
    indicator_id: int,
    provider: str,
    *,
    status: str = "success",
    normalized_data: dict[str, Any] | None = None,
) -> None:
    with factory() as session:
        session.add(
            IndicatorEnrichment(
                indicator_id=indicator_id,
                provider=provider,
                status=status,
                normalized_data=normalized_data or {},
                raw_response={"api_key": "must-never-leak", "provider_payload": "secret"},
                enriched_at=NOW - timedelta(hours=1),
                expires_at=NOW + timedelta(hours=1),
            )
        )
        session.commit()


def _stored_score(
    session: Session,
    indicator_id: int,
    *,
    calculated_at: datetime,
    evidence_hash: str,
    score: Decimal,
    component_names: tuple[str, ...] = ("independent_sources",),
) -> ScoreHistory:
    history = ScoreHistory(
        target_kind="indicator",
        indicator_id=indicator_id,
        score=score,
        severity="high" if score >= 60 else "low",
        formula_version="phase6b-v1",
        evidence_hash=evidence_hash,
        canonical_evidence={
            "as_of": calculated_at.isoformat().replace("+00:00", "Z"),
            "providers": [{"provider": "nvd", "status": "missing"}],
        },
        calculated_at=calculated_at,
    )
    history.components = [
        ScoreComponentRecord(
            component_name=name,
            raw_input={"count": 1},
            normalized_input="0.2",
            weight=Decimal("10"),
            contribution=Decimal("2"),
            freshness_multiplier=Decimal("1"),
            explanation=f"Explanation for {name}",
            provider=None if name == "independent_sources" else "nvd",
            evidence_at=None,
        )
        for name in component_names
    ]
    session.add(history)
    session.flush()
    return history


def test_post_calculates_commits_and_reuses_identical_snapshot(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory)
    _enrichment(factory, indicator_id, "nvd", normalized_data={"cvss_score": 8.0})

    first = _request(app, "POST", f"/api/v1/indicators/{indicator_id}/score")
    second = _request(app, "POST", f"/api/v1/indicators/{indicator_id}/score")

    assert first.status_code == second.status_code == 200
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert second.json()["score"]["id"] == first.json()["score"]["id"]
    assert first.json()["score"]["score"] == 28.0
    assert first.json()["score"]["components"][0]["explanation"]
    assert "canonical_evidence" not in first.text
    assert "api_key" not in first.text
    with factory() as session:
        assert session.scalar(select(func.count(ScoreHistory.id))) == 1
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 5
        stored = session.get(ScoreHistory, first.json()["score"]["id"])
        assert stored is not None
        assert float(stored.score) == first.json()["score"]["score"]


def test_force_refresh_reloads_stored_evidence_without_provider_calls(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, value="CVE-2026-12346")
    _enrichment(factory, indicator_id, "nvd", status="not_found")
    first = _request(app, "POST", f"/api/v1/indicators/{indicator_id}/score")
    with factory() as session:
        row = session.scalar(
            select(IndicatorEnrichment).where(IndicatorEnrichment.indicator_id == indicator_id)
        )
        assert row is not None
        row.status = "success"
        row.normalized_data = {"cvss_score": 10.0}
        session.commit()

    refreshed = _request(
        app,
        "POST",
        f"/api/v1/indicators/{indicator_id}/score?force_refresh=true",
    )

    assert first.json()["score"]["score"] == 0.0
    assert refreshed.status_code == 200
    assert refreshed.json()["created"] is True
    assert refreshed.json()["score"]["score"] == 35.0
    assert "provider_payload" not in refreshed.text


def test_force_refresh_uses_current_time_while_default_reuses_canonical_as_of(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    indicator_id = _indicator(
        factory,
        ioc_type=IOCType.EMAIL,
        value="force-semantics@example.com",
    )
    first = _request(app, "POST", f"/api/v1/indicators/{indicator_id}/score")
    monkeypatch.setattr(score_api, "_utc_now", lambda: NOW + timedelta(days=1))

    default_reuse = _request(app, "POST", f"/api/v1/indicators/{indicator_id}/score")
    forced = _request(
        app,
        "POST",
        f"/api/v1/indicators/{indicator_id}/score?force_refresh=true",
    )

    assert first.json()["created"] is True
    assert default_reuse.json()["created"] is False
    assert default_reuse.json()["score"]["id"] == first.json()["score"]["id"]
    assert forced.json()["created"] is True
    assert forced.json()["score"]["as_of"] == "2026-08-29T12:00:00Z"


@pytest.mark.parametrize(
    ("stored_status", "api_status"),
    [
        ("not_found", "missing"),
        ("failed", "failed"),
        ("invalid", "invalid"),
        ("unsupported", "unsupported"),
    ],
)
def test_post_exposes_safe_stored_evidence_statuses(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    stored_status: str,
    api_status: str,
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, value=f"CVE-2026-22{len(stored_status):03d}")
    _enrichment(factory, indicator_id, "nvd", status=stored_status)

    response = _request(app, "POST", f"/api/v1/indicators/{indicator_id}/score")

    nvd = next(item for item in response.json()["score"]["components"] if item["provider"] == "nvd")
    assert response.status_code == 200
    assert nvd["status"] == api_status


def test_post_missing_and_unscorable_indicator_errors_are_stable(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    missing = _request(app, "POST", "/api/v1/indicators/999/score")
    invalid_id = _indicator(factory, value="not-a-cve")
    invalid = _request(app, "POST", f"/api/v1/indicators/{invalid_id}/score")

    assert missing.status_code == 404
    assert missing.json() == {
        "error": "INDICATOR_NOT_FOUND",
        "message": "Indicator was not found.",
    }
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "INDICATOR_UNSCORABLE"


def test_post_service_failure_rolls_back_partial_rows_and_hides_details(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, ioc_type=IOCType.EMAIL, value="rollback@example.com")
    real_service = score_api.calculate_and_persist_indicator_score

    def fail_after_flush(session: Session, target_id: int, *, as_of: datetime) -> None:
        real_service(session, target_id, as_of=as_of)
        raise RuntimeError("database credentials and SQL must remain private")

    monkeypatch.setattr(score_api, "calculate_and_persist_indicator_score", fail_after_flush)
    response = _request(
        app,
        "POST",
        f"/api/v1/indicators/{indicator_id}/score?force_refresh=false",
        raise_app_exceptions=False,
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": "Internal Server Error",
        "message": "An unexpected error occurred.",
    }
    assert "credentials" not in response.text
    with factory() as session:
        assert session.scalar(select(func.count(ScoreHistory.id))) == 0
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 0


def test_post_does_not_convert_unrelated_integrity_error_into_success(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, ioc_type=IOCType.EMAIL, value="integrity@example.com")

    def unrelated_failure(*args: object, **kwargs: object) -> None:
        raise IntegrityError("INSERT private_table", {}, RuntimeError("unrelated constraint"))

    monkeypatch.setattr(score_api, "calculate_and_persist_indicator_score", unrelated_failure)
    response = _request(
        app,
        "POST",
        f"/api/v1/indicators/{indicator_id}/score",
        raise_app_exceptions=False,
    )

    assert response.status_code == 500
    assert response.json()["error"] == "Internal Server Error"
    assert "constraint" not in response.text
    with factory() as session:
        assert session.scalar(select(func.count(ScoreHistory.id))) == 0


def test_latest_is_deterministic_includes_components_and_is_read_only(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, value="CVE-2026-12347")
    with factory() as session:
        older = _stored_score(
            session,
            indicator_id,
            calculated_at=NOW,
            evidence_hash="a" * 64,
            score=Decimal("10"),
        )
        latest = _stored_score(
            session,
            indicator_id,
            calculated_at=NOW,
            evidence_hash="b" * 64,
            score=Decimal("70"),
            component_names=("nvd_cvss", "independent_sources"),
        )
        session.commit()
        assert latest.id > older.id
    monkeypatch.setattr(
        score_api,
        "calculate_and_persist_indicator_score",
        lambda *args, **kwargs: pytest.fail("GET must not recalculate"),
    )

    response = _request(app, "GET", f"/api/v1/indicators/{indicator_id}/score")

    assert response.status_code == 200
    assert response.json()["id"] == latest.id
    assert [item["name"] for item in response.json()["components"]] == [
        "independent_sources",
        "nvd_cvss",
    ]
    assert response.json()["components"][1]["explanation"] == "Explanation for nvd_cvss"
    with factory() as session:
        assert session.scalar(select(func.count(ScoreHistory.id))) == 2


def test_latest_distinguishes_missing_indicator_from_missing_score(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, ioc_type=IOCType.EMAIL, value="none@example.com")

    no_score = _request(app, "GET", f"/api/v1/indicators/{indicator_id}/score")
    no_indicator = _request(app, "GET", "/api/v1/indicators/999/score")

    assert no_score.status_code == 404
    assert no_score.json()["error"] == "SCORE_NOT_FOUND"
    assert no_indicator.status_code == 404
    assert no_indicator.json()["error"] == "INDICATOR_NOT_FOUND"


def test_history_orders_pages_counts_and_handles_empty_history(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    _, factory = api_database
    indicator_id = _indicator(factory, value="CVE-2026-12348")
    with factory() as session:
        first = _stored_score(
            session,
            indicator_id,
            calculated_at=NOW - timedelta(hours=1),
            evidence_hash="a" * 64,
            score=Decimal("10"),
        )
        second = _stored_score(
            session,
            indicator_id,
            calculated_at=NOW,
            evidence_hash="b" * 64,
            score=Decimal("20"),
        )
        third = _stored_score(
            session,
            indicator_id,
            calculated_at=NOW,
            evidence_hash="c" * 64,
            score=Decimal("30"),
        )
        session.commit()
        expected = [third.id, second.id, first.id]

    default_page = _request(app, "GET", f"/api/v1/indicators/{indicator_id}/score/history")
    custom_page = _request(
        app,
        "GET",
        f"/api/v1/indicators/{indicator_id}/score/history?limit=1&offset=1",
    )
    empty_id = _indicator(factory, ioc_type=IOCType.EMAIL, value="empty@example.com")
    empty = _request(app, "GET", f"/api/v1/indicators/{empty_id}/score/history")

    assert default_page.status_code == 200
    assert default_page.json()["limit"] == 20
    assert default_page.json()["offset"] == 0
    assert default_page.json()["total"] == 3
    assert [item["id"] for item in default_page.json()["items"]] == expected
    assert [item["id"] for item in custom_page.json()["items"]] == [second.id]
    assert empty.json() == {
        "indicator_id": empty_id,
        "items": [],
        "limit": 20,
        "offset": 0,
        "total": 0,
    }


@pytest.mark.parametrize(
    "query",
    ["limit=0", "limit=101", "offset=-1", "limit=abc", "offset=abc"],
)
def test_history_rejects_invalid_pagination(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
    query: str,
) -> None:
    _, factory = api_database
    indicator_id = _indicator(
        factory,
        ioc_type=IOCType.EMAIL,
        value=f"pagination-{query.replace('=', '-')}@example.com",
    )

    response = _request(
        app,
        "GET",
        f"/api/v1/indicators/{indicator_id}/score/history?{query}",
    )

    assert response.status_code == 422
    assert "detail" in response.json()


def test_history_missing_indicator_and_path_validation(
    app: FastAPI,
) -> None:
    missing = _request(app, "GET", "/api/v1/indicators/999/score/history")
    malformed = _request(app, "GET", "/api/v1/indicators/not-an-int/score/history")
    zero = _request(app, "GET", "/api/v1/indicators/0/score")

    assert missing.status_code == 404
    assert missing.json()["error"] == "INDICATOR_NOT_FOUND"
    assert malformed.status_code == zero.status_code == 422


def test_latest_and_history_queries_are_constant_with_many_components(
    app: FastAPI,
    api_database: tuple[Engine, sessionmaker[Session]],
) -> None:
    engine, factory = api_database
    indicator_id = _indicator(factory, value="CVE-2026-12349")
    with factory() as session:
        for position in range(3):
            _stored_score(
                session,
                indicator_id,
                calculated_at=NOW + timedelta(seconds=position),
                evidence_hash=f"{position + 1:064x}",
                score=Decimal("50"),
                component_names=("one", "two", "three", "four", "five"),
            )
        session.commit()

    statements: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def count_selects(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    try:
        latest = _request(app, "GET", f"/api/v1/indicators/{indicator_id}/score")
        latest_count = len(statements)
        statements.clear()
        history = _request(app, "GET", f"/api/v1/indicators/{indicator_id}/score/history")
        history_count = len(statements)
    finally:
        event.remove(engine, "before_cursor_execute", count_selects)

    assert latest.status_code == history.status_code == 200
    assert latest_count == 2
    assert history_count == 4
    assert len(history.json()["items"]) == 3


def test_openapi_contract_lists_routes_models_and_actual_statuses(
    app: FastAPI,
) -> None:
    schema = app.openapi()
    score_path = schema["paths"]["/api/v1/indicators/{indicator_id}/score"]
    history_path = schema["paths"]["/api/v1/indicators/{indicator_id}/score/history"]

    assert set(score_path) == {"get", "post"}
    assert set(history_path) == {"get"}
    assert "IndicatorScorePostResponse" in schema["components"]["schemas"]
    assert "IndicatorScoreResponse" in schema["components"]["schemas"]
    assert "IndicatorScoreHistoryResponse" in schema["components"]["schemas"]
    assert "200" in score_path["post"]["responses"]
    assert "404" in score_path["get"]["responses"]
    force_parameter = next(
        item for item in score_path["post"]["parameters"] if item["name"] == "force_refresh"
    )
    assert force_parameter["schema"]["default"] is False

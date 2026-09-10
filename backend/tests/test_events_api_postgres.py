from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
from alembic import command
from fastapi import FastAPI
from sqlalchemy.orm import Session, sessionmaker

from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    create_guarded_test_engine,
    run_guarded_alembic_command,
)
from app.database.session import get_db_session
from app.ingestion.models import Indicator, IOCType, RawArticle
from app.main import create_app
from app.models.phase6b import CorrelatedEvent, EventArticle, EventIndicator, ScoreHistory

NOW = datetime(2026, 9, 10, 14, tzinfo=UTC)


def _request(app: FastAPI, path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(path)

    return asyncio.run(send())


def test_postgres_event_api_filters_orders_and_selects_latest_scores(
    phase6b_postgres_database: OwnedDisposablePostgres,
) -> None:
    url = phase6b_postgres_database.url
    run_guarded_alembic_command(url, command.upgrade, "head")
    engine = create_guarded_test_engine(url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        event_row = CorrelatedEvent(
            event_key="cve:CVE-2026-83001",
            title="CVE-2026-83001 vulnerability",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
            updated_at=NOW,
        )
        indicator = Indicator(
            indicator_type=IOCType.CVE,
            indicator_value="CVE-2026-83001",
            created_at=NOW,
        )
        session.add_all([event_row, indicator])
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
        articles = [
            RawArticle(
                source_id=f"event-api-postgres-{position}",
                source_name="PostgreSQL Exact Source",
                title=f"PostgreSQL article {position}",
                published_at=published_at,
                fetched_at=fetched_at,
                content_hash=f"event-api-postgres-{position}",
            )
            for position, published_at, fetched_at in (
                (1, NOW - timedelta(hours=3), NOW),
                (2, None, NOW - timedelta(hours=2)),
            )
        ]
        session.add_all(articles)
        session.flush()
        session.add_all(
            EventArticle(
                event_id=event_row.id,
                article_id=article.id,
                reason="shared_canonical_cve",
                rule_name="shared-cve",
                rule_version="v1",
                created_at=NOW,
            )
            for article in articles
        )
        session.add_all(
            [
                ScoreHistory(
                    target_kind="event",
                    event_id=event_row.id,
                    score=Decimal(score),
                    severity=severity,
                    formula_version="postgres-event-v1",
                    evidence_hash=f"{sequence:064x}",
                    canonical_evidence={"private": True},
                    calculated_at=NOW,
                )
                for sequence, score, severity in (
                    (83001, "20", "medium"),
                    (83002, "90", "critical"),
                )
            ]
        )
        session.add_all(
            [
                ScoreHistory(
                    target_kind="indicator",
                    indicator_id=indicator.id,
                    score=Decimal(score),
                    severity=severity,
                    formula_version="postgres-indicator-v1",
                    evidence_hash=f"{sequence:064x}",
                    canonical_evidence={"private": True},
                    calculated_at=NOW,
                )
                for sequence, score, severity in (
                    (83003, "30", "medium"),
                    (83004, "85", "critical"),
                )
            ]
        )
        session.commit()
        event_id = event_row.id
        fallback_article_id = articles[1].id

    application = create_app()

    def override_session() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    application.dependency_overrides[get_db_session] = override_session
    try:
        filtered = _request(
            application,
            "/api/v1/events?cve=CVE-2026-83001&source_name=PostgreSQL%20Exact%20Source",
        )
        detail = _request(application, f"/api/v1/events/{event_id}")
        article_page = _request(application, f"/api/v1/events/{event_id}/articles?limit=1")
        indicator_page = _request(application, f"/api/v1/events/{event_id}/indicators")

        assert filtered.status_code == detail.status_code == 200
        assert filtered.json()["total"] == 1
        assert [item["id"] for item in filtered.json()["items"]] == [event_id]
        assert detail.json()["latest_score"]["score"] == 90.0
        assert article_page.json()["total"] == 2
        assert article_page.json()["items"][0]["id"] == fallback_article_id
        assert indicator_page.json()["items"][0]["latest_score"]["score"] == 85.0
        assert "canonical_evidence" not in "".join(
            response.text for response in (filtered, detail, article_page, indicator_page)
        )
    finally:
        application.dependency_overrides.clear()
        engine.dispose()

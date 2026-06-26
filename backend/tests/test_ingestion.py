from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.ingestion.feed_manager import FeedManager
from app.ingestion.models import NormalizedArticle
from app.ingestion.normalizer import RSSNormalizer
from app.ingestion.registry import FeedRegistry, FeedSource
from app.ingestion.rss_client import RSSClient
from app.ingestion.scheduler import build_beat_schedule
from app.ingestion.services import IngestionService


@pytest.fixture()
def sqlite_session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    yield SessionLocal
    Base.metadata.drop_all(engine)


def test_rss_parsing_normalizes_entries() -> None:
    source = FeedSource(name="Demo Feed", url="https://example.com/rss", poll_interval_minutes=15)
    normalizer = RSSNormalizer()
    raw_content = """<?xml version=\"1.0\"?>
    <rss version=\"2.0\">
      <channel>
        <title>Demo</title>
        <item>
          <title>First alert</title>
          <description>Example description</description>
          <link>https://example.com/1</link>
          <pubDate>Wed, 26 Jun 2026 12:00:00 GMT</pubDate>
          <author>Analyst</author>
          <category>malware</category>
        </item>
      </channel>
    </rss>"""

    articles = normalizer.normalize(source, raw_content)

    assert len(articles) == 1
    assert articles[0].title == "First alert"
    assert articles[0].source_name == "Demo Feed"
    assert articles[0].url == "https://example.com/1"


def test_duplicate_detection_skips_existing_articles(sqlite_session_factory) -> None:
    manager = FeedManager(session_factory=sqlite_session_factory)
    article = NormalizedArticle(
        source_id="Demo Feed",
        title="Duplicate",
        description="A duplicate entry",
        url="https://example.com/duplicate",
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["phishing"],
        source_name="Demo Feed",
        raw_content="raw",
    )

    first_store = manager.store(article)
    second_store = manager.store(article)

    assert first_store is True
    assert second_store is False


def test_database_insertion_persists_raw_article(sqlite_session_factory) -> None:
    manager = FeedManager(session_factory=sqlite_session_factory)
    article = NormalizedArticle(
        source_id="Demo Feed",
        title="Stored item",
        description="Persisted for testing",
        url="https://example.com/stored",
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["ransomware"],
        source_name="Demo Feed",
        raw_content="raw-body",
    )

    stored = manager.store(article)
    assert stored is True
    assert manager.count() == 1


def test_scheduler_builds_beat_schedule() -> None:
    registry = FeedRegistry(
        [
            FeedSource(name="Feed A", url="https://example.com/a", poll_interval_minutes=10),
            FeedSource(name="Feed B", url="https://example.com/b", poll_interval_minutes=20, enabled=False),
        ]
    )

    schedule = build_beat_schedule(registry)

    assert "ingest-feed-a" in schedule
    assert "ingest-feed-b" not in schedule
    assert schedule["ingest-feed-a"]["task"] == "app.ingestion.scheduler.run_ingestion_task"


def test_rss_client_fetches_raw_content(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def __init__(self, text: str) -> None:
            self.text = text

        def raise_for_status(self) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.kwargs = kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        async def get(self, url: str) -> FakeResponse:
            return FakeResponse("<rss />")

    monkeypatch.setattr("app.ingestion.rss_client.httpx.AsyncClient", FakeAsyncClient)
    client = RSSClient(timeout=1.0, max_retries=1)

    content = asyncio.run(client.fetch(FeedSource(name="Test", url="https://example.com/rss", poll_interval_minutes=5)))

    assert content == "<rss />"


def test_ingestion_service_runs_and_persists_articles(sqlite_session_factory) -> None:
    class FakeClient:
        async def fetch(self, source: FeedSource) -> str:
            return """<?xml version=\"1.0\"?>
            <rss version=\"2.0\">
              <channel>
                <item><title>Service item</title><description>Body</description><link>https://example.com/service</link></item>
              </channel>
            </rss>"""

    feed_manager = FeedManager(session_factory=sqlite_session_factory)
    registry = FeedRegistry([FeedSource(name="Service Feed", url="https://example.com/rss", poll_interval_minutes=5)])
    service = IngestionService(registry=registry, rss_client=FakeClient(), feed_manager=feed_manager)

    stats = service.run_all()

    assert stats["stored"] == 1
    assert stats["fetched"] == 1
    assert feed_manager.count() == 1


def test_registry_from_settings_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INGESTION_FEEDS_JSON", '[{"name": "Env Feed", "url": "https://example.com/env", "poll_interval_minutes": 7}]')

    registry = FeedRegistry.from_settings()

    assert registry.get_enabled_sources()[0].name == "Env Feed"

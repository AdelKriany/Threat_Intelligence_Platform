from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.feed_manager import FeedManager
from app.ingestion.models import Indicator, IOCType, NormalizedArticle, RawArticle
from app.ingestion.normalizer import RSSNormalizer
from app.ingestion.registry import FeedRegistry, FeedSource
from app.ingestion.rss_client import RSSClient
from app.ingestion.scheduler import build_beat_schedule
from app.ingestion.services import IngestionService


@pytest.fixture()
def sqlite_session_factory() -> Generator[sessionmaker[Session], None, None]:
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


def test_duplicate_detection_skips_existing_articles(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
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

    first_store, first_iocs = manager.store(article)
    second_store, second_iocs = manager.store(article)

    assert first_store is True
    assert first_iocs == 2
    assert second_store is False
    assert second_iocs == 0


def test_database_insertion_persists_raw_article(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
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

    stored, ioc_count = manager.store(article)
    assert stored is True
    assert ioc_count == 2
    assert manager.count() == 1


def test_article_with_no_iocs_persists_zero_indicators(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    manager = FeedManager(session_factory=sqlite_session_factory)
    article = NormalizedArticle(
        source_id="Demo Feed",
        title="No indicators here",
        description="A benign status update with no IOC content",
        url=None,
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["news"],
        source_name="Demo Feed",
        raw_content="This text contains no indicators at all.",
    )

    stored, ioc_count = manager.store(article)

    assert stored is True
    assert ioc_count == 0
    with sqlite_session_factory() as session:
        assert session.query(Indicator).count() == 0


def test_duplicate_iocs_in_one_article_create_one_row(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    manager = FeedManager(session_factory=sqlite_session_factory)
    article = NormalizedArticle(
        source_id="Demo Feed",
        title="Repeated IOC",
        description="8.8.8.8 8.8.8.8 8.8.8.8",
        url=None,
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["network"],
        source_name="Demo Feed",
        raw_content="Observed beaconing to 8.8.8.8 again.",
    )

    stored, ioc_count = manager.store(article)

    assert stored is True
    assert ioc_count == 1
    with sqlite_session_factory() as session:
        indicators = session.query(Indicator).all()
        assert len(indicators) == 1
        assert indicators[0].indicator_type == IOCType.IPV4
        assert indicators[0].indicator_value == "8.8.8.8"


def test_same_ioc_in_different_articles_is_stored_per_article(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    manager = FeedManager(session_factory=sqlite_session_factory)
    first = NormalizedArticle(
        source_id="Demo Feed",
        title="First IOC report",
        description="IOC 9.9.9.9 observed",
        url=None,
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["network"],
        source_name="Demo Feed",
        raw_content="9.9.9.9",
    )
    second = NormalizedArticle(
        source_id="Demo Feed",
        title="Second IOC report",
        description="IOC 9.9.9.9 observed again",
        url=None,
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["network"],
        source_name="Demo Feed",
        raw_content="9.9.9.9",
    )

    first_stored, first_count = manager.store(first)
    second_stored, second_count = manager.store(second)

    assert first_stored is True
    assert second_stored is True
    assert first_count == 1
    assert second_count == 1

    with sqlite_session_factory() as session:
        indicators = (
            session.query(Indicator)
            .filter(
                Indicator.indicator_type == IOCType.IPV4, Indicator.indicator_value == "9.9.9.9"
            )
            .all()
        )
        assert len(indicators) == 2
        assert indicators[0].raw_article_id != indicators[1].raw_article_id


def test_indicators_reference_their_source_article(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    manager = FeedManager(session_factory=sqlite_session_factory)
    article = NormalizedArticle(
        source_id="Demo Feed",
        title="Reference test",
        description="CVE-2026-12345 is present",
        url=None,
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["vuln"],
        source_name="Demo Feed",
        raw_content="",
    )

    stored, ioc_count = manager.store(article)

    assert stored is True
    assert ioc_count == 1

    with sqlite_session_factory() as session:
        raw_article = session.query(RawArticle).filter(RawArticle.url == article.url).one()
        indicator = (
            session.query(Indicator).filter(Indicator.raw_article_id == raw_article.id).one()
        )

        assert indicator.raw_article_id == raw_article.id
        assert indicator.raw_article.id == raw_article.id


def test_scheduler_builds_beat_schedule() -> None:
    registry = FeedRegistry(
        [
            FeedSource(name="Feed A", url="https://example.com/a", poll_interval_minutes=10),
            FeedSource(
                name="Feed B", url="https://example.com/b", poll_interval_minutes=20, enabled=False
            ),
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

        async def get(self, url: str, **kwargs: object) -> FakeResponse:
            return FakeResponse("<rss />")

    monkeypatch.setattr("app.ingestion.rss_client.httpx.AsyncClient", FakeAsyncClient)
    client = RSSClient(timeout=1.0, max_retries=1)

    content = asyncio.run(
        client.fetch(
            FeedSource(name="Test", url="https://example.com/rss", poll_interval_minutes=5)
        )
    )

    assert content == "<rss />"


def test_ingestion_service_runs_and_persists_articles(
    sqlite_session_factory: sessionmaker[Session],
) -> None:
    class FakeClient:
        async def fetch(self, source: FeedSource) -> str:
            return """<?xml version=\"1.0\"?>
            <rss version=\"2.0\">
              <channel>
                <item><title>Service item</title><description>Body</description><link>https://example.com/service</link></item>
              </channel>
            </rss>"""

    feed_manager = FeedManager(session_factory=sqlite_session_factory)
    registry = FeedRegistry(
        [FeedSource(name="Service Feed", url="https://example.com/rss", poll_interval_minutes=5)]
    )
    service = IngestionService(
        registry=registry, rss_client=FakeClient(), feed_manager=feed_manager
    )

    stats = service.run_all()

    assert stats["stored"] == 1
    assert stats["fetched"] == 1
    assert stats["iocs_extracted"] == 2
    assert feed_manager.count() == 1


def test_registry_from_settings_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "INGESTION_FEEDS_JSON",
        '[{"name": "Env Feed", "url": "https://example.com/env", "poll_interval_minutes": 7}]',
    )

    registry = FeedRegistry.from_settings()

    assert registry.get_enabled_sources()[0].name == "Env Feed"

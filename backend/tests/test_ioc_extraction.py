from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Enum as SQLEnum
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.ingestion.feed_manager import FeedManager
from app.ingestion.ioc.extractor import IOCExtractionService
from app.ingestion.models import Indicator, IOCType, NormalizedArticle, RawArticle


def _build_raw_article(content: str, url: str | None = "https://unit.test/article") -> RawArticle:
    now = datetime.now(timezone.utc)
    return RawArticle(
        source_id="unit-test",
        source_name="Unit Test Feed",
        title="IOC sample",
        description=content,
        url=url,
        published_at=now,
        fetched_at=now,
        raw_content=content,
        content_hash="sample-content-hash",
        author="tester",
        categories="test",
        created_at=now,
    )


def test_ioc_extractor_finds_all_supported_types() -> None:
    sample_text = """
    Threat bulletin references CVE-2026-12345 and C2 host 185.199.110.153.
    Secondary node is 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
    Visit https://evil-example.com/login?next=alert and email soc@evil-example.com.
    Hashes: d41d8cd98f00b204e9800998ecf8427e,
    da39a3ee5e6b4b0d3255bfef95601890afd80709,
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
    Domain indicator: evil-example.com.
    """

    extractor = IOCExtractionService()
    indicators = extractor.extract(_build_raw_article(sample_text))

    actual = {(item.indicator_type, item.indicator_value) for item in indicators}

    assert (IOCType.CVE, "CVE-2026-12345") in actual
    assert (IOCType.IPV4, "185.199.110.153") in actual
    assert (IOCType.IPV6, "2001:db8:85a3::8a2e:370:7334") in actual
    assert (IOCType.DOMAIN, "evil-example.com") in actual
    assert (IOCType.URL, "https://evil-example.com/login?next=alert") in actual
    assert (IOCType.EMAIL, "soc@evil-example.com") in actual
    assert (IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e") in actual
    assert (IOCType.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709") in actual
    assert (
        IOCType.SHA256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ) in actual


def test_ioc_extractor_filters_invalid_candidates() -> None:
    sample_text = """
    Invalid values should be ignored: CVE-2026-12, 999.999.999.999,
    hxxp://malicious_local, deadbeef, and local token localhost.
    """

    extractor = IOCExtractionService()
    indicators = extractor.extract(_build_raw_article(sample_text, url=None))

    assert indicators == []


def test_ioc_extractor_deduplicates_and_normalizes_values() -> None:
    sample_text = """
    cve-2026-7777 repeated as CVE-2026-7777.
    MD5 D41D8CD98F00B204E9800998ECF8427E and d41d8cd98f00b204e9800998ecf8427e.
    """

    extractor = IOCExtractionService()
    indicators = extractor.extract(_build_raw_article(sample_text))
    actual = {(item.indicator_type, item.indicator_value) for item in indicators}

    assert (IOCType.CVE, "CVE-2026-7777") in actual
    assert (IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e") in actual
    assert sum(1 for item in indicators if item.indicator_type is IOCType.CVE) == 1
    assert sum(1 for item in indicators if item.indicator_type is IOCType.MD5) == 1


def test_feed_manager_persists_extracted_indicators() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    manager = FeedManager(session_factory=session_factory)
    article = NormalizedArticle(
        source_id="Demo Feed",
        title="IOC article",
        description="Detected CVE-2026-9999 from bad.example and 10.20.30.40",
        url="https://bad.example/report",
        published_at=datetime.now(timezone.utc),
        author="Analyst",
        categories=["threat"],
        source_name="Demo Feed",
        raw_content="Contact ir@bad.example",
    )

    stored, ioc_count = manager.store(article)

    assert stored is True
    assert ioc_count >= 4

    with session_factory() as session:
        stored_indicators = session.scalars(select(Indicator)).all()

    assert len(stored_indicators) >= 4
    stored_types = {indicator.indicator_type for indicator in stored_indicators}
    assert IOCType.CVE in stored_types
    assert IOCType.DOMAIN in stored_types
    assert IOCType.IPV4 in stored_types
    assert IOCType.EMAIL in stored_types


def test_indicator_enum_persists_lowercase_values() -> None:
    enum_type = Indicator.__table__.c.indicator_type.type
    assert isinstance(enum_type, SQLEnum)
    assert enum_type.enums == [member.value for member in IOCType]

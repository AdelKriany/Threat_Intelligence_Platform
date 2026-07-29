from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.database.base import Base
from app.ingestion.enrichment.exceptions import (
    ProviderAuthenticationError,
    ProviderRateLimitError,
    ProviderTemporaryError,
)
from app.ingestion.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.ingestion.enrichment.providers.base import EnrichmentProvider
from app.ingestion.enrichment.providers.nvd import NVDProvider
from app.ingestion.enrichment.providers.virustotal import VirusTotalProvider
from app.ingestion.enrichment.registry import ProviderRegistry
from app.ingestion.enrichment.service import EnrichmentService
from app.ingestion.enrichment.tasks import build_pending_indicator_query
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.feed_manager import FeedManager
from app.ingestion.models import (
    Indicator,
    IndicatorEnrichment,
    IOCType,
    NormalizedArticle,
    RawArticle,
)


@pytest.fixture()
def enrichment_db() -> Generator[tuple[sessionmaker[Session], int], None, None]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    with factory() as session:
        article = RawArticle(
            source_id="test",
            title="test",
            fetched_at=now,
            content_hash="enrichment-test",
            created_at=now,
        )
        session.add(article)
        session.flush()
        indicator = Indicator(
            raw_article_id=article.id,
            indicator_type=IOCType.CVE,
            indicator_value="CVE-2026-12345",
        )
        session.add(indicator)
        session.commit()
        indicator_id = indicator.id
    yield factory, indicator_id
    Base.metadata.drop_all(engine)


def test_provider_selection_and_disabled_credentials() -> None:
    nvd = NVDProvider(enabled=True)
    abuse = AbuseIPDBProvider(api_key=None)
    vt = VirusTotalProvider(api_key=None)
    registry = ProviderRegistry([nvd, abuse, vt])

    assert registry.for_ioc_type(IOCType.CVE) == [nvd]
    assert registry.for_ioc_type(IOCType.EMAIL) == []
    assert abuse.enabled is False
    assert vt.enabled is False


def test_nvd_is_enabled_without_api_key_from_worker_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.setenv("NVD_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_ENABLED", "false")
    monkeypatch.setenv("VIRUSTOTAL_ENABLED", "false")
    monkeypatch.setenv("CISA_KEV_ENABLED", "false")
    monkeypatch.setenv("EPSS_ENABLED", "false")

    config = Settings()
    registry = ProviderRegistry.from_settings(config)

    assert config.enrichment_enabled is True
    assert config.nvd_enabled is True
    assert config.abuseipdb_enabled is False
    assert config.virustotal_enabled is False
    assert [provider.name for provider in registry.for_ioc_type(IOCType.CVE)] == ["nvd"]


def test_compose_passes_enrichment_flags_to_all_application_services() -> None:
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    for variable in (
        "ENRICHMENT_ENABLED",
        "NVD_ENABLED",
        "ABUSEIPDB_ENABLED",
        "VIRUSTOTAL_ENABLED",
    ):
        assert compose.count(f"{variable}: ${{{variable}:") == 3


def test_enrichment_tasks_are_registered() -> None:
    from app.workers.celery_app import celery_app

    expected = {
        "app.ingestion.enrichment.tasks.enrich_indicator_task",
        "app.ingestion.enrichment.tasks.enrich_article_indicators_task",
        "app.ingestion.enrichment.tasks.enrich_pending_batch_task",
    }

    assert expected.issubset(celery_app.tasks)


def test_nvd_normalization() -> None:
    result = NVDProvider().normalize(
        7,
        "CVE-2026-12345",
        IOCType.CVE,
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-12345",
                        "published": "2026-01-01T00:00:00Z",
                        "lastModified": "2026-01-02T00:00:00Z",
                        "descriptions": [{"lang": "en", "value": "Remote code execution."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    },
                                }
                            ]
                        },
                        "references": [{"url": "https://vendor.example/advisory"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        },
    )

    assert result.status is EnrichmentStatus.SUCCESS
    assert result.risk_score == 98.0
    assert result.severity == "critical"
    assert result.normalized_data["cvss_version"] == "3.1"
    assert result.normalized_data["affected_cpes"]


def test_abuseipdb_normalization() -> None:
    result = AbuseIPDBProvider(api_key="test").normalize(
        1,
        "8.8.8.8",
        IOCType.IPV4,
        {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 75,
                "countryCode": "US",
                "usageType": "Data Center",
                "isp": "Example",
                "domain": "example.net",
                "totalReports": 12,
                "lastReportedAt": "2026-01-01T00:00:00Z",
                "isWhitelisted": False,
            }
        },
    )

    assert result.risk_score == 75.0
    assert result.severity == "high"
    assert result.normalized_data["total_reports"] == 12


def test_virustotal_normalization_and_url_identifier() -> None:
    provider = VirusTotalProvider(api_key="test")
    assert (
        provider.url_identifier("https://example.com/a?b=1") == "aHR0cHM6Ly9leGFtcGxlLmNvbS9hP2I9MQ"
    )
    result = provider.normalize(
        1,
        "example.com",
        IOCType.DOMAIN,
        {
            "data": {
                "id": "example.com",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 7,
                    },
                    "reputation": -10,
                    "tags": ["phishing"],
                    "categories": {"Vendor": "malicious"},
                    "last_analysis_date": 1_700_000_000,
                },
            }
        },
    )

    assert result.risk_score == 30.0
    assert result.normalized_data["object_id"] == "example.com"
    assert result.normalized_data["tags"] == ["phishing"]


class FakeProvider(EnrichmentProvider):
    name = "fake"
    supported_ioc_types = frozenset({IOCType.CVE})

    def __init__(self, *, failure: Exception | None = None) -> None:
        super().__init__(enabled=True, timeout=0.1, max_retries=0)
        self.calls = 0
        self.failure = failure

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        self.calls += 1
        if self.failure:
            raise self.failure
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=indicator_value,
            indicator_type=ioc_type,
            provider=self.name,
            status=EnrichmentStatus.SUCCESS,
            risk_score=50,
            normalized_data={"ok": True},
            enriched_at=datetime.now(UTC),
        )

    def normalize(
        self,
        indicator_id: int,
        indicator_value: str,
        ioc_type: IOCType,
        payload: dict[str, Any],
    ) -> EnrichmentResult:
        raise NotImplementedError


class FailedProvider(FakeProvider):
    name = "failed"


def test_persistence_cache_force_refresh_and_expiry(
    enrichment_db: tuple[sessionmaker[Session], int],
) -> None:
    factory, indicator_id = enrichment_db
    provider = FakeProvider()
    with factory() as session:
        service = EnrichmentService(session, registry=ProviderRegistry([provider]), ttl_seconds=60)
        first = asyncio.run(service.enrich_indicator(indicator_id))
        second = asyncio.run(service.enrich_indicator(indicator_id))
        forced = asyncio.run(service.enrich_indicator(indicator_id, force_refresh=True))

        assert first[0].cached is False
        assert second[0].cached is True
        assert forced[0].cached is False
        assert provider.calls == 2
        assert session.query(IndicatorEnrichment).count() == 1

        record = session.scalar(select(IndicatorEnrichment))
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
        asyncio.run(service.enrich_indicator(indicator_id))
        assert provider.calls == 3
        assert session.query(IndicatorEnrichment).count() == 1


def test_partial_provider_failure_is_persisted(
    enrichment_db: tuple[sessionmaker[Session], int],
) -> None:
    factory, indicator_id = enrichment_db
    successful = FakeProvider()
    failed = FailedProvider(failure=ProviderTemporaryError("temporary"))
    with factory() as session:
        results = asyncio.run(
            EnrichmentService(
                session,
                registry=ProviderRegistry([successful, failed]),
                ttl_seconds=60,
            ).enrich_indicator(indicator_id)
        )

        assert {result.status for result in results} == {
            EnrichmentStatus.SUCCESS,
            EnrichmentStatus.TEMPORARY_FAILURE,
        }
        assert session.query(IndicatorEnrichment).count() == 2


@pytest.mark.parametrize(
    ("status_code", "exception_type"),
    [
        (401, ProviderAuthenticationError),
        (403, ProviderAuthenticationError),
        (429, ProviderRateLimitError),
    ],
)
def test_http_permanent_status_handling(status_code: int, exception_type: type[Exception]) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status_code, request=request, json={})
    )
    client = httpx.AsyncClient(transport=transport)
    provider = NVDProvider(client=client, max_retries=2)
    with pytest.raises(exception_type):
        asyncio.run(provider.enrich(1, "CVE-2026-12345", IOCType.CVE))
    asyncio.run(client.aclose())


def test_http_timeout_is_bounded() -> None:
    calls = 0

    def timeout(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("timed out", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(timeout))
    provider = NVDProvider(client=client, max_retries=1)
    with pytest.raises(ProviderTemporaryError):
        asyncio.run(provider.enrich(1, "CVE-2026-12345", IOCType.CVE))
    assert calls == 2
    asyncio.run(client.aclose())


def test_anonymous_nvd_success_omits_key_and_is_idempotently_persisted(
    enrichment_db: tuple[sessionmaker[Session], int],
) -> None:
    factory, indicator_id = enrichment_db
    requests: list[httpx.Request] = []

    def nvd_success(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            request=request,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "descriptions": [{"lang": "en", "value": "Mocked NVD result"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "type": "Primary",
                                        "cvssData": {
                                            "version": "3.1",
                                            "baseScore": 7.5,
                                            "baseSeverity": "HIGH",
                                        },
                                    }
                                ]
                            },
                        }
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(nvd_success))
    provider = NVDProvider(enabled=True, api_key=None, client=client, max_retries=0)
    with factory() as session:
        service = EnrichmentService(
            session,
            registry=ProviderRegistry([provider]),
            ttl_seconds=60,
        )
        first = asyncio.run(service.enrich_indicator(indicator_id))
        second = asyncio.run(service.enrich_indicator(indicator_id))

        assert first[0].status is EnrichmentStatus.SUCCESS
        assert second[0].cached is True
        assert session.query(IndicatorEnrichment).count() == 1

    assert len(requests) == 1
    assert requests[0].headers.get("apiKey") is None
    assert requests[0].url.params["cveId"] == "CVE-2026-12345"
    asyncio.run(client.aclose())


def test_nvd_only_backfill_selects_missing_cves_and_honors_limit(
    enrichment_db: tuple[sessionmaker[Session], int],
) -> None:
    factory, first_cve_id = enrichment_db
    now = datetime.now(UTC)
    with factory() as session:
        article_id = session.scalar(select(RawArticle.id))
        assert article_id is not None
        session.add_all(
            [
                Indicator(
                    raw_article_id=article_id,
                    indicator_type=IOCType.CVE,
                    indicator_value=f"CVE-2026-{number}",
                )
                for number in range(20000, 20004)
            ]
            + [
                Indicator(
                    raw_article_id=article_id,
                    indicator_type=IOCType.DOMAIN,
                    indicator_value="not-for-nvd.example",
                )
            ]
        )
        session.commit()
        registry = ProviderRegistry([NVDProvider(enabled=True, api_key=None)])
        selected = list(
            session.scalars(
                build_pending_indicator_query(
                    registry,
                    now=now,
                    limit=3,
                    provider_name="nvd",
                )
            )
        )

    assert len(selected) == 3
    assert selected[0] == first_cve_id
    with factory() as session:
        selected_types = set(
            session.scalars(select(Indicator.indicator_type).where(Indicator.id.in_(selected)))
        )
    assert selected_types == {IOCType.CVE}


def test_article_dispatch_occurs_after_indicator_commit(
    enrichment_db: tuple[sessionmaker[Session], int],
) -> None:
    factory, _ = enrichment_db
    dispatched: list[int] = []
    committed_counts: list[int] = []

    def dispatch(raw_article_id: int) -> None:
        dispatched.append(raw_article_id)
        with factory() as verification_session:
            committed_counts.append(
                verification_session.query(Indicator)
                .filter(Indicator.raw_article_id == raw_article_id)
                .count()
            )

    manager = FeedManager(factory, enrichment_dispatcher=dispatch)
    stored, count = manager.store(
        NormalizedArticle(
            source_id="feed",
            title="new article",
            description="CVE-2026-9999",
            url="https://unit.test/new",
        )
    )

    assert stored is True
    assert count >= 1
    assert len(dispatched) == 1
    assert committed_counts == [count]
    with factory() as session:
        assert (
            session.query(Indicator).filter(Indicator.raw_article_id == dispatched[0]).count()
            == count
        )


def test_celery_single_indicator_task_uses_id_and_closes_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.ingestion.enrichment import tasks

    state: dict[str, object] = {"closed": False, "indicator_id": None}

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            state["closed"] = True

    class FakeService:
        def __init__(self, session: object, **kwargs: object) -> None:
            assert isinstance(session, FakeSession)

        async def enrich_indicator(
            self, indicator_id: int, *, force_refresh: bool = False
        ) -> list[EnrichmentResult]:
            state["indicator_id"] = indicator_id
            return [
                EnrichmentResult(
                    indicator_id=indicator_id,
                    indicator_value="CVE-2026-12345",
                    indicator_type=IOCType.CVE,
                    provider="fake",
                    status=EnrichmentStatus.SUCCESS,
                    enriched_at=datetime.now(UTC),
                )
            ]

    monkeypatch.setattr(tasks, "SessionLocal", FakeSession)
    monkeypatch.setattr(tasks, "EnrichmentService", FakeService)

    result = tasks.enrich_indicator_task.run(42)

    assert result[0]["indicator_id"] == 42
    assert state == {"closed": True, "indicator_id": 42}


def test_celery_single_indicator_task_closes_session_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.ingestion.enrichment import tasks

    state = {"closed": False}

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            state["closed"] = True

    class FailedService:
        def __init__(self, session: object, **kwargs: object) -> None:
            assert isinstance(session, FakeSession)

        async def enrich_indicator(
            self, indicator_id: int, *, force_refresh: bool = False
        ) -> list[EnrichmentResult]:
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(tasks, "SessionLocal", FakeSession)
    monkeypatch.setattr(tasks, "EnrichmentService", FailedService)

    with pytest.raises(RuntimeError, match="database unavailable"):
        tasks.enrich_indicator_task.run(42)

    assert state["closed"] is True

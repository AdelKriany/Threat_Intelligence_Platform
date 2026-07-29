from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast

import httpx
import pytest
from sqlalchemy import Table, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.database.base import Base
from app.ingestion.enrichment.exceptions import (
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderTemporaryError,
)
from app.ingestion.enrichment.persistence import result_from_record
from app.ingestion.enrichment.providers.cisa_kev import CISAKEVProvider
from app.ingestion.enrichment.providers.epss import EPSSProvider
from app.ingestion.enrichment.providers.nvd import NVDProvider
from app.ingestion.enrichment.registry import ProviderRegistry
from app.ingestion.enrichment.service import EnrichmentService
from app.ingestion.enrichment.tasks import build_pending_indicator_query, restrict_registry
from app.ingestion.enrichment.types import EnrichmentResult, EnrichmentStatus
from app.ingestion.models import (
    EPSSHistory,
    Indicator,
    IndicatorEnrichment,
    IOCType,
    RawArticle,
)
from app.workers.celery_app import celery_app


class MemoryCache:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, Any]] = {}
        self.locked = False
        self.lock_acquisitions = 0

    async def get_json(self, key: str) -> dict[str, Any] | None:
        return self.values.get(key)

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        self.values[key] = value

    async def acquire_lock(self, key: str, ttl_seconds: int) -> str | None:
        if self.locked:
            return None
        self.locked = True
        self.lock_acquisitions += 1
        return "token"

    async def release_lock(self, key: str, token: str) -> None:
        self.locked = False


@pytest.fixture()
def phase5_db() -> Generator[tuple[sessionmaker[Session], list[int]], None, None]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    with factory() as session:
        article = RawArticle(
            source_id="phase5",
            title="phase5",
            fetched_at=now,
            content_hash="phase5",
            created_at=now,
        )
        session.add(article)
        session.flush()
        indicators = [
            Indicator(
                raw_article_id=article.id,
                indicator_type=IOCType.CVE,
                indicator_value=f"CVE-2026-{number}",
            )
            for number in (12345, 12346, 12347, 12348, 12349)
        ]
        session.add_all(indicators)
        session.commit()
        ids = [indicator.id for indicator in indicators]
    yield factory, ids
    Base.metadata.drop_all(engine)


def _kev_payload() -> dict[str, Any]:
    return {
        "title": "CISA Catalog",
        "catalogVersion": "2026.07.29",
        "dateReleased": "2026-07-29T12:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-12345",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Example Vulnerability",
                "dateAdded": "2026-07-20",
                "shortDescription": "Actively exploited.",
                "requiredAction": "Apply updates.",
                "dueDate": "2026-08-10",
                "knownRansomwareCampaignUse": "Known",
                "notes": "Example note",
            }
        ],
    }


def test_kev_catalog_is_fetched_once_cached_and_matches_positive_and_negative() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, request=request, json=_kev_payload())

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache = MemoryCache()
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        client=client,
        cache=cache,
    )
    results = asyncio.run(
        provider.enrich_many(
            [
                (1, "CVE-2026-12345", IOCType.CVE),
                (2, "CVE-2026-12346", IOCType.CVE),
            ]
        )
    )
    second = asyncio.run(provider.enrich(3, "CVE-2026-12347", IOCType.CVE))

    assert requests == 1
    assert cache.lock_acquisitions == 1
    assert results[1].normalized_data["known_exploited"] is True
    assert results[1].normalized_data["vendor_project"] == "Example Vendor"
    assert results[2].status is EnrichmentStatus.SUCCESS
    assert results[2].normalized_data["known_exploited"] is False
    assert second.normalized_data["known_exploited"] is False
    asyncio.run(client.aclose())


def test_kev_refresh_lock_prevents_duplicate_download() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, request=request, json=_kev_payload())

    async def no_sleep(delay: float) -> None:
        return None

    cache = MemoryCache()
    cache.locked = True
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        client=client,
        cache=cache,
        sleep=no_sleep,
    )
    with pytest.raises(ProviderTemporaryError, match="already in progress"):
        asyncio.run(provider.fetch_catalog())
    assert requests == 0
    asyncio.run(client.aclose())


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"vulnerabilities": "invalid"},
        {"vulnerabilities": [{"cveID": "not-a-cve"}]},
    ],
)
def test_kev_rejects_malformed_catalog(payload: dict[str, Any]) -> None:
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        cache=MemoryCache(),
    )
    with pytest.raises(ProviderResponseError):
        provider.normalize(1, "CVE-2026-12345", IOCType.CVE, payload)


def test_kev_rejects_oversized_response() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            request=request,
            headers={
                "content-type": "application/json",
                "content-length": "3000000",
            },
            content=b"{}",
        )
    )
    client = httpx.AsyncClient(transport=transport)
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        client=client,
        cache=MemoryCache(),
        max_retries=0,
    )
    with pytest.raises(ProviderResponseError, match="size limit"):
        asyncio.run(provider.fetch_catalog())
    asyncio.run(client.aclose())


def test_kev_timeout_is_controlled() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(timeout))
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        client=client,
        cache=MemoryCache(),
        max_retries=0,
    )
    with pytest.raises(ProviderTemporaryError):
        asyncio.run(provider.fetch_catalog())
    asyncio.run(client.aclose())


@pytest.mark.parametrize(
    ("status_code", "exception_type"),
    [(429, ProviderRateLimitError), (503, ProviderTemporaryError)],
)
def test_kev_http_failures_are_controlled(
    status_code: int, exception_type: type[Exception]
) -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status_code, request=request, json={})
        )
    )
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        client=client,
        cache=MemoryCache(),
        max_retries=0,
    )
    with pytest.raises(exception_type):
        asyncio.run(provider.fetch_catalog())
    asyncio.run(client.aclose())


def test_epss_batches_parses_decimal_deduplicates_and_marks_missing() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cves = request.url.params["cve"].split(",")
        requests.append(request.url.params["cve"])
        data = [
            {
                "cve": cve,
                "epss": "0.9234500",
                "percentile": "0.9987000",
                "date": "2026-07-29",
            }
            for cve in cves
            if not cve.endswith("12349")
        ]
        if data:
            data.append(dict(data[0]))
        return httpx.Response(200, request=request, json={"status": "OK", "data": data})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = EPSSProvider(
        api_url="https://api.first.org/data/v1/epss",
        batch_size=2,
        ttl_seconds=86400,
        client=client,
    )
    indicators = [(number, f"CVE-2026-{12344 + number}", IOCType.CVE) for number in range(1, 6)]
    results = asyncio.run(provider.enrich_many(indicators))

    assert len(requests) == 3
    assert results[1].normalized_data["epss"] == "0.9234500"
    assert results[1].normalized_data["percentile"] == "0.9987000"
    assert results[5].status is EnrichmentStatus.NOT_FOUND
    asyncio.run(client.aclose())


@pytest.mark.parametrize(
    ("epss", "percentile"),
    [("invalid", "0.5"), ("1.1", "0.5"), ("0.5", "-0.1")],
)
def test_epss_malformed_values_are_missing(epss: str, percentile: str) -> None:
    provider = EPSSProvider(
        api_url="https://api.first.org/data/v1/epss",
        batch_size=100,
        ttl_seconds=86400,
    )
    result = provider.normalize(
        1,
        "CVE-2026-12345",
        IOCType.CVE,
        {
            "data": [
                {
                    "cve": "CVE-2026-12345",
                    "epss": epss,
                    "percentile": percentile,
                    "date": "2026-07-29",
                }
            ]
        },
    )
    assert result.status is EnrichmentStatus.NOT_FOUND


def test_epss_current_and_history_are_idempotent(
    phase5_db: tuple[sessionmaker[Session], list[int]],
) -> None:
    factory, indicator_ids = phase5_db

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            json={
                "data": [
                    {
                        "cve": "CVE-2026-12345",
                        "epss": "0.1234567",
                        "percentile": "0.7654321",
                        "date": "2026-07-29",
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = EPSSProvider(
        api_url="https://api.first.org/data/v1/epss",
        batch_size=100,
        ttl_seconds=60,
        client=client,
    )
    with factory() as session:
        service = EnrichmentService(
            session,
            registry=ProviderRegistry([provider]),
            ttl_seconds=60,
        )
        asyncio.run(service.enrich_indicator(indicator_ids[0], force_refresh=True))
        asyncio.run(service.enrich_indicator(indicator_ids[0], force_refresh=True))

        assert session.query(IndicatorEnrichment).count() == 1
        assert session.query(EPSSHistory).count() == 1
        history = session.scalar(select(EPSSHistory))
        assert history is not None
        assert history.epss == Decimal("0.1234567")
        assert history.percentile == Decimal("0.7654321")
    asyncio.run(client.aclose())


@pytest.mark.parametrize(
    ("failure", "exception_type"),
    [
        ("timeout", ProviderTemporaryError),
        ("rate_limit", ProviderRateLimitError),
        ("server_error", ProviderTemporaryError),
    ],
)
def test_epss_http_failures_are_controlled(failure: str, exception_type: type[Exception]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ReadTimeout("timeout", request=request)
        status = 429 if failure == "rate_limit" else 503
        return httpx.Response(status, request=request, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = EPSSProvider(
        api_url="https://api.first.org/data/v1/epss",
        batch_size=100,
        ttl_seconds=86400,
        client=client,
        max_retries=0,
    )
    with pytest.raises(exception_type):
        asyncio.run(provider.enrich(1, "CVE-2026-12345", IOCType.CVE))
    asyncio.run(client.aclose())


def test_kev_current_result_is_idempotent(
    phase5_db: tuple[sessionmaker[Session], list[int]],
) -> None:
    factory, indicator_ids = phase5_db
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, request=request, json=_kev_payload())
        )
    )
    provider = CISAKEVProvider(
        catalog_url="https://www.cisa.gov/kev.json",
        ttl_seconds=3600,
        client=client,
        cache=MemoryCache(),
    )
    with factory() as session:
        service = EnrichmentService(session, registry=ProviderRegistry([provider]))
        asyncio.run(service.enrich_indicator(indicator_ids[0], force_refresh=True))
        asyncio.run(service.enrich_indicator(indicator_ids[0], force_refresh=True))
        assert session.query(IndicatorEnrichment).count() == 1
    asyncio.run(client.aclose())


def test_retry_after_and_5xx_retries_are_bounded() -> None:
    responses = [429, 500, 200]
    delays: list[float] = []

    async def no_sleep(delay: float) -> None:
        delays.append(delay)

    def handler(request: httpx.Request) -> httpx.Response:
        status = responses.pop(0)
        if status == 200:
            return httpx.Response(200, request=request, json={"vulnerabilities": []})
        return httpx.Response(
            status,
            request=request,
            headers={"retry-after": "7"} if status == 429 else {},
            json={},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = NVDProvider(client=client, max_retries=2, sleep=no_sleep)
    result = asyncio.run(provider.enrich(1, "CVE-2026-12345", IOCType.CVE))

    assert result.status is EnrichmentStatus.NOT_FOUND
    assert delays[0] == 7
    assert len(delays) == 2
    asyncio.run(client.aclose())


def test_nvd_value_cache_avoids_duplicate_cve_requests() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            request=request,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "descriptions": [{"lang": "en", "value": "Cached result"}],
                        }
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache = MemoryCache()
    provider = NVDProvider(client=client, cache=cache)
    first = asyncio.run(provider.enrich(1, "CVE-2026-12345", IOCType.CVE))
    second = asyncio.run(provider.enrich(2, "CVE-2026-12345", IOCType.CVE))

    assert first.status is EnrichmentStatus.SUCCESS
    assert second.status is EnrichmentStatus.SUCCESS
    assert requests == 1
    asyncio.run(client.aclose())


def test_exhausted_429_preserves_retry_after() -> None:
    async def no_sleep(delay: float) -> None:
        return None

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                429,
                request=request,
                headers={"retry-after": "30"},
                json={},
            )
        )
    )
    provider = NVDProvider(client=client, max_retries=1, sleep=no_sleep)
    with pytest.raises(ProviderRateLimitError) as exc_info:
        asyncio.run(provider.enrich(1, "CVE-2026-12345", IOCType.CVE))
    assert exc_info.value.retry_after == 30
    asyncio.run(client.aclose())


class StatusProvider(NVDProvider):
    name = "status"

    def __init__(self, status: EnrichmentStatus) -> None:
        super().__init__(enabled=True, max_retries=0)
        self.status = status

    async def enrich(
        self, indicator_id: int, indicator_value: str, ioc_type: IOCType
    ) -> EnrichmentResult:
        return EnrichmentResult(
            indicator_id=indicator_id,
            indicator_value=indicator_value,
            indicator_type=ioc_type,
            provider=self.name,
            status=self.status,
            enriched_at=datetime.now(UTC),
        )


@pytest.mark.parametrize(
    ("status", "ttl_setting"),
    [
        (EnrichmentStatus.SUCCESS, "enrichment_ttl_seconds"),
        (EnrichmentStatus.NOT_FOUND, "enrichment_not_found_ttl_seconds"),
        (EnrichmentStatus.RATE_LIMITED, "enrichment_rate_limit_retry_seconds"),
        (EnrichmentStatus.TEMPORARY_FAILURE, "enrichment_failure_retry_seconds"),
    ],
)
def test_status_specific_expiration(
    phase5_db: tuple[sessionmaker[Session], list[int]],
    status: EnrichmentStatus,
    ttl_setting: str,
) -> None:
    factory, indicator_ids = phase5_db
    with factory() as session:
        result = asyncio.run(
            EnrichmentService(
                session,
                registry=ProviderRegistry([StatusProvider(status)]),
            ).enrich_indicator(indicator_ids[0], force_refresh=True)
        )[0]
        assert result.enriched_at is not None
        assert result.expires_at is not None
        actual = (result.expires_at - result.enriched_at).total_seconds()
        assert abs(actual - getattr(settings, ttl_setting)) < 2


def test_old_rate_limited_record_becomes_backfill_eligible(
    phase5_db: tuple[sessionmaker[Session], list[int]],
) -> None:
    factory, indicator_ids = phase5_db
    now = datetime.now(UTC)
    with factory() as session:
        session.add(
            IndicatorEnrichment(
                indicator_id=indicator_ids[0],
                provider="nvd",
                status="rate_limited",
                normalized_data={},
                enriched_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
                created_at=now - timedelta(hours=1),
                updated_at=now - timedelta(hours=1),
            )
        )
        session.commit()
        selected = list(
            session.scalars(
                build_pending_indicator_query(
                    ProviderRegistry([NVDProvider(enabled=True)]),
                    now=now,
                    limit=10,
                    provider_name="nvd",
                )
            )
        )
    assert indicator_ids[0] in selected


def test_disabled_epss_provider_sends_no_request(
    phase5_db: tuple[sessionmaker[Session], list[int]],
) -> None:
    factory, indicator_ids = phase5_db
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, request=request, json={"data": []})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = EPSSProvider(
        enabled=False,
        api_url="https://api.first.org/data/v1/epss",
        batch_size=100,
        ttl_seconds=86400,
        client=client,
    )
    with factory() as session:
        results = asyncio.run(
            EnrichmentService(
                session,
                registry=ProviderRegistry([provider]),
            ).enrich_indicator(indicator_ids[0])
        )
    assert results == []
    assert requests == 0
    asyncio.run(client.aclose())


def test_legacy_failed_row_remains_readable(
    phase5_db: tuple[sessionmaker[Session], list[int]],
) -> None:
    factory, indicator_ids = phase5_db
    now = datetime.now(UTC)
    with factory() as session:
        record = IndicatorEnrichment(
            indicator_id=indicator_ids[0],
            provider="nvd",
            status="failed",
            normalized_data={},
            error_message="legacy failure",
            enriched_at=now,
            expires_at=now + timedelta(hours=1),
            created_at=now,
            updated_at=now,
        )
        session.add(record)
        session.commit()
        indicator = session.get(Indicator, indicator_ids[0])
        assert indicator is not None
        result = result_from_record(record, indicator)
    assert result.status is EnrichmentStatus.FAILED
    assert result.error_code is None


def test_phase5_model_constraints() -> None:
    enrichment_constraints = {
        constraint.name for constraint in cast(Table, IndicatorEnrichment.__table__).constraints
    }
    history_constraints = {
        constraint.name for constraint in cast(Table, EPSSHistory.__table__).constraints
    }
    assert "uq_indicator_enrichments_indicator_provider" in enrichment_constraints
    assert "uq_epss_history_indicator_model_date" in history_constraints


def test_phase5_tasks_and_schedules_are_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_names = {
        "app.ingestion.enrichment.tasks.refresh_kev_catalog_task",
        "app.ingestion.enrichment.tasks.refresh_epss_batch_task",
        "app.ingestion.enrichment.tasks.phase5_coverage_task",
    }
    assert task_names.issubset(celery_app.tasks)

    monkeypatch.setattr(settings, "enrichment_enabled", True)
    monkeypatch.setattr(settings, "cisa_kev_enabled", True)
    monkeypatch.setattr(settings, "epss_enabled", True)
    from app.workers.celery_app import configure_beat_schedule

    configure_beat_schedule()
    assert {"refresh-cisa-kev", "refresh-epss", "phase5-coverage"}.issubset(
        celery_app.conf.beat_schedule
    )


def test_provider_filtered_registry_executes_only_requested_provider() -> None:
    registry = ProviderRegistry(
        [
            NVDProvider(enabled=True),
            CISAKEVProvider(
                enabled=True,
                catalog_url="https://www.cisa.gov/kev.json",
                ttl_seconds=3600,
                cache=MemoryCache(),
            ),
            EPSSProvider(
                enabled=True,
                api_url="https://api.first.org/data/v1/epss",
                batch_size=100,
                ttl_seconds=86400,
            ),
        ]
    )

    restricted = restrict_registry(registry, "nvd")

    assert [provider.name for provider in restricted.providers] == ["nvd"]

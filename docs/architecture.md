# ThreatLens Architecture Notes

This directory holds conceptual documentation for the Phase 1 foundation.

## Current scope

- FastAPI application factory
- Versioned health endpoint
- Configuration with Pydantic Settings
- SQLAlchemy and Alembic scaffolding
- Redis and Celery configuration
- Centralized logging and structured errors
- Docker Compose foundation services
- Modular RSS ingestion pipeline with feed registry, async fetching, normalization, duplicate detection, and Celery beat scheduling
- Provider-neutral IOC enrichment with asynchronous HTTP providers, database-backed TTL
  caching, and isolated Celery tasks

## Phase 3.2 IOC enrichment

`FeedManager` commits extracted indicators before it dispatches enrichment. Enrichment is
therefore outside the ingestion transaction, and dispatch or provider failure cannot undo an
article or its indicators. Each Celery task opens and closes its own SQLAlchemy session.

The provider registry selects only enabled providers that support the IOC type:

| Provider | IOC types | Credential behavior |
| --- | --- | --- |
| NVD | CVE | Works anonymously; optionally sends an NVD API key |
| AbuseIPDB | IPv4, IPv6 | Disabled without an API key |
| VirusTotal | IPv4, IPv6, domain, URL, MD5, SHA1, SHA256 | Disabled without an API key |

Email indicators are intentionally unsupported. Provider base URLs are fixed in code; indicator
values can only become path components or query values and cannot redirect requests to arbitrary
hosts. VirusTotal URL objects use unpadded URL-safe Base64 identifiers.

Normalized and bounded raw responses are stored in `indicator_enrichments`, uniquely keyed by
indicator and provider. A non-expired row is returned without an HTTP call. Force refresh bypasses
that cache; an expired row is updated in place, so retries never create duplicate rows. Provider
failures are stored as controlled statuses and do not stop other providers.

The worker exposes these tasks:

- `app.ingestion.enrichment.tasks.enrich_indicator_task(indicator_id, force_refresh=False)`
- `app.ingestion.enrichment.tasks.enrich_article_indicators_task(raw_article_id, force_refresh=False)`
- `app.ingestion.enrichment.tasks.enrich_pending_batch_task(batch_size=None, provider_name=None)`

For a manual call:

```bash
celery -A app.workers.celery_app.celery_app call \
  app.ingestion.enrichment.tasks.enrich_indicator_task --args='[123]'
```

When enrichment is enabled, Beat runs a bounded pending/expired refresh batch at the configured
interval. Apply the schema with `alembic upgrade head`; downgrade one revision with
`alembic downgrade -1`.

### Runtime configuration and backfill

`.env.example` is a template only. Docker Compose reads the root `.env` for `${VARIABLE}`
interpolation and explicitly passes enrichment settings to `api`, `celery-worker`, and
`celery-beat`. Pydantic's application-side `.env` lookup is not a substitute inside the
containers: their working directory is `/app/backend`, and the root host `.env` is not copied or
mounted there. After changing `.env`, recreate the application containers:

```bash
docker compose up -d --no-deps --force-recreate api celery-worker celery-beat
```

Verify the four non-secret flags in the worker:

```bash
docker compose exec -T celery-worker python -c \
  "from app.core.config import settings; \
print(settings.enrichment_enabled, settings.nvd_enabled, \
settings.abuseipdb_enabled, settings.virustotal_enabled)"
```

For NVD-only operation, the expected values are `True True False False`. Confirm task
registration with:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app inspect registered
```

New articles schedule article enrichment only after their indicator transaction commits.
Indicators created before Phase 3.2 require a backfill. First select one CVE ID and enrich only
that ID:

```bash
docker compose exec -T postgres psql -U threatlens -d threatlens -c \
  "SELECT id, indicator_value FROM indicators
   WHERE indicator_type='cve' ORDER BY id LIMIT 1;"

docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_indicator_task --args='[INDICATOR_ID]'
```

After confirming a row for that exact ID, run at most five pending NVD indicators:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_pending_batch_task --args='[5,"nvd"]'
```

The task query starts from `indicators`, so CVEs with no enrichment row are eligible. It applies
the provider's supported IOC types, deterministic ID ordering, and a limit no greater than
`ENRICHMENT_BATCH_SIZE`. With only NVD enabled, domains, URLs, emails, IPs, and hashes are not
selected. A 60-minute Beat interval means the first scheduled refresh may not occur during the
first ten minutes after startup.

Inspect task execution and persisted status without printing raw responses:

```bash
docker compose logs --tail=100 celery-worker

docker compose exec -T postgres psql -U threatlens -d threatlens -c \
  "SELECT provider, status, COUNT(*) FROM indicator_enrichments
   GROUP BY provider, status ORDER BY provider, status;"
```

Configuration uses `ENRICHMENT_ENABLED`, `ENRICHMENT_TTL_SECONDS`,
`ENRICHMENT_REQUEST_TIMEOUT_SECONDS`, `ENRICHMENT_MAX_RETRIES`,
`ENRICHMENT_BATCH_SIZE`, `ENRICHMENT_REFRESH_INTERVAL_MINUTES`, `NVD_ENABLED`,
`NVD_API_KEY`, `ABUSEIPDB_ENABLED`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_ENABLED`, and
`VIRUSTOTAL_API_KEY`. No key is required for application startup. Keys and authorization headers
are never logged. Retries are bounded, authentication failures are permanent, 429 responses are
recorded without tight retry loops, and payload/error sizes are limited. Anonymous NVD access
omits the API-key header and is subject to stricter provider rate limits. AbuseIPDB and
VirusTotal remain disabled unless both their provider flag and credential are configured.

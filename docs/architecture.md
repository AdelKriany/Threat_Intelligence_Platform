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

## Phase 5 CVE enrichment

Phase 5 gives every CVE up to three independent current enrichment rows:

| Provider | Signal | Retrieval pattern | Default refresh |
| --- | --- | --- | --- |
| NVD | CVSS and vulnerability metadata | Value-keyed Redis response cache plus PostgreSQL TTL | Hourly bounded scan |
| CISA KEV | Confirmed exploitation | One shared catalog download, Redis cache and lock | Every 6 hours |
| FIRST EPSS | 30-day exploitation probability | CVE batches of at most 100 | Daily |

The authoritative sources are the
[CISA KEV JSON catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[FIRST EPSS API](https://www.first.org/epss/api). Each provider is isolated: failure in one does
not prevent the others from persisting results.

KEV absence is a successful negative observation with `known_exploited=false`, not an error.
EPSS `epss` and `percentile` are probabilities in the inclusive range 0–1. Current JSON stores
their exact decimal text, while `epss_history` stores precise `NUMERIC(8,7)` daily observations.
Phase 5 does not combine CVSS, KEV, or EPSS into a ThreatLens risk score.

### Status and retry policy

| Status | Meaning | Default policy |
| --- | --- | --- |
| `success` | Valid result, including KEV negative results | Provider TTL |
| `not_found` | No provider record for a valid CVE | 6-hour negative cache |
| `rate_limited` | HTTP 429 | Retry after 15 minutes |
| `temporary_failure` | Timeout, network, or exhausted 5xx retries | Retry after 15 minutes |
| `permanent_failure` | Invalid input, authentication, or invalid response | No tight retry loop |

Legacy `failed` and `auth_error` rows remain readable. Pending selection applies short retry
policies to old `rate_limited`/`failed` rows even when they originally received a 24-hour expiry.
Retries use exponential backoff with jitter, honor bounded `Retry-After`, and never store keys or
authorization headers.

Redis keys use the `threatlens:enrichment` namespace. NVD responses are cached by normalized CVE
value so article-scoped duplicate indicators do not repeat upstream requests. Token-checked locks
prevent duplicate NVD/KEV downloads and overlapping periodic batches. Redis failure is logged and
fails open so it cannot corrupt or block PostgreSQL persistence.

### Phase 5 tasks and operations

```text
app.ingestion.enrichment.tasks.enrich_indicator_task
app.ingestion.enrichment.tasks.enrich_pending_batch_task
app.ingestion.enrichment.tasks.refresh_kev_catalog_task
app.ingestion.enrichment.tasks.refresh_epss_batch_task
app.ingestion.enrichment.tasks.phase5_coverage_task
```

Safely verify at most three CVEs, one provider at a time:

```bash
docker compose exec -T celery-worker celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_pending_batch_task --args='[3,"nvd"]'

docker compose exec -T celery-worker celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.refresh_kev_catalog_task --args='[3,true]'

docker compose exec -T celery-worker celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.refresh_epss_batch_task --args='[3]'
```

Inspect coverage without raw responses:

```sql
SELECT provider, status, COUNT(*)
FROM indicator_enrichments
GROUP BY provider, status
ORDER BY provider, status;

SELECT provider, COUNT(DISTINCT indicator_id) AS covered_cves
FROM indicator_enrichments
WHERE provider IN ('nvd', 'cisa_kev', 'epss') AND status = 'success'
GROUP BY provider;

SELECT COUNT(*) AS known_exploited
FROM indicator_enrichments
WHERE provider = 'cisa_kev'
  AND status = 'success'
  AND normalized_data->>'known_exploited' = 'true';

SELECT provider, COUNT(*) AS stale
FROM indicator_enrichments
WHERE expires_at <= now()
GROUP BY provider;
```

Phase 5 adds `CISA_KEV_ENABLED`, `CISA_KEV_CATALOG_URL`, `CISA_KEV_TTL_SECONDS`,
`CISA_KEV_REFRESH_INTERVAL_MINUTES`, `EPSS_ENABLED`, `EPSS_API_URL`, `EPSS_BATCH_SIZE`,
`EPSS_TTL_SECONDS`, `EPSS_REFRESH_INTERVAL_MINUTES`,
`ENRICHMENT_RATE_LIMIT_RETRY_SECONDS`, `ENRICHMENT_NOT_FOUND_TTL_SECONDS`,
`ENRICHMENT_FAILURE_RETRY_SECONDS`, and `ENRICHMENT_RETRY_MAX_DELAY_SECONDS`.

Compose passes these to API, worker, and Beat. `.env.example` contains safe defaults only; real
secrets remain in `.env` or deployment secrets. Apply migrations and recreate application
containers after changing Phase 5 settings.

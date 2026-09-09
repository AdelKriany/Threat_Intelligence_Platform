# ThreatLens Architecture Notes

This directory holds conceptual documentation for the Phase 1 foundation.

## Phase 6A IOC quality and read-only audit

`app.ingestion.ioc.validators.validate_indicator()` is the canonical network-free
validation engine used by extraction, persistence, providers that normalize CVEs, and
the database audit. It returns an immutable result containing the original and
normalized values, IOC type, `valid`/`invalid`/`suspicious` status, and a stable reason
code. `normalize_indicator()` remains the compatibility API and returns normalized
values for both valid and suspicious results.

Parseable non-public IP addresses are `suspicious`, not invalid. This preserves the
existing ability to record private infrastructure while making loopback, private,
reserved, unspecified, link-local, and multicast use explicit and auditable.

Domain validation uses label, length, character, IDNA, and plausible-suffix checks.
The `domain_file_extension` policy rejects bare names ending in common web, document,
archive, executable, and image extensions. This is intentionally conservative for
OSINT article extraction: a technically registerable name can resemble a filename, but
accepting article titles such as `malwares.jpg` creates substantially more dangerous
false intelligence. URLs are evaluated independently, so a path such as
`https://example.com/payload.exe` remains valid.

Run the read-only audit locally:

```bash
python -m app.ingestion.ioc.audit --format summary --sample-limit 5
python -m app.ingestion.ioc.audit --format json --sample-limit 5
```

Or through the API service image:

```bash
docker compose exec -T api \
  python -m app.ingestion.ioc.audit --format summary --sample-limit 5
```

The default exits zero even when questionable data exists. CI can use
`--fail-on invalid`, `--fail-on suspicious`, or `--fail-on any`; policy findings then
exit 1, while operational failures exit 2. The query is ordered and streamed in
bounded batches. It selects only indicator IDs, types, and values and performs no
updates, deletes, commits, enrichment reads, or network calls. Cleanup must be designed
as a separate reviewed migration after the report is approved.

The older `app.enrichment` package remains active as a candidate-generation
compatibility layer. Its public extraction helpers now delegate final acceptance and
normalization to the canonical validator, preventing rule drift without breaking
callers.

### Reviewed IOC cleanup

`app.ingestion.ioc.cleanup` is a maintenance command rather than an Alembic data
migration. Cleanup decisions depend on a specific reviewed audit and the current
validator, so embedding mutable policy or hundreds of production IDs in schema history
would be unsafe. No schema change is needed.

Apply mode requires an expected count, a full-sample audit, and its SHA-256 file. It
compares the complete current candidate set with the manifest, locks every candidate,
revalidates type/value/status/reason, counts dependencies, and explicitly deletes EPSS
history, enrichment rows, article associations, then indicators in one transaction.
Any mismatch rolls everything back. Suspicious and valid indicators are never cleanup
candidates.

```bash
python -m app.ingestion.ioc.cleanup --dry-run \
  --expected-count 635 \
  --audit-file reviewed-audit.json \
  --audit-sha256 reviewed-audit.json.sha256

python -m app.ingestion.ioc.cleanup --apply \
  --expected-count 635 \
  --audit-file reviewed-audit.json \
  --audit-sha256 reviewed-audit.json.sha256
```

Before apply, stop `api`, `celery-worker`, and `celery-beat` without clearing queues,
and create a verified custom-format PostgreSQL backup. Recovery is intentionally
database restore, because no archive schema or fake Alembic downgrade can reliably
reconstruct deleted canonical rows and relationships:

```bash
docker compose exec -T postgres pg_restore --list \
  < backups/threatlens-before-ioc-cleanup-TIMESTAMP.dump
docker compose exec -T postgres createdb -U threatlens threatlens_recovery
docker compose exec -T postgres pg_restore -U threatlens -d threatlens_recovery \
  --no-owner --no-privileges \
  < backups/threatlens-before-ioc-cleanup-TIMESTAMP.dump
```

After review and cleanup, rerun both audit formats, orphan queries, health checks, and
the full test suite before restarting only the paused services. Generated backups and
timestamped audits are ignored by Git.

## Canonical indicators and article mentions

Before revision `b74f3c9a21de`, each extracted IOC belonged directly to one article.
The same CVE therefore received many indicator IDs and repeated provider results. The
canonical model is now:

```text
raw_articles ──< article_indicators >── indicators ──< indicator_enrichments
                                             └──────< epss_history
```

`indicators` is unique on `(indicator_type, indicator_value)`;
`article_indicators` is unique on `(raw_article_id, indicator_id)`. Deleting an article
cascades only its associations, never a shared indicator. Deleting an indicator still
cascades its associations, current enrichment, and EPSS history.

Canonical identity follows existing extraction behavior: validated CVEs are uppercase;
hashes, domains, and emails are lowercase; trailing domain dots are removed; IPs use
Python `ipaddress` canonical form; and validated HTTP(S) URLs retain their exact
existing representation. Type is part of identity. Invalid legacy values remain
verbatim during migration rather than aborting or being silently merged.

The lowest old ID becomes canonical. Colliding provider rows rank `success`,
`not_found`, `rate_limited`, `temporary_failure`, `permanent_failure`, `auth_error`,
then `failed`; latest timestamps and ID break equal-status ties. An older success
therefore beats a newer failure. Same-date EPSS history keeps the latest fetched
observation. Provider data is neither merged nor fabricated.

NVD `risk_score` remains provider-native scaled CVSS data, not the future Phase 6
combined ThreatLens score.

### Safe deployment, backup, and recovery

Inspect state, confirm `.env` is ignored, and record the revision:

```bash
git status --short
git check-ignore -v .env
docker compose ps
docker compose exec -T postgres psql -U threatlens -d threatlens -Atc \
  "SELECT version_num FROM alembic_version"
```

Create and verify a custom-format backup:

```bash
docker compose exec -T postgres pg_dump \
  -U threatlens -d threatlens -Fc > threatlens_before_indicator_dedup.dump
test -s threatlens_before_indicator_dedup.dump
```

Restore only into a separately created recovery database:

```bash
docker compose exec -T postgres createdb -U threatlens threatlens_recovery
docker compose exec -T postgres pg_restore \
  -U threatlens -d threatlens_recovery --clean --if-exists \
  < threatlens_before_indicator_dedup.dump
```

After recording the pre-migration SQL below, stop writers and use a one-off container
because the normal API container is stopped:

```bash
docker compose stop api celery-worker celery-beat
docker compose run --rm --no-deps api alembic upgrade head
docker compose up -d api celery-worker celery-beat
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app inspect registered
```

Review this migration against a restored staging copy before production. No automatic
full enrichment backfill is needed.

### Migration validation SQL

Capture before migration:

```sql
SELECT count(*) AS indicator_rows FROM indicators;
SELECT count(*) AS represented_mentions FROM indicators;
SELECT count(*) AS exact_identities
FROM (SELECT DISTINCT indicator_type, indicator_value FROM indicators) identity;
SELECT provider, status, count(*) FROM indicator_enrichments GROUP BY 1, 2 ORDER BY 1, 2;
SELECT indicator_type, indicator_value, count(*)
FROM indicators GROUP BY 1, 2 HAVING count(*) > 1 ORDER BY count(*) DESC;
SELECT i.indicator_type, i.indicator_value, e.provider, count(*)
FROM indicators i JOIN indicator_enrichments e ON e.indicator_id = i.id
GROUP BY 1, 2, 3 HAVING count(*) > 1 ORDER BY count(*) DESC;
```

After migration, the duplicate and orphan queries must return no rows:

```sql
SELECT indicator_type, indicator_value, count(*)
FROM indicators GROUP BY 1, 2 HAVING count(*) > 1;
SELECT raw_article_id, indicator_id, count(*)
FROM article_indicators GROUP BY 1, 2 HAVING count(*) > 1;
SELECT indicator_id, provider, count(*)
FROM indicator_enrichments GROUP BY 1, 2 HAVING count(*) > 1;
SELECT ai.* FROM article_indicators ai
LEFT JOIN raw_articles a ON a.id = ai.raw_article_id
LEFT JOIN indicators i ON i.id = ai.indicator_id
WHERE a.id IS NULL OR i.id IS NULL;
SELECT e.* FROM indicator_enrichments e
LEFT JOIN indicators i ON i.id = e.indicator_id WHERE i.id IS NULL;
```

Compare semantic counts and a known repeated CVE:

```sql
SELECT count(*) AS unique_indicators FROM indicators;
SELECT count(*) AS mentions FROM article_indicators;
SELECT provider, status, count(*) AS provider_rows
FROM indicator_enrichments GROUP BY 1, 2 ORDER BY 1, 2;
SELECT i.indicator_value, count(*) AS mentioning_articles
FROM indicators i JOIN article_indicators ai ON ai.indicator_id = i.id
WHERE i.indicator_value = 'CVE-2026-15409'
GROUP BY i.indicator_value;
```

Display distinct NVD CVSS results without multiplying article mentions:

```sql
SELECT i.indicator_value, e.risk_score, e.severity, e.enriched_at
FROM indicators i JOIN indicator_enrichments e ON e.indicator_id = i.id
WHERE i.indicator_type = 'cve' AND e.provider = 'nvd' AND e.status = 'success'
ORDER BY e.risk_score DESC NULLS LAST, i.indicator_value;
```

The downgrade is structurally valid but lossy: it assigns each canonical indicator to
its lowest associated article and discards additional associations. It refuses orphan
canonical indicators. For lossless production recovery, stop writers, restore the
verified dump, deploy the previous application image, and restart services.

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

## Phase 6C indicator scoring API

The versioned synchronous router is a thin transaction boundary over Phase 6B. It does not load
provider payloads itself, calculate Formula v1, build or hash snapshots, insert score/component
rows, or handle uniqueness races. Those responsibilities remain in
`calculate_and_persist_indicator_score`. The service flushes without committing; the POST endpoint
commits exactly once after constructing the complete response and rolls back every exception.

| Method and path | Success | Behavior |
| --- | --- | --- |
| `POST /api/v1/indicators/{indicator_id}/score` | `200` | Calculate from stored evidence and persist or reuse the canonical score |
| `GET /api/v1/indicators/{indicator_id}/score` | `200` | Return the latest persisted score only |
| `GET /api/v1/indicators/{indicator_id}/score/history` | `200` | Return a bounded newest-first history page |

POST accepts only the Boolean query parameter `force_refresh`, defaulting to `false`. For the
default, the router supplies the latest persisted calculation time to Phase 6B, which reloads the
currently stored evidence before Formula v1 calculation. This lets unchanged stored evidence
reproduce and reuse its canonical snapshot. If new evidence postdates that calculation context, the
same orchestration is retried at current UTC. `force_refresh=true` uses current UTC immediately; it
is not an enrichment refresh and does not call any external provider. Neither path overrides the
evidence hash or database uniqueness constraint, so an identical canonical snapshot returns the
existing row and `created: false`.

The POST response is:

```json
{
  "created": false,
  "score": {
    "id": 456,
    "indicator_id": 123,
    "indicator_type": "cve",
    "indicator_value": "CVE-2026-12345",
    "score": 87.4,
    "severity": "critical",
    "formula_version": "phase6b-v1",
    "evidence_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "as_of": "2026-08-28T12:00:00Z",
    "calculated_at": "2026-08-28T12:00:00Z",
    "components": []
  }
}
```

GET returns the nested `score` object directly and never includes `created`. Components expose only
the safe Formula inputs persisted in `score_components`, normalized values, exact stored weights
and contributions, freshness multiplier, provider/evidence status, evidence timestamp, and
explanation. Raw enrichment responses and the full canonical evidence document are never returned.

Latest ordering is `calculated_at DESC, id DESC`. History uses the same deterministic ordering,
with `limit` default 20/minimum 1/maximum 100 and `offset` default 0/minimum 0:

```json
{"indicator_id": 123, "items": [], "limit": 20, "offset": 0, "total": 0}
```

An existing indicator without a latest score returns `404 SCORE_NOT_FOUND`; its history returns an
empty page. A missing indicator returns `404 INDICATOR_NOT_FOUND`. Invalid stored canonical data
that Formula v1 cannot score returns `422 INDICATOR_UNSCORABLE`. Normal FastAPI path/query
validation uses `422`; unexpected exceptions use the centralized sanitized `500` response.

## Phase 7 exact CVE event correlation

Phase 7 introduces a synchronous service boundary for deterministic correlation of one stored,
canonical CVE indicator. It uses the existing `correlated_events`, `event_articles`, and
`event_indicators` schema; no migration, API, task, schedule, trigger, or event scoring path is
added.

```text
correlate_cve_indicator(session, indicator_id, *, as_of)
    -> CVECorrelationResult
```

The service requires a timezone-aware logical timestamp and an existing `IOCType.CVE` indicator
whose stored value is already the validator's canonical uppercase form. Missing indicators,
non-CVE indicators, and malformed/noncanonical CVE rows produce distinct typed errors before any
event write. A valid CVE with no articles still creates its event and indicator relationship.

The stable event identity and metadata are:

```text
event_key    = cve:<UPPERCASE-CVE>
title        = <UPPERCASE-CVE> vulnerability
rule_name    = shared-cve
rule_version = v1
reason       = shared_canonical_cve
```

All current `article_indicators` rows for the CVE are loaded in one ordered query and inserted as
event relationships in one statement. PostgreSQL and SQLite use conflict handling scoped to the
documented event-key unique constraint and relationship primary keys. This makes repeated and
concurrent calls idempotent without catching unrelated `IntegrityError` instances. A pre-existing
stable key with incompatible title/rule metadata is rejected instead of silently rewritten.

The result exposes the persisted event, whether it was created, whether the indicator link was
created, and the exact sorted article IDs newly linked by this call. When a reused event gains a
new relationship, only `updated_at` advances. Existing articles, canonical indicators,
enrichments, indicator scores, event scores, and historical rows are never merged, deleted, or
recalculated.

The caller owns the outer transaction. The service performs a final flush but never commits or
rolls back. A normal operation uses six SQL statements independent of whether one or many articles
are linked; extending an existing event adds one bounded `updated_at` statement. PostgreSQL tests
exercise two independent sessions racing on the same CVE and verify one event, unique links, no
deadlock, and preservation of unrelated caller work.

Non-CVE correlation, fuzzy/title similarity, shared network indicators, embeddings, actor/malware
matching, campaign inference, automatic ingestion hooks, backfill tooling, event scoring, and an
event API remain intentionally deferred.

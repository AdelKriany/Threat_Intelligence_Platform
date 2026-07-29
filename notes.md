# ThreatLens Canonical Indicator Repair Verification Notes

## Canonical indicator repair work log

Pre-edit inspection found:

- Active ownership was `RawArticle -> Indicator` with `delete-orphan`; every indicator
  carried a non-null `raw_article_id`.
- The actual uniqueness rule was
  `(raw_article_id, indicator_type, indicator_value)`, so identical values in different
  articles intentionally received different IDs.
- Extraction normalizes CVEs to uppercase, hashes/domains/emails to lowercase, IPv4
  and IPv6 through Python's `ipaddress` canonical form, and leaves validated HTTP(S)
  URLs in their existing exact representation.
- Current enrichment upserts conflict on `(indicator_id, provider)`. EPSS history
  conflicts on `(indicator_id, model_date)`.
- `indicator_enrichments.indicator_id` and `epss_history.indicator_id` are the only
  active foreign keys referencing `indicators`.
- Migration risks are provider-row collisions after ID repointing, EPSS same-date
  collisions, accidental cascade deletion, invalid legacy values, and the inherently
  lossy downgrade from many article mentions back to one `raw_article_id`.

The repair uses `(indicator_type, indicator_value)` as the canonical identity after
applying the existing safe normalization rules. Invalid legacy values are preserved
verbatim instead of being cast or rejected during migration, so they cannot abort the
upgrade or be silently merged.

## Canonical repair checks actually run

Changed-file formatting:

```bash
ruff format --check \
  backend/app/ingestion/models.py \
  backend/app/ingestion/feed_manager.py \
  backend/app/ingestion/ioc/persistence.py \
  backend/app/ingestion/enrichment/tasks.py \
  backend/app/models/indicator.py \
  backend/tests/test_ioc_enrichment.py \
  backend/tests/test_phase5_enrichment.py \
  backend/tests/test_ingestion.py \
  backend/tests/test_canonical_indicators.py \
  alembic/versions/20260729_canonical_indicators.py
```

Expected and observed output:

```text
10 files already formatted
```

The repository-wide formatting command was also attempted. It reported only:

```text
Would reformat: backend/app/ingestion/rss_client.py
1 file would be reformatted, 71 files already formatted
```

That unrelated pre-existing file was deliberately not modified.

Repository-wide Ruff, Mypy, tests, compilation, migration head, Compose, and diff:

```bash
ruff check backend/app backend/tests alembic/versions
mypy backend
pytest -q
python -m compileall -q backend/app alembic/versions
alembic heads
docker compose config -q
git diff --check
```

Expected and observed significant output:

```text
All checks passed!
Success: no issues found in 65 source files
77 passed
b74f3c9a21de (head)
```

The final three commands other than `alembic heads` produce no output on success.

The migration was also tested against a separate disposable PostgreSQL 16 database
populated at revision `61b739ac42e5` with three articles, four old indicator rows,
conflicting NVD/KEV/EPSS statuses, and duplicate same-date EPSS history. Upgrade
produced these exact counts:

```text
canonical_indicators = 2
mentions             = 4
provider_rows        = 3
history_rows         = 1
orphan_count         = 0
```

`CVE-2026-15409` became one canonical row with three article associations. The retained
provider rows were NVD success, KEV successful negative, and EPSS success; newer
failure/rate-limit rows did not replace successes. The newest same-date EPSS observation
(`0.2000000`, percentile `0.6000000`) won. Downgrade to `61b739ac42e5` and re-upgrade
to head both completed successfully; as documented, downgrade necessarily loses
additional article associations.

Run the commands below from the repository root:

```bash
cd /home/adel/programming/osint_tool/Threat_Intelligence_Platform
```

The commands are listed in the same order used to verify the IOC enrichment
implementation. Provider HTTP requests are mocked, so the tests need neither internet
access nor real API keys.

## 1. Lint the application, tests, and migrations

```bash
ruff check backend/app backend/tests alembic/versions
```

Expected output:

```text
All checks passed!
```

## 2. Check formatting

```bash
ruff format --check \
  backend/app/core/config.py \
  backend/app/ingestion/feed_manager.py \
  backend/app/ingestion/models.py \
  backend/app/workers/celery_app.py \
  backend/app/ingestion/enrichment \
  backend/tests/test_health.py \
  backend/tests/test_ioc_enrichment.py \
  backend/tests/test_phase5_enrichment.py \
  alembic/versions/20260724_phase32_indicator_enrichments.py \
  alembic/versions/20260729_phase5_epss_history.py
```

Expected output:

```text
25 files already formatted
```

The repository's `black --check` command stalled under the available Python 3.14
sandbox because Black attempted to create worker processes. `ruff format --check` was
used for the final non-mutating formatting verification.

## 3. Run static type checking

```bash
mypy backend
```

Expected output:

```text
Success: no issues found in 65 source files
```

## 4. Compile the Python sources

```bash
python -m compileall -q backend/app alembic/versions
```

Expected output:

```text
```

No output and an exit status of zero means compilation succeeded.

## 5. Run the focused Phase 5 and regression tests

```bash
pytest -q \
  backend/tests/test_phase5_enrichment.py \
  backend/tests/test_ioc_enrichment.py \
  backend/tests/test_enrichment.py \
  backend/tests/test_ingestion.py \
  backend/tests/test_ioc_extraction.py
```

Expected output:

```text
.....................................................................    [100%]
70 passed
```

These tests cover:

- NVD value caching and per-CVE Redis locking
- CISA KEV positive, negative, malformed, oversized, timeout, 429, and 5xx responses
- EPSS batching, partial responses, exact decimal persistence, and daily history
- Provider enablement, IOC selection, and indicator/provider uniqueness
- Success, not-found, rate-limited, temporary-failure, and permanent-failure TTLs
- `Retry-After`, bounded exponential backoff, and idempotent refreshes
- Celery provider restriction, overlap locks, schedules, and database cleanup
- Existing RSS ingestion and IOC extraction regressions

## 6. Run the complete test suite

```bash
pytest -q
```

Expected output:

```text
......................................................................   [100%]
77 passed
```

The health test uses HTTPX's in-process ASGI transport because FastAPI's blocking
`TestClient` stalled with the available Python 3.14 runtime.

## 7. Verify the Alembic migration chain

```bash
alembic heads
```

Expected output:

```text
b74f3c9a21de (head)
```

To inspect the complete chain:

```bash
alembic history --verbose
```

The first revision in the output should be:

```text
Rev: b74f3c9a21de (head)
Parent: 61b739ac42e5
Path: .../alembic/versions/20260729_canonical_indicators.py
```

Apply the migration to a configured PostgreSQL database with:

```bash
alembic upgrade head
```

Expected successful final line:

```text
Running upgrade 61b739ac42e5 -> b74f3c9a21de, Canonicalize indicators and preserve article mentions in an association table.
```

The migration was applied only to the separate disposable
`threatlens_canonical_test` database. It was intentionally not applied to the populated
ThreatLens database. Downgrade and re-upgrade were both executed on that disposable
fixture.

## 8. Check the final diff

```bash
git diff --check
```

Expected output:

```text
```

No output and an exit status of zero means the diff contains no whitespace errors.

Then inspect all modified and newly created files:

```bash
git status --short
```

Expected entries include:

```text
 M .env.example
 M README.md
 M backend/app/core/config.py
 M backend/app/ingestion/enrichment/exceptions.py
 M backend/app/ingestion/enrichment/persistence.py
 M backend/app/ingestion/enrichment/providers/__init__.py
 M backend/app/ingestion/enrichment/providers/base.py
 M backend/app/ingestion/enrichment/providers/nvd.py
 M backend/app/ingestion/enrichment/registry.py
 M backend/app/ingestion/enrichment/service.py
 M backend/app/ingestion/enrichment/tasks.py
 M backend/app/ingestion/enrichment/types.py
 M backend/app/ingestion/models.py
 M backend/app/workers/celery_app.py
 M backend/tests/test_ioc_enrichment.py
 M docs/architecture.md
 M docker-compose.yml
 M notes.md
?? alembic/versions/20260729_phase5_epss_history.py
?? backend/app/ingestion/enrichment/cache.py
?? backend/app/ingestion/enrichment/providers/cisa_kev.py
?? backend/app/ingestion/enrichment/providers/epss.py
?? backend/tests/test_phase5_enrichment.py
```

## 9. Verify the container configuration and Celery path

`.env.example` is only a template. Put runtime values in `.env`, then recreate the
application containers:

```bash
docker compose up -d --no-deps --force-recreate api celery-worker celery-beat
```

Expected output ends with:

```text
Container threatlens-api Started
Container threatlens-celery-worker Started
Container threatlens-celery-beat Started
```

Verify the non-secret flags inside the worker:

```bash
docker compose exec -T celery-worker python -c \
  "from app.core.config import settings; \
print(settings.enrichment_enabled, settings.nvd_enabled, \
settings.cisa_kev_enabled, settings.epss_enabled, \
settings.abuseipdb_enabled, settings.virustotal_enabled)"
```

Expected Phase 5 output with future providers safely disabled:

```text
True True True True False False
```

Verify task registration:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app inspect registered
```

Expected task entries:

```text
app.ingestion.enrichment.tasks.enrich_article_indicators_task
app.ingestion.enrichment.tasks.enrich_indicator_task
app.ingestion.enrichment.tasks.enrich_pending_batch_task
app.ingestion.enrichment.tasks.phase5_coverage_task
app.ingestion.enrichment.tasks.refresh_epss_batch_task
app.ingestion.enrichment.tasks.refresh_kev_catalog_task
```

The final runtime check returned:

```text
1 node online.
```

Run one known existing CVE first, explicitly restricting it to NVD:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_indicator_task \
  --args='[INDICATOR_ID,["nvd"]]'
```

Expected output is a Celery task UUID. Confirm that exact indicator before continuing:

```sql
SELECT indicator_id, provider, status, severity, error_code, error_message
FROM indicator_enrichments
WHERE indicator_id = :tested_indicator_id;
```

Only after observing that row, run a three-item NVD-only batch:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_pending_batch_task --args='[3,"nvd"]'
```

Expected worker result:

```text
{'indicators': 3, 'results': 3}
```

The bounded live smoke also completed three-item KEV and EPSS refreshes successfully.
The exact success/not-found distribution depends on the selected CVEs and the current
official catalogs.

## 10. Optional PostgreSQL verification

After applying the migration and running enrichment, inspect stored results:

```sql
SELECT
    indicator_id,
    provider,
    status,
    severity,
    error_code,
    enriched_at,
    expires_at
FROM indicator_enrichments
ORDER BY updated_at DESC
LIMIT 20;
```

Expected shape:

```text
 indicator_id | provider | status    | severity | error_code | enriched_at | expires_at
--------------+----------+-----------+----------+------------+-------------+------------
 ...          | nvd      | success   | ...      |            | ...         | ...
 ...          | cisa_kev | success   |          |            | ...         | ...
 ...          | epss     | not_found |          | not_found  | ...         | ...
```

Verify exact EPSS observations separately:

```sql
SELECT indicator_id, model_date, epss, percentile, fetched_at
FROM epss_history
ORDER BY fetched_at DESC
LIMIT 20;
```

Expected shape:

```text
 indicator_id | model_date |   epss    | percentile | fetched_at
--------------+------------+-----------+------------+------------
 ...          | 2026-..-.. | 0.......  | 0.......   | ...
```

Exact rows depend on the enabled providers, current upstream data, and extracted CVEs.
Phase 5 does not calculate a combined risk score; that remains Phase 6 work.

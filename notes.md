# ThreatLens Phase 5 Verification Notes

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
Success: no issues found in 64 source files
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
71 passed
```

The health test uses HTTPX's in-process ASGI transport because FastAPI's blocking
`TestClient` stalled with the available Python 3.14 runtime.

## 7. Verify the Alembic migration chain

```bash
alembic heads
```

Expected output:

```text
61b739ac42e5 (head)
```

To inspect the complete chain:

```bash
alembic history --verbose
```

The first revision in the output should be:

```text
Rev: 61b739ac42e5 (head)
Parent: 8c31f1e782b4
Path: .../alembic/versions/20260729_phase5_epss_history.py
```

Apply the migration to a configured PostgreSQL database with:

```bash
alembic upgrade head
```

Expected successful final line:

```text
Running upgrade 8c31f1e782b4 -> 61b739ac42e5, Add Phase 5 error codes and EPSS history.
```

The migration was applied successfully to the local Docker PostgreSQL service. Its downgrade SQL
was also generated offline and inspected without deleting the live EPSS observations.

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

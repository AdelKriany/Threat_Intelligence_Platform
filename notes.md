# ThreatLens Phase 3.2 Verification Notes

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
  alembic/versions/20260724_phase32_indicator_enrichments.py
```

Expected output:

```text
19 files already formatted
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
Success: no issues found in 60 source files
```

## 4. Compile the Python sources

```bash
python -m compileall -q backend/app alembic/versions
```

Expected output:

```text
```

No output and an exit status of zero means compilation succeeded.

## 5. Run the focused Phase 3.2 and regression tests

```bash
pytest -q \
  backend/tests/test_ioc_enrichment.py \
  backend/tests/test_enrichment.py \
  backend/tests/test_ingestion.py \
  backend/tests/test_ioc_extraction.py
```

Expected output:

```text
.......................................                                  [100%]
39 passed
```

These tests cover:

- Provider selection by IOC type and unsupported email indicators
- NVD, AbuseIPDB, and VirusTotal response normalization
- VirusTotal URL identifier generation
- Credential-dependent provider disablement
- Successful persistence and indicator/provider uniqueness
- Cached results, force refresh, and expired results
- Partial provider failures
- HTTP timeouts, authentication failures, and HTTP 429 handling
- Celery task serialization and database-session cleanup
- Article-to-indicator post-commit task scheduling
- Existing RSS ingestion and IOC extraction behavior

## 6. Run the complete test suite

```bash
pytest -q
```

Expected output:

```text
........................................                                 [100%]
40 passed
```

The health test uses HTTPX's in-process ASGI transport because FastAPI's blocking
`TestClient` stalled with the available Python 3.14 runtime.

## 7. Verify the Alembic migration chain

```bash
alembic heads
```

Expected output:

```text
8c31f1e782b4 (head)
```

To inspect the complete chain:

```bash
alembic history --verbose
```

The first revision in the output should be:

```text
Rev: 8c31f1e782b4 (head)
Parent: 2d1d8a617db8
Path: .../alembic/versions/20260724_phase32_indicator_enrichments.py
```

Apply the migration to a configured PostgreSQL database with:

```bash
alembic upgrade head
```

Expected successful final line:

```text
Running upgrade 2d1d8a617db8 -> 8c31f1e782b4, Create indicator enrichment results.
```

The migration application command was not run during the automated verification because
the test environment did not provide a dedicated PostgreSQL database.

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
 M backend/app/ingestion/feed_manager.py
 M backend/app/ingestion/models.py
 M backend/app/workers/celery_app.py
 M backend/tests/test_health.py
 M docs/architecture.md
 M docker-compose.yml
 M notes.md
?? alembic/versions/20260724_phase32_indicator_enrichments.py
?? backend/app/ingestion/enrichment/
?? backend/tests/conftest.py
?? backend/tests/test_ioc_enrichment.py
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
settings.abuseipdb_enabled, settings.virustotal_enabled)"
```

Expected NVD-only output:

```text
True True False False
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
```

Run one known existing CVE first:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_indicator_task --args='[INDICATOR_ID]'
```

Expected output is a Celery task UUID. Confirm that exact indicator before continuing:

```sql
SELECT indicator_id, provider, status, risk_score, severity, error_message
FROM indicator_enrichments
WHERE indicator_id = :tested_indicator_id;
```

Only after observing that row, run a five-item NVD-only batch:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_pending_batch_task --args='[5,"nvd"]'
```

Expected worker result:

```text
{'indicators': 5, 'results': 5}
```

## 10. Optional PostgreSQL verification

After applying the migration and running enrichment, inspect stored results:

```sql
SELECT
    indicator_id,
    provider,
    status,
    risk_score,
    severity,
    enriched_at,
    expires_at
FROM indicator_enrichments
ORDER BY updated_at DESC
LIMIT 20;
```

Expected shape:

```text
 indicator_id | provider    | status  | risk_score | severity | enriched_at | expires_at
--------------+-------------+---------+------------+----------+-------------+------------
 ...          | nvd         | success | ...        | ...      | ...         | ...
 ...          | abuseipdb   | success | ...        | ...      | ...         | ...
 ...          | virustotal  | success | ...        | ...      | ...         | ...
```

Exact rows depend on the configured providers, credentials, and extracted indicators.

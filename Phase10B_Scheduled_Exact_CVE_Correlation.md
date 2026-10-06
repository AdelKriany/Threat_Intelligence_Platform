# Phase 10B - Scheduled Exact-CVE Correlation

Date: 2026-10-07

## Purpose and boundaries

Phase 10B schedules the existing bounded exact-CVE correlation backfill. It does not create a new
correlation algorithm. The existing Phase 7 and 7B services remain authoritative for stable event
keys, event titles, rule metadata, relationship reasons, pagination, invalid-CVE handling, dry-run
forecasting, and concurrent uniqueness behavior.

No database schema, migration, scoring formula, enrichment provider, API endpoint, fuzzy matching,
campaign inference, or network request is added.

## Existing service reused

```python
backfill_cve_correlations(
    session,
    *,
    apply: bool,
    limit: int = 100,
    after_id: int = 0,
    as_of: datetime,
) -> CVECorrelationBackfillResult
```

The service scans canonical CVE indicators by ascending ID and processes one bounded page. Valid
canonical CVEs create or reuse events with `cve:<UPPERCASE-CVE>`, rule `shared-cve`, version `v1`,
and relationship reason `shared_canonical_cve`. Invalid CVEs are counted and skipped; non-CVE
indicators are outside the candidate query.

## Scheduled execution

The new task is:

```text
app.workers.cve_correlation_tasks.correlate_cve_page_task
```

For each invocation it:

1. Parses or creates the root sweep's UTC timestamp before taking the lock.
2. Acquires the global `cve-correlation-backfill` Redis lock.
3. Opens one `SessionLocal` transaction.
4. Calls `backfill_cve_correlations(..., apply=True)` for one page.
5. Commits exactly once after the complete page succeeds.
6. Rolls back and propagates any unexpected failure.
7. Releases the lock.
8. Publishes one successor with `next_after_id` only after commit.

The final page commits and stops. Lock contention returns a structured skip response without opening
a database session. Every successor receives the same logical timestamp chosen by the root.

## Configuration

Scheduling is disabled by default because it performs database writes.

| Environment variable | Default | Constraint | Purpose |
| --- | ---: | ---: | --- |
| `CVE_CORRELATION_SCHEDULE_ENABLED` | `false` | Boolean | Enables scheduled apply mode |
| `CVE_CORRELATION_SCHEDULE_INTERVAL_MINUTES` | `60` | at least 1 | Root sweep interval |
| `CVE_CORRELATION_PAGE_LIMIT` | `100` | 1-1000 | CVE indicators per transaction |

Example:

```bash
CVE_CORRELATION_SCHEDULE_ENABLED=true \
CVE_CORRELATION_SCHEDULE_INTERVAL_MINUTES=60 \
CVE_CORRELATION_PAGE_LIMIT=100 \
docker compose up -d --force-recreate celery-worker celery-beat
```

## Recovery and idempotency

The Redis lock serializes scheduled pages. Database uniqueness on event keys and event relationships
remains authoritative if concurrent callers bypass the lock or the lock backend fails open.

Successor publication is intentionally post-commit. If a worker stops between commit and publish,
the next periodic root begins at ID zero, reuses existing events and links, and continues through the
remaining indicators. Exactly-once publication would require an outbox or workflow table and is
deferred to later operational work.

## Files

- `backend/app/workers/cve_correlation_tasks.py`: one-page task, lock, transaction, and continuation.
- `backend/app/core/config.py`: validated enable, interval, and page-limit settings.
- `backend/app/workers/celery_app.py`: task registration and optional Beat root.
- `docker-compose.yml`: Beat environment wiring.
- `backend/tests/test_cve_correlation_tasks.py`: transaction, lock, continuation, and schedule tests.
- `docs/architecture.md`: Phase 10B runtime contract.
- `notes.md`: append-only implementation and verification record.
- `Phase10B_Scheduled_Exact_CVE_Correlation.md`: this operator guide.

## Verification observed on 2026-10-07

```bash
pytest -q backend/tests/test_cve_correlation_service.py \
  backend/tests/test_cve_correlation_backfill.py \
  backend/tests/test_cve_correlation_tasks.py
# 30 passed in 1.38s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_cve_correlation_backfill_postgres.py \
  backend/tests/test_cve_correlation_postgres.py
# 2 passed in 1.57s

pytest -q
# 486 passed, 11 skipped in 15.76s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 497 passed in 14.71s

ruff check .
# All checks passed.

ruff format --check backend/app/workers/cve_correlation_tasks.py \
  backend/app/core/config.py backend/app/workers/celery_app.py \
  backend/tests/test_cve_correlation_tasks.py
# 4 files already formatted.

black --check --no-cache --workers 1 <the same four Python files>
# Exit 0 with no output.

mypy backend
# Success: no issues found in 128 source files.

python -m compileall -q backend
# Exit 0 with no output.

docker compose config --quiet
# Exit 0 with no output.

git diff --check
# Exit 0 with no output.
```

The ownership-validated fixture removed its disposable `threatlens_phase6b_test` database; the final
exact-name count was zero. A read-only transaction observed development database `threatlens` with
428 raw articles, 2023 indicators, 65530 article-indicator links, 234 enrichments, 519 EPSS rows,
zero correlated events, zero event-article links, zero event-indicator links, and one score-history
row, then rolled back. Scheduled correlation remained disabled and did not write development data.

## Remaining work

Phase 10B schedules correlation but does not coordinate it with enrichment, indicator scoring, or
event scoring. Phase 10C should define an explicit cross-stage workflow while retaining each stage's
bounded page and transaction boundaries.

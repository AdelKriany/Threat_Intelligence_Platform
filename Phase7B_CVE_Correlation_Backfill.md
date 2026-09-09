# Phase 7B — bounded CVE correlation backfill
#in notes.md have the same exact copy of this phase
Date: 2026-09-10

## Purpose

Phase 8 adds an explicit operational entry point for the Phase 7 exact-CVE correlation
service. It can inspect or process one deterministic, size-capped page of stored CVE
indicators. Dry-run is the default and performs no writes. Apply mode must be requested
explicitly and commits only the selected page.

This increment reuses the existing database schema. It does not add a migration,
event scoring, an API, a scheduled task, an ingestion trigger, or non-CVE/fuzzy
correlation. `docs/architecture.md` was deliberately not edited for Phase 8.

## Command interface

Run from the repository root with the intended `DATABASE_URL` configured:

```bash
PYTHONPATH=backend python -m app.services.cve_correlation_backfill \
  --dry-run --limit 100 --after-id 0

PYTHONPATH=backend python -m app.services.cve_correlation_backfill \
  --apply --limit 100 --after-id 0
```

`--dry-run` and `--apply` are mutually exclusive. Omitting both selects dry-run.
`--limit` defaults to 100 and must be between 1 and 1,000. `--after-id` defaults to
zero and must be non-negative. Candidates are stored CVE rows with IDs greater than
`after-id`, ordered by ID; the query reads at most `limit + 1` rows so `has_more` can
be reported without an unbounded count.

When `has_more` is true, pass the returned `next_after_id` to the next invocation.
When it is false, the page traversal is complete. The output is one deterministic
JSON object containing:

- mode, requested bound, and input cursor;
- scanned, eligible, and invalid-skipped counts;
- first/last scanned IDs, continuation cursor, and `has_more`;
- relationships forecast by the pre-apply snapshot;
- relationships actually created (zero in dry-run).

Non-CVE indicators are outside the candidate query. CVE-typed rows that are malformed
or not stored in canonical uppercase form are counted as `invalid_skipped` and receive
no event. A valid CVE remains eligible even when it has no article associations; it
creates an event and indicator relationship with zero article relationships.

## Service interface and transaction behavior

```python
backfill_cve_correlations(
    session: Session,
    *,
    apply: bool,
    limit: int = 100,
    after_id: int = 0,
    as_of: datetime,
) -> CVECorrelationBackfillResult
```

The Python service validates a timezone-aware timestamp and all bounds, builds the
page plan with bulk queries, and leaves commit/rollback control to its caller. In
dry-run it only reads. In apply mode it delegates every eligible ID to the Phase 7
`correlate_cve_indicator` service, flushes, and reports actual inserts. The CLI is the
transaction owner: it rolls back dry-run, commits successful apply, and rolls back on
any error.

Forecast counts and actual apply counts are intentionally separate. Another caller
may create a forecast relationship before apply reaches it; database uniqueness then
makes the actual count smaller without making the operation fail. Phase 7 conflict
handling remains scoped to the exact event-key and relationship constraints, so
unexpected integrity failures still propagate and cause CLI rollback.

The plan performs three queries when no candidate event exists and at most five when
existing event links must be inspected, independent of page size and without
per-article database lookups. Article pairs are grouped by indicator in memory.
Apply work is bounded by at most 1,000 scanned CVE indicators and uses stable ascending
ID order. Each eligible CVE still links all of its associations, as required by the
event invariant.

## Files created or edited

### `backend/app/services/cve_correlation_backfill.py` — created

Provides the bounded planner, structured result, dry-run/apply orchestration, argument
validation, JSON output, and executable module entry point. It owns no schema and
reuses the Phase 7 correlation service for mutations.

### `backend/tests/test_cve_correlation_backfill.py` — created

Provides portable SQLite tests for read-only forecasts, deterministic pagination,
hard batch limits, idempotent apply, invalid/non-CVE handling, article-free CVEs,
caller rollback, CLI default/apply behavior, unsafe arguments, and constant dry-run
query counts.

### `backend/tests/test_cve_correlation_backfill_postgres.py` — created

Uses only the existing ownership-validated `threatlens_phase6b_test` fixture. It tests
dry-run immutability, two independent sessions applying the same planned page,
database-level idempotency, pagination, invalid-row accounting, and preservation of
unrelated caller work. It performs no manual create/drop/truncate operation.

### `backend/tests/test_cve_correlation_postgres.py` — edited

Tightens the Phase 7 concurrency assertion from a global event-table count to the
specific `cve:CVE-2026-72001` stable key owned by that test. This allows PostgreSQL
integration tests to share the session-scoped disposable fixture without ordering
assumptions or destructive between-test cleanup.

### `Phase8_CVE_Correlation_Backfill.md` — created

This document records the interface, design decisions, every Phase 8 file change,
actual verification, encountered problems, operating boundaries, and keep/push
guidance.

The pre-existing uncommitted Phase 7 files
`backend/app/services/cve_correlation.py`,
`backend/tests/test_cve_correlation_service.py`,
`backend/tests/test_cve_correlation_postgres.py`, and the Phase 7 addition already in
`docs/architecture.md` remain dependencies of Phase 8. Apart from the test-isolation
assertion described above, Phase 8 did not alter their behavior. `notes.md` was not
edited in this increment.

## Verification actually performed

Focused portable commands:

```bash
pytest -q backend/tests/test_cve_correlation_backfill.py
# 9 passed in 0.62s

pytest -q backend/tests/test_cve_correlation_service.py \
  backend/tests/test_cve_correlation_backfill.py
# 23 passed in 0.94s (final combined run)
```

Focused PostgreSQL commands used the exact fixture-owned database:

```bash
PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_cve_correlation_backfill_postgres.py
# 1 passed in 1.54s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_cve_correlation_backfill_postgres.py \
  backend/tests/test_cve_correlation_postgres.py
# 2 passed in 1.57s (final focused run)
```

Full suites after the final implementation change:

```bash
pytest -q
# 375 passed, 6 skipped in 6.80s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 381 passed in 10.59s
```

The six portable skips are the explicitly PostgreSQL-only tests. No final suite test
failed.

Quality checks after the final Python change:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
# All checks passed.

mypy backend
# Success: no issues found in 97 source files.

python -m compileall -q backend/app backend/tests alembic
# Exit 0 with no output.

ruff format --check <the six Phase 7/8 Python files>
# 6 files already formatted.

black --check <each of the same six Python files, serially>
# Each file would be left unchanged.

git diff --check
# Exit 0 with no output.

PYTHONPATH=backend python -m app.services.cve_correlation_backfill --help
# Exit 0; displayed dry-run/apply, limit, and after-id options.
```

The broader `ruff format --check backend/app backend/tests alembic/versions
alembic/env.py` check reported 105 files formatted and the pre-existing unrelated
`backend/app/ingestion/rss_client.py` as needing reformatting. That file was not
changed. All six Phase 7/8 Python files passed the focused Ruff and Black checks.

## PostgreSQL isolation evidence

Before integration validation, the administrative exact-name query reported zero
databases named `threatlens_phase6b_test`. The ownership-validated fixture created,
marked, and removed its own disposable database for each pytest invocation. A final
administrative query again reported zero exact-name matches.

Read-only development-database transactions before and after validation both observed:

```text
current_database      = threatlens
raw_articles          = 196
indicators            = 1040
article_indicators    = 29925
indicator_enrichments = 124
epss_history          = 122
correlated_events     = 0
event_articles        = 0
event_indicators      = 0
score_history         = 1
```

The transactions were rolled back. The development database was not used by tests or
the backfill command, and no manual database cleanup was performed.

## Problems encountered and resolutions

1. The first focused query-count assertion expected five statements, but a page with
   no existing events correctly skips both existing-link queries and uses three. The
   test expectation was corrected; both one- and three-CVE pages used three.
2. The Docker test image currently lacks pytest. That container attempt stopped with
   `No module named pytest` before test collection. Host pytest was used against the
   same exact fixture URL instead.
3. The first sandboxed host PostgreSQL run could not open the local connection. It was
   rerun through the approved local PostgreSQL access path and passed.
4. The first full PostgreSQL suite produced 380 passes and one failure because the
   older Phase 7 race test counted every event left by other tests. Its assertion was
   scoped to its own stable event key; the two focused tests and final 381-test suite
   then passed without truncation or manual cleanup.

## What to keep and push

All source, test, and documentation files below should be kept, committed, and pushed
together because Phase 8 depends on the uncommitted Phase 7 implementation:

```text
backend/app/services/cve_correlation.py
backend/app/services/cve_correlation_backfill.py
backend/tests/test_cve_correlation_service.py
backend/tests/test_cve_correlation_postgres.py
backend/tests/test_cve_correlation_backfill.py
backend/tests/test_cve_correlation_backfill_postgres.py
docs/architecture.md
Phase8_CVE_Correlation_Backfill.md
```

The test files are part of the permanent regression suite and should be committed and
pushed. Test runtime artifacts are not source and should not be committed or pushed:

```text
.pytest_cache/
.mypy_cache/
.ruff_cache/
**/__pycache__/
.coverage
/tmp/threatlens-phase8-logs/
```

No migration file, database dump, log, generated report, or environment file belongs
to this increment. Nothing was staged, committed, or pushed by Codex.

## Summary and remaining work

Phase 8 adds a safe, bounded, deterministic dry-run/apply CVE correlation backfill,
including explicit cursors and forecasts, transactional apply, concurrent idempotency,
and full portable/PostgreSQL coverage. Event scoring, APIs, automatic invocation,
scheduling, and broader correlation rules remain separate future increments.

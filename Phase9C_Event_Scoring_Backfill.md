# Phase 9C — Bounded Event-Scoring Backfill

Date: 2026-09-15

## Purpose and boundaries

Phase 9C adds a deliberately bounded command-line adapter around the existing Phase 9A event-score
orchestration. It previews or persists scores for exact-CVE event candidates in ascending database
ID order. It does not correlate events, calculate indicator scores, enrich indicators, contact a
provider, make network requests, alter the schema, or delete historical data.

The command processes one page and exits. Dry-run is the default; persistence requires the explicit
`--apply` flag. This makes page boundaries and commits visible to an operator instead of hiding an
unbounded loop inside the command.

## Service interface

```python
backfill_event_scores(
    session,
    *,
    apply: bool,
    limit: int = 100,
    after_id: int = 0,
    as_of: datetime,
) -> EventScoreBackfillResult
```

The caller supplies a timezone-aware calculation time and owns the outer transaction. The service
validates `limit` in the inclusive range 1–1000 and requires a non-negative cursor. It loads at most
`limit + 1` candidate rows, returns at most `limit`, and uses the extra row only to set `has_more`.
Candidates are ordered by `correlated_events.id ASC` and must belong to the exact-CVE family by a
`cve:` key or the historical `shared-cve` rule. This deliberately admits malformed or unsupported
historical candidates so the result can count them instead of silently hiding them; unrelated
campaign events are not scanned.

Every scoreable event delegates to
`calculate_and_persist_event_score(session, event_id, as_of=...)`. The backfill does not reproduce
the formula, evidence snapshot, hashing, components, or uniqueness handling. If an event already
has a score, its latest persisted calculation time is reused as the scoring context. This lets
unchanged evidence forecast or apply as a reuse even if the command is run later. New evidence still
changes the canonical snapshot and creates a new history row.

Dry-run invokes the same orchestration inside a rollback-only savepoint, copies the scalar forecast,
and rolls the savepoint back. Therefore it can report the actual score, severity, evidence hash, and
whether persistence would create or reuse a row without leaving score or component records. The CLI
also rolls back its outer session. Apply leaves each service operation in the caller transaction;
the CLI commits exactly once after the complete bounded page succeeds. An unexpected error rolls
back the whole page.

The structured result reports page metadata and ordered item results, plus separate totals for:

- scoreable events;
- unsupported exact-CVE-family events;
- malformed event keys or relationships;
- unscorable stored score evidence;
- scores that would be created or reused;
- scores actually created or reused in apply mode.

Expected typed data errors are counted and processing continues. Unexpected exceptions propagate to
the CLI transaction boundary and abort the page. Repeated and concurrent apply calls inherit Phase
9A's exact `(event_id, formula_version, evidence_hash)` uniqueness and narrow conflict handling.

## Command-line operation

Run from the repository root with the intended database configuration already set:

```bash
PYTHONPATH=backend python -m app.services.event_scoring_backfill
PYTHONPATH=backend python -m app.services.event_scoring_backfill --dry-run --limit 100 --after-id 0
PYTHONPATH=backend python -m app.services.event_scoring_backfill --apply --limit 100 --after-id 0
```

The first two commands are equivalent read-only previews. The third commits one page. Output is one
compact JSON object. If `has_more` is true, pass the returned `next_after_id` to the next invocation.
Review each dry-run page before applying the corresponding cursor and limit. The command never
selects a database on the operator's behalf, so verify configuration before using `--apply`.

## Files added or changed

- `backend/app/services/event_scoring_backfill.py` adds the bounded service, structured results,
  classification, dry-run savepoints, one-page CLI, bounds, JSON output, and transaction boundary.
- `backend/tests/test_event_scoring_backfill.py` tests dry-run durability, exact forecasts,
  ordering, bounds, cursor paging, classification, idempotency, rollback, CLI commit behavior,
  unexpected-error atomicity, and prohibited-service boundaries on the portable test database.
- `backend/tests/test_event_scoring_backfill_postgres.py` tests dry-run plus two-session concurrent
  apply behavior using only `OwnedDisposablePostgres`, including preservation of unrelated caller
  work and unique score/component persistence.
- `docs/architecture.md` records the Phase 9C contract in the existing architecture document.
- `notes.md` records implementation decisions, problems, exact observed checks, database isolation,
  and remaining work.
- `Phase9C_Event_Scoring_Backfill.md` is this focused operator and implementation guide.

No model, migration, API, ingestion, correlation, enrichment, or scoring-formula file changed.

## Verification observed on 2026-09-15

```bash
pytest -vv backend/tests/test_event_scoring_backfill.py
# 10 passed in 1.10s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -vv backend/tests/test_event_scoring_backfill_postgres.py
# 1 passed in 1.74s

pytest -q backend/tests/test_event_scoring.py backend/tests/test_event_scoring_service.py \
  backend/tests/test_event_score_schemas.py backend/tests/test_event_scores_api.py \
  backend/tests/test_event_schemas.py backend/tests/test_events_api.py \
  backend/tests/test_cve_correlation_service.py backend/tests/test_cve_correlation_backfill.py \
  backend/tests/test_event_scoring_backfill.py
# 105 passed in 3.42s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q <the ten PostgreSQL tests in isolation-safe module order>
# 10 passed in 4.20s

pytest -q
# 457 passed, 10 skipped in 9.39s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 467 passed in 13.27s

ruff check .
# All checks passed.

ruff format --check backend/app/services/event_scoring_backfill.py \
  backend/tests/test_event_scoring_backfill.py \
  backend/tests/test_event_scoring_backfill_postgres.py
# 3 files already formatted.

mypy backend
# Success: no issues found in 119 source files.

python -m compileall -q backend
# Exit 0 with no output.
```

The repository-wide Ruff format check reported one pre-existing unrelated difference in
`backend/app/ingestion/rss_client.py`; it was not changed. The final post-documentation checks are
recorded in `notes.md`.

## Database isolation and remaining work

The PostgreSQL tests used only the ownership-validated fixture for the exact disposable name
`threatlens_phase6b_test`. The fixture created, marked, validated, and removed it; no test manually
created, dropped, truncated, or cleaned a database. Administrative checks observed the exact name
absent before and after validation.

Read-only development checks observed the same before/after values: database `threatlens`, 246 raw
articles, 1223 indicators, 37451 article-indicator links, 144 enrichments, 256 EPSS rows, zero
correlated events/event relationships, and one score-history row. Both checks rolled back.

Scheduling, Celery tasks, an API trigger, automatic scoring, event-list score filters, non-CVE event
scoring, campaign aggregation, enrichment, and correlation remain outside Phase 9C. Nothing was
staged, committed, or pushed.

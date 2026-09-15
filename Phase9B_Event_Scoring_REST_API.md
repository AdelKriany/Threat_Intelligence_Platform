# Phase 9B — Event Scoring REST API

Date: 2026-09-11

## Starting state and scope

Phase 9A core scoring and persistence was committed as `1e592e9`. Initial inspection also found its
event-API regression and documentation still uncommitted: `backend/tests/test_events_api.py`,
`docs/architecture.md`, `notes.md`, and `Phase9A_Event_Scoring_and_Persistence.md`. They were
preserved while Phase 9B was added.

The existing score tables, component table, partial unique index, Phase 9A service, database-session
dependency, and centralized API errors cover Phase 9B. No model, migration, event correlation,
indicator formula, or provider behavior changed.

## Endpoint contracts

```text
POST /api/v1/events/{event_id}/score?force_refresh=false
GET  /api/v1/events/{event_id}/score
GET  /api/v1/events/{event_id}/score/history?limit=20&offset=0
```

POST delegates to `calculate_and_persist_event_score`, serializes the complete response, then
commits exactly once. Every failure rolls back. Newly inserted and reused rows both return 200 with
`created=true` or `created=false` respectively.

With `force_refresh=false`, the router uses the latest persisted event score's calculation time as
the reusable `as_of` context. If no score exists, it uses current UTC. SQLite timestamps are safely
normalized to UTC; an invalid old context retries once at current UTC using the same service.
`force_refresh=true` selects current UTC immediately. Both modes remain governed by the canonical
evidence hash, so the same evidence and same context reuse one row. The flag never refreshes
enrichment, calculates the member indicator, runs correlation, or changes/deletes history.

Latest and history are read-only. Both filter on event target, requested event ID, and null indicator
ID, ordered by `calculated_at DESC, id DESC`. History uses SQL total plus limit 1–100 and offset at
least zero. Existing events have an empty history page but latest returns
`EVENT_SCORE_NOT_FOUND` when no score exists.

## Safe schemas and errors

`EventScoreResponse` exposes score-history ID, event ID/key/title, score, severity, event formula,
evidence hash, UTC `as_of`/calculation timestamps, and ordered components. The POST wrapper adds
`created`; the history wrapper adds event ID, items, pagination, and total.

Components expose name, status, safe raw and normalized input, weight, contribution, freshness,
optional provider/timestamp, and explanation. Ordering is member score then independent sources,
regardless of database collection order. Missing member evidence maps to `missing`; source evidence
maps to `usable`. Numeric API serialization matches Phase 6C.

Responses exclude canonical evidence documents, raw provider/enrichment data, credentials, and
internal exceptions. Stable errors are:

```text
404 EVENT_NOT_FOUND
404 EVENT_SCORE_NOT_FOUND
422 EVENT_UNSCORABLE
```

Unsupported rules, invalid keys, missing/ambiguous/inconsistent CVE links, invalid stored member
scores, and other typed scoring-input failures map to the same safe unscorable response. Unexpected
failures use the existing sanitized 500 response; standard path/query validation remains 422.

## Query and route behavior

Latest uses two SELECTs: one joined score/event query and one select-in component query. History
uses three: event plus SQL total, bounded score page, and select-in components. Query counts are
independent of the number of returned components or history rows. OpenAPI and live requests verify
that the new paths coexist with Phase 8 `/{event_id}`, `/articles`, and `/indicators` routes.

## Files created or modified

- `backend/app/schemas/event_scores.py` — explicit event score/component/POST/history Pydantic
  contracts, UTC normalization, Decimal serialization, and bounds.
- `backend/app/services/event_score_queries.py` — target-safe latest/history queries, reusable
  context lookup, deterministic component order/status, and safe response mapping.
- `backend/app/api/v1/event_scores.py` — thin POST/GET router, transaction ownership, force semantics,
  safe typed error translation, and bounded logging context.
- `backend/app/api/v1/router.py` — registers event-score routes before the Phase 8 event router.
- `backend/tests/test_event_score_schemas.py` — serialization, UTC, evidence exclusion, hash, and
  pagination schema tests.
- `backend/tests/test_event_scores_api.py` — portable POST/reuse/force, response, rollback/error,
  latest/history, pagination, query count, OpenAPI, route, and boundary tests.
- `backend/tests/test_event_scores_api_postgres.py` — real concurrent POST uniqueness and unrelated
  request-work preservation test using the ownership-validated fixture.
- `docs/architecture.md` — endpoint, transaction, safety, query, error, and deferred contracts.
- `notes.md` — dated implementation, problems, exact observed results, database comparison, and diff.
- `Phase9B_Event_Scoring_REST_API.md` — this focused phase document.

The pre-existing uncommitted Phase 9A files remain part of the final working tree and should be
committed with their originating phase or together with Phase 9B as one coherent documentation/API
history update.

## Problems encountered and resolved

The first complete API run had nine passes and four failures. The fixes were:

1. normalize the portable database's naive reusable timestamp to UTC so default POST reuses its
   original calculation context;
2. count commits/rollbacks on the tracking base session rather than the sessionmaker subclass;
3. suppress `CorrelatedEvent`'s select-in relationships in score reads, reducing latest from six
   SELECTs to two and history to three;
4. retain the Phase 6C-style retry for a genuinely invalid reusable context.

Two combined schema/API invocations stalled at the module transition in the command runner and were
manually interrupted; neither reported a test failure. Running each focused module independently
completed normally and produced the final passing results below. Ruff also identified import order
during initial development; imports were corrected before final verification.

## Verification actually performed

```bash
pytest -q backend/tests/test_event_score_schemas.py
# 4 passed in 0.34s

pytest -q backend/tests/test_event_scores_api.py
# 13 passed in 1.37s

pytest -q <four Phase 9B failure/rollback node IDs>
# 4 passed in 0.90s

pytest -q <three Phase 9B latest/history node IDs>
# 3 passed in 0.68s

pytest -q backend/tests/test_event_scores_api.py::test_get_query_counts_are_bounded_and_endpoints_do_not_write
# 1 passed in 0.68s

pytest -q backend/tests/test_event_scoring.py backend/tests/test_event_scoring_service.py
# 30 passed in 0.75s

pytest -q backend/tests/test_event_schemas.py backend/tests/test_events_api.py
# 25 passed in 1.58s

pytest -q backend/tests/test_indicator_score_schemas.py backend/tests/test_indicator_scores_api.py
# 24 passed in 1.32s

pytest -q backend/tests/test_cve_correlation_service.py backend/tests/test_cve_correlation_backfill.py
# 23 passed in 0.86s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_event_scores_api_postgres.py
# 1 passed in 1.62s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q <nine PostgreSQL regression module tests in isolation-safe order>
# 9 passed in 4.64s

pytest -q
# 447 passed, 9 skipped in 8.93s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 456 passed in 12.82s

ruff check backend/app backend/tests alembic/versions alembic/env.py
# All checks passed.

ruff format --check <seven Phase 9B Python files>
# 7 files already formatted.

black --check <each of the seven Phase 9B Python files, serially>
# Each file would be left unchanged.

mypy backend
# Success: no issues found in 116 source files.

python -m compileall -q backend/app backend/tests alembic
# Exit 0 with no output.

git diff --check
# Exit 0 with no output before final documentation append; repeated afterward.
```

The repository-wide Ruff formatting check reported 124 files already formatted and only the known,
unrelated `backend/app/ingestion/rss_client.py` as requiring formatting. It was not changed.

## PostgreSQL isolation and development preservation

The exact disposable database was absent before and after validation. Each PostgreSQL pytest run
used `OwnedDisposablePostgres` to create and mark only `threatlens_phase6b_test`, verify ownership,
terminate its own remaining connections, and remove it through the guarded cleanup path. No manual
database create/drop/truncate/rename/cleanup or volume operation was used.

Read-only development transactions before and after validation both observed:

```text
current_database      = threatlens
raw_articles          = 222
indicators            = 1169
article_indicators    = 34271
indicator_enrichments = 141
epss_history          = 168
correlated_events     = 0
event_articles        = 0
event_indicators      = 0
score_history         = 1
```

Both transactions ended with rollback. Development data was not used by the tests and did not
change during validation.

## Deferred work

Event-score filtering, API-triggered enrichment/correlation/indicator scoring, scoring CLI/backfill,
automatic hooks, Celery tasks/schedules, non-CVE/campaign scoring, authentication, dashboards,
reports, notifications, and schema changes remain deferred.

Nothing was staged, committed, or pushed during this increment.
Final visible working diff (including preserved Phase 9A leftovers): 12 files, 2,538 additions,
and 1 deletion.

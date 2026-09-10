# Phase 8 — correlated-event REST API

Date: 2026-09-10

## Purpose and boundary

Phase 8 exposes the persisted exact-CVE events created by Phase 7A/7B through a typed,
read-only FastAPI interface. It does not run correlation or backfill, calculate or
persist scores, call enrichment providers, modify records, or commit transactions.
The existing schema and indexes cover the implemented query shapes; no migration or
index was added.

## Endpoints

```text
GET /api/v1/events
GET /api/v1/events/{event_id}
GET /api/v1/events/{event_id}/articles
GET /api/v1/events/{event_id}/indicators
```

Every collection supports `limit` (default 20, range 1–100) and `offset` (default 0,
minimum 0). Event IDs must be positive.

The event list orders by `updated_at DESC, id DESC` and supports conjunctive filters:

- `cve`: exact canonical uppercase CVE;
- `source_name`: exact linked-article source name;
- `updated_from` and `updated_to`: inclusive timezone-aware timestamps.

`updated_from` cannot exceed `updated_to`. Invalid canonical CVEs return
`422 INVALID_CVE_FILTER`; naive or reversed time filters return
`422 INVALID_EVENT_FILTER`. Missing detail/article/indicator targets return
`404 EVENT_NOT_FOUND`. Ordinary FastAPI field/path validation remains HTTP 422.

The detail response contains event metadata, relationship counts, and an optional
latest persisted event-score summary, but no unbounded relationships. Article and
indicator relationships have separate pages. Article ordering is
`COALESCE(published_at, fetched_at) DESC, article_id DESC`: publication time is used
when present, otherwise fetch time. Indicator ordering is type, canonical value, then
ID. Score ties are broken deterministically by `calculated_at DESC, id DESC`.

Responses never expose article raw content, enrichment responses, provider payloads,
canonical score evidence, evidence hashes, or score components. Events and indicators
without persisted scores return `latest_score: null`.

## Query design

Reusable SQL construction and response mapping live in the event query service; the
router performs HTTP validation/error translation only.

- Event list: one filtered SQL count plus one page query.
- Event detail: one query.
- Article page: one event-existence/total query plus one page query.
- Indicator page: one event-existence/total query plus one page query.

Correlated `EXISTS` filters prevent duplicate list rows when several articles match a
source. Grouped relationship-count subqueries prevent N+1 aggregate queries. Window
subqueries rank persisted event and indicator scores once per target using the
required timestamp/ID order. Query counts remain fixed as page size grows.

The existing `ix_correlated_events_updated_at`, event relationship primary keys,
article/source indexes, indicator indexes, and score target/calculation-time indexes
support these actual query predicates and orderings. No test or observed query
identified a concrete missing database capability, so no speculative index migration
was introduced.

## Files created or modified

- `backend/app/api/v1/events.py` — new thin read-only router, filter validation, and
  safe API errors.
- `backend/app/api/v1/router.py` — registers the event router under `/api/v1`.
- `backend/app/schemas/events.py` — typed event, article, indicator, score-summary,
  and paginated response contracts with UTC normalization.
- `backend/app/services/event_queries.py` — bounded SQL query service, aggregate
  counts, `EXISTS` filters, score window ranking, ordering, and response mapping.
- `backend/tests/test_event_schemas.py` — schema serialization, extra-field, and
  pagination-bound tests.
- `backend/tests/test_events_api.py` — portable endpoint, validation, filtering,
  ordering, privacy, read-only, and query-count tests.
- `backend/tests/test_events_api_postgres.py` — guarded PostgreSQL verification of
  exact source filtering, de-duplication, timestamp fallback, and score tie-breaking.
- `docs/architecture.md` — endpoint contracts, query strategy, read-only boundary,
  errors, filters, and deferred features.
- `notes.md` — dated implementation and verification log.
- `Phase8_Correlated_Event_REST_API.md` — this focused Phase 8 record.
- `Phase7B_CVE_Correlation_Backfill.md` — corrected internal Phase 7B naming after
  the previously completed backfill was committed during this task.

## Verification actually performed

Focused tests were run first:

```bash
pytest -q backend/tests/test_event_schemas.py backend/tests/test_events_api.py
# 24 passed in 1.39s

pytest -q backend/tests/test_indicator_score_schemas.py \
  backend/tests/test_indicator_scores_api.py
# 24 passed in 1.50s

pytest -q backend/tests/test_cve_correlation_service.py
# 14 passed in 0.75s

pytest -q backend/tests/test_cve_correlation_backfill.py
# 9 passed in 0.65s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_events_api_postgres.py
# 1 passed in 1.50s
```

Final suites:

```bash
pytest -q
# 399 passed, 7 skipped in 6.99s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 406 passed in 9.86s
```

The seven portable skips are PostgreSQL-only tests. No final test failed.

Quality checks:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
# All checks passed.

ruff format --check <seven Phase 8 Python files>
# 7 files already formatted.

black --check <each of the same seven files, serially>
# Each file would be left unchanged.

mypy backend
# Success: no issues found in 103 source files.

python -m compileall -q backend/app backend/tests alembic
# Exit 0 with no output.

git diff --check
# Exit 0 with no output.
```

The broader Ruff formatting check reported 111 formatted files and only the known,
unrelated `backend/app/ingestion/rss_client.py` as needing reformatting. It was not
modified.

## Problems encountered and resolutions

The initial API query-count test counted SQLite's explicit `BEGIN` alongside the two
SELECTs and failed after 20 tests passed. It was aligned with the repository's
established convention of counting SELECT statements; the corrected focused suite
passed all 24 tests and confirmed two SELECTs for list and relationship pages.

While Phase 8 was in progress, the completed Phase 7B work was committed externally as
`0bf5e9a`. The new commit was preserved. Its tracked phase document was retained and
its internal Phase 7B naming corrected. An obsolete duplicate bearing a Phase 8
backfill filename was removed so this REST API document is the only Phase 8 phase
document.

## PostgreSQL isolation and development preservation

Before and after guarded PostgreSQL validation, an administrative exact-name query
found zero databases named `threatlens_phase6b_test`. The hardened fixture exclusively
created, marked, and removed its disposable database; no manual create, drop,
truncate, or cleanup command was used.

Read-only transactions against the development database before and after returned the
same observations:

```text
current_database      = threatlens
raw_articles          = 211
indicators            = 1102
article_indicators    = 32174
indicator_enrichments = 130
epss_history          = 163
correlated_events     = 0
event_articles        = 0
event_indicators      = 0
score_history         = 1
```

Both read-only transactions were rolled back. Development data remained untouched.

## Deferred work

Event-score calculation and persistence orchestration, score/severity list filters,
write endpoints, authentication, automatic correlation, schedules, dashboards, and
non-CVE/fuzzy correlation remain intentionally deferred. The next recommended
increment is to specify and implement event scoring before exposing score-based event
filters.

Nothing was staged, committed, or pushed by Codex during this increment.

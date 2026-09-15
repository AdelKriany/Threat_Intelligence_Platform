# Phase 9A — explainable event scoring and persistence

Date: 2026-09-11

## Purpose and verified starting point

Phase 8 was present as commit `4d6927b`, and initial `git status --short` reported a clean tree.
The final audit revealed that `docs/architecture.md` and `notes.md` had pre-existing modifications
hidden by Git `assume-unchanged` flags. Those flags were cleared for only these two files without
staging them; their earlier Phase 8 documentation was preserved, and Phase 9A was appended.
Inspection confirmed that exact-CVE correlation and the read-only event API existed, and that the
Phase 6B `score_history` and `score_components` tables already supported event targets and the
partial event-evidence unique index. No schema change or migration was required.

Phase 9A adds a synchronous pure scorer and append-only persistence orchestration for Phase 7
exact-CVE events only. It does not change Formula v1 indicator scoring.

## Formula and behavior

The event formula is versioned separately as `phase9a-event-v1`:

```text
event score = latest persisted matching CVE score * 0.90
            + min(max(distinct_source_count - 1, 0), 4) / 4 * 10
```

Examples:

```text
member 80, 1 source  -> 72.00
member 80, 2 sources -> 74.50
missing member, 3 sources -> 5.00
member 100, 5+ sources -> 100.00
```

The engine uses `Decimal`, clamps the total to 0–100, rounds once to two decimals with
`ROUND_HALF_UP`, and applies the existing none/low/medium/high/critical boundaries. Components
always appear as `member_indicator_score`, then `independent_sources`. A missing persisted member
score is explicit, contributes zero, and permits a source-only result.

The service supports only an event whose key is `cve:<CANONICAL-UPPERCASE-CVE>`, whose rule is
`shared-cve:v1`, and which has exactly one canonical CVE relationship agreeing with that key.
Typed failures distinguish missing events, unsupported metadata, invalid keys, missing matching
relationships, ambiguous/inconsistent relationships, and invalid persisted member-score evidence.
The member row is selected from indicator targets by `calculated_at DESC, id DESC`. Event scoring
does not calculate an indicator score and does not read provider enrichment.

Source names come through event/article links. Null and blank names do not count; remaining names
are trimmed, internal whitespace is collapsed, case-folded, de-duplicated, and sorted using the
same normalization as indicator scoring.

## Evidence, persistence, and transactions

The canonical evidence snapshot includes:

- event ID, stable key, correlation rule name/version, and event formula version;
- canonical CVE indicator ID and value;
- `as_of` calculation context;
- sorted normalized source names;
- either explicit member-score absence or safe member score identity, score, severity, formula,
  evidence hash, and timestamp.

It excludes derived event output, component contributions/normalized ratios, provider responses,
the member's full canonical evidence, credentials, and ORM objects. Sorted compact UTF-8 JSON is
hashed with SHA-256. The stored JSON payload is parsed from those same canonical bytes.
`canonical_serialize_event_result` is only deterministic derived-result serialization and is never
used for evidence hashing.

Public orchestration interface:

```python
calculate_and_persist_event_score(
    session: Session,
    event_id: int,
    *,
    as_of: datetime,
) -> PersistedEventScore
```

`PersistedEventScore` exposes the `ScoreHistory` row, ordered component records, `created`, and the
evidence hash. The service flushes without committing. Identical evidence reuses the existing row;
a changed member score, normalized source set, or `as_of` appends a new row. The caller owns commit
or rollback. A nested savepoint catches only the exact event evidence-uniqueness race, re-queries
the winner, and allows unrelated integrity errors to propagate. PostgreSQL concurrency testing
proved that two sessions return the same row/hash, exactly one reports creation, components are not
duplicated, no deadlock occurs, and unrelated caller inserts survive.

## Files created or modified

- `backend/app/scoring/event_models.py` — immutable event evidence/result types and validation.
- `backend/app/scoring/event_engine.py` — pure Event Formula v1 calculation and result serializer.
- `backend/app/scoring/event_evidence_snapshot.py` — canonical evidence payload and SHA-256 hash.
- `backend/app/services/event_scoring.py` — database evidence loading, invariant errors,
  append/reuse persistence, savepoint conflict handling, and public orchestration.
- `backend/tests/test_event_scoring.py` — pure formula, caps, normalization, rounding, severity,
  missing evidence, validation, order, and determinism tests.
- `backend/tests/test_event_scoring_service.py` — portable evidence, snapshot, history,
  idempotency, rollback, preservation, and error tests.
- `backend/tests/test_event_scoring_postgres.py` — guarded two-session PostgreSQL race test.
- `backend/tests/test_events_api.py` — regression proving the existing API reads a Phase 9A score.
- `docs/architecture.md` — Event Formula v1 architecture, evidence, transactions, concurrency, and
  boundaries.
- `Phase9A_Event_Scoring_and_Persistence.md` — this focused phase record.
- `notes.md` — dated implementation and actual verification log.

## Verification and encountered problems

The final observed test results were 19 pure tests, 11 portable service tests, 180 existing
indicator-scoring tests, 25 Phase 8 API tests, and 23 Phase 7A/7B tests passing. The focused
PostgreSQL race passed 1 test. The final portable suite passed 430 tests with 8 PostgreSQL-only
skips, and the PostgreSQL-enabled suite passed all 438 tests.

One initial verification command named a nonexistent `test_scoring.py`; no tests in that command's
indicator-scoring portion ran. It was corrected to `test_scoring_engine.py`, and all 180 selected
indicator tests passed. The first combined PostgreSQL command put indicator tests before the older
backfill module; committed fixture rows then affected that backfill's unscoped first-page forecast,
producing one failure and seven passes. Re-running the same eight integration tests in repository
isolation order passed all eight. No production or historical test code was changed for this
ordering-only issue. A portable rollback test also needed the repository's established explicit
SQLite outer `BEGIN` because the Python driver does not begin a transaction for SELECT in legacy
mode; PostgreSQL transaction behavior required no workaround.

Final quality results were: Ruff lint passed; all eight focused Python files passed Ruff formatting
and serial Black checks; Mypy found no issues in 110 source files; compileall and `git diff --check`
exited successfully. The repository-wide Ruff format check found 118 files formatted and only the
known unrelated `backend/app/ingestion/rss_client.py` requiring formatting; that file was not
changed. A single multi-file Black invocation was blocked by sandbox process creation, so the same
eight checks were run serially and all passed.

The exact disposable database name was absent both before and after PostgreSQL validation. Every
integration run used the ownership-validated fixture, which created, marked, verified, and removed
only `threatlens_phase6b_test`. Read-only development checks before and after both observed:

```text
current_database      = threatlens
raw_articles          = 222
indicators            = 1169
article_indicators    = 34271
indicator_enrichments = 136
epss_history          = 163
correlated_events     = 0
event_articles        = 0
event_indicators      = 0
score_history         = 1
```

Both read-only transactions were rolled back. Exact verification commands and all observed
intermediate/final results are preserved in `notes.md`.

## Scope left unfinished

Event-score APIs, score filters, CLI/backfill scoring, background tasks, schedules, automatic
triggers, indicator-score calculation, provider access, authentication, analyst overrides,
dashboards, event aggregation, and non-CVE/fuzzy/campaign scoring remain deferred.

Nothing was staged, committed, or pushed during this increment.
The final diff therefore contains the surfaced earlier documentation plus Phase 9A.
Final working diff: 11 files, 1,932 additions, and 1 deletion.

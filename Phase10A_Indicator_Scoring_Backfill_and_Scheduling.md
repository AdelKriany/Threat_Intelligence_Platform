# Phase 10A - Bounded Indicator-Scoring Backfill and Scheduling

Date: 2026-10-07

## Purpose

Phase 10A closes the automation gap between stored enrichment evidence and persisted Formula v1
indicator scores. It adds a bounded dry-run/apply service, a command-line entry point, and an
explicitly enabled Celery Beat workflow. Existing indicator scoring remains authoritative.

This phase does not change the scoring formula, provider evidence mapping, canonical evidence hash,
score-history schema, enrichment, correlation, event scoring, APIs, or network behavior. No
migration is required.

## Service interface

```python
backfill_indicator_scores(
    session,
    *,
    apply: bool,
    limit: int = 100,
    after_id: int = 0,
    as_of: datetime,
) -> IndicatorScoreBackfillResult
```

The service selects canonical indicators by ascending ID. It reads at most `limit + 1` lightweight
rows, processes at most `limit`, and uses the extra row only to report `has_more`. The caller owns
the transaction.

Each candidate delegates to `calculate_and_persist_indicator_score`. Dry-run invokes the exact same
persistence path inside a rollback-only savepoint, so its `would_create` and `would_reuse` outcomes
match apply behavior without leaving score or component rows. Apply mode flushes through the
existing service and never commits internally.

The result reports:

- scan bounds, first/last IDs, continuation cursor, and `has_more`;
- scoreable, missing, and unscorable counts;
- would-create/would-reuse forecasts;
- created/reused apply counts; and
- ordered per-indicator type, value, score, severity, formula, and evidence-hash details.

`missing` covers a candidate removed between page selection and evidence loading. `unscorable`
covers typed `ScoringInputError` conditions. Unexpected exceptions abort the whole page.

## Command line

Dry-run is the default:

```bash
python -m app.services.indicator_scoring_backfill --limit 100 --after-id 0
```

Apply exactly one bounded page:

```bash
python -m app.services.indicator_scoring_backfill --apply --limit 100 --after-id 0
```

Both modes print one deterministic JSON result. The command commits exactly once only in apply mode.
Use `next_after_id` for a manual next page when `has_more` is true.

## Scheduling

The schedule is off by default:

| Environment variable | Default | Constraint | Purpose |
| --- | ---: | ---: | --- |
| `INDICATOR_SCORING_SCHEDULE_ENABLED` | `false` | Boolean | Enables scheduled apply mode |
| `INDICATOR_SCORING_SCHEDULE_INTERVAL_MINUTES` | `60` | at least 1 | Root sweep interval |
| `INDICATOR_SCORING_PAGE_LIMIT` | `100` | 1-1000 | Indicators per atomic page |

When enabled, Beat publishes a root at `after_id=0`. The worker:

```text
acquires indicator-scoring-backfill lock
  -> opens one database session
  -> applies one bounded page
  -> commits once
  -> releases the lock
  -> publishes the next cursor after commit
```

The root chooses one UTC logical timestamp and every successor receives it. Indicators with existing
scores use their latest persisted calculation time, preserving unchanged-evidence idempotency while
allowing changed evidence to append score history.

## Files

- `backend/app/services/indicator_scoring_backfill.py`: service, result types, and CLI.
- `backend/app/workers/indicator_scoring_tasks.py`: one-page Celery task and continuation.
- `backend/app/core/config.py`: validated schedule configuration.
- `backend/app/workers/celery_app.py`: task registration and optional Beat entry.
- `docker-compose.yml`: Beat environment wiring.
- `backend/tests/test_indicator_scoring_backfill.py`: portable service and CLI coverage.
- `backend/tests/test_indicator_scoring_tasks.py`: task and scheduling coverage.
- `backend/tests/test_indicator_scoring_backfill_postgres.py`: protected concurrency coverage.
- `docs/architecture.md`: transaction and runtime architecture.
- `notes.md`: implementation and verification record.

## Verification observed on 2026-10-07

```bash
pytest -q backend/tests/test_indicator_scoring_backfill.py \
  backend/tests/test_indicator_scoring_tasks.py
# 16 passed in 0.93s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_indicator_scoring_backfill_postgres.py
# 1 passed in 2.62s

pytest -q
# 479 passed, 11 skipped in 10.09s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 490 passed in 15.45s

ruff check .
# All checks passed.

ruff format --check <seven Phase 10A Python files>
# 7 files already formatted.

black --check --no-cache --workers 1 <seven Phase 10A Python files>
# Exit 0 with no output.

mypy backend
# Success: no issues found in 126 source files.

python -m compileall -q backend
# Exit 0 with no output.

docker compose config --quiet
# Exit 0 with no output.

git diff --check
# Exit 0 with no output.
```

The protected fixture deleted its owned `threatlens_phase6b_test` database; the final exact-name
count was zero. A read-only transaction observed development database `threatlens` with 428 raw
articles, 2023 indicators, 65530 article-indicator links, 234 enrichments, 519 EPSS rows, and one
score-history row, then rolled back. These are final observations, not a before/after equality
claim. Scheduled indicator scoring remained disabled and did not write development data.

## Limitations and next increment

Successor publication is not transactional with the page commit. The next periodic root safely
recovers that narrow window through idempotent replay. Phase 10A does not schedule correlation or
coordinate the entire ingestion-to-event pipeline.

The recommended next increment is Phase 10B: schedule the existing bounded exact-CVE correlation
service with the same disabled-by-default, one-page atomic transaction contract.

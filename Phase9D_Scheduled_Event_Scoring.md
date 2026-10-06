# Phase 9D — Scheduled Event-Scoring Workflow

Date: 2026-09-29

## Purpose and boundaries

Phase 9D schedules the existing Phase 9C exact-CVE event-score backfill with Celery Beat. It does
not change event-score calculation, evidence loading, canonical hashing, persistence semantics,
database models, migrations, correlation, indicator scoring, enrichment, APIs, or provider access.

Scheduling is disabled by default because it performs apply-mode database writes. An operator must
set `EVENT_SCORING_SCHEDULE_ENABLED=true` before Beat will create the periodic entry.

## Execution path

```text
Celery Beat
  -> score_event_page_task(limit, after_id=0, as_of=None)
  -> acquire the existing Redis task lock
  -> open SessionLocal
  -> backfill_event_scores(..., apply=True)
  -> calculate_and_persist_event_score() for each scoreable event
  -> commit exactly once for the complete bounded page
  -> release the task lock
  -> enqueue one successor with next_after_id after commit, when has_more=true
```

Each Celery invocation owns exactly one Phase 9C page transaction. A failure rolls that page back,
releases the lock, propagates to Celery, and never enqueues a successor. The final page commits and
stops. The first page chooses one UTC logical `as_of`; every successor receives the same ISO-8601
value, preventing the sweep clock from changing between pages. Phase 9C still reuses each event's
latest persisted calculation context when one exists.

The global Redis task lock serializes event-score pages. Lock contention returns an explicit
`skipped` result without opening a database session. If Redis is unavailable, the existing lock
helper fails open; Phase 9C's database idempotency remains the final correctness boundary.

There is a deliberate commit-to-enqueue recovery window: a worker can commit and fail before it
publishes the successor. No outbox or workflow table was added. The next periodic root begins at
zero, safely reuses completed scores, and resumes traversal. This favors the existing idempotent
service and schema over a new persistence subsystem.

## Configuration

| Environment variable | Default | Constraint | Purpose |
| --- | ---: | ---: | --- |
| `EVENT_SCORING_SCHEDULE_ENABLED` | `false` | Boolean | Explicitly enables scheduled apply mode |
| `EVENT_SCORING_SCHEDULE_INTERVAL_MINUTES` | `60` | at least 1 | Interval between root sweeps |
| `EVENT_SCORING_PAGE_LIMIT` | `100` | 1–1000 | Maximum events in each atomic page |

Example:

```bash
EVENT_SCORING_SCHEDULE_ENABLED=true \
EVENT_SCORING_SCHEDULE_INTERVAL_MINUTES=60 \
EVENT_SCORING_PAGE_LIMIT=100 \
docker compose up -d --force-recreate celery-worker celery-beat
```

## Files created or modified

- `backend/app/workers/event_scoring_tasks.py` — thin Celery task, lock, one-page transaction, JSON
  result, and post-commit continuation.
- `backend/app/core/config.py` — validated enable, interval, and page-limit settings.
- `backend/app/workers/celery_app.py` — task-module registration and optional Beat entry.
- `docker-compose.yml` — Beat environment settings and backend bind mount so local Beat loads the
  same source tree as the worker.
- `backend/tests/test_event_scoring_tasks.py` — task ordering, commit, rollback, continuation, lock,
  timestamp, registration, and opt-in schedule tests.
- `docs/architecture.md` — Phase 9D runtime and recovery contract.
- `notes.md` — implementation record and observed verification.
- `Phase9D_Scheduled_Event_Scoring.md` — this focused guide.

The Phase 9C backfill service and every scoring/formula file remain unchanged.

## Verification observed on 2026-09-29

```bash
pytest -q backend/tests/test_event_scoring_tasks.py \
  backend/tests/test_event_scoring_backfill.py \
  backend/tests/test_ingestion.py::test_scheduler_builds_beat_schedule \
  backend/tests/test_phase5_enrichment.py::test_phase5_tasks_and_schedules_are_registered
# 18 passed in 0.91s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_event_scoring_backfill_postgres.py
# 1 passed in 1.29s

pytest -q
# 463 passed, 10 skipped in 9.12s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 473 passed, 1 warning in 13.79s

ruff check .
# All checks passed.

ruff format --check <four Phase 9D Python files>
# 4 files already formatted.

black --check --no-cache <each Phase 9D Python file separately>
# All 4 files would be left unchanged.

mypy backend
# Success: no issues found in 121 source files.

python -m compileall -q backend
# Exit 0 with no output.

docker compose config --quiet
# Exit 0 with no output.
```

The full PostgreSQL run emitted one pre-existing Pydantic `Field(alias="offset")` warning from the
event-score API test. The repository-wide Ruff formatting check reported 130 formatted files and
the known unrelated `backend/app/ingestion/rss_client.py` difference; it was not changed.

Live container checks confirmed the worker registers
`app.workers.event_scoring_tasks.score_event_page_task`, the default Beat schedule omits the task,
and an isolated enabled configuration produces the requested 900-second schedule with a 40-event
page. No scheduled event-score task was enabled or executed against the development database.

## Remaining work

Exactly-once task publication would require a transactional outbox or durable workflow record and
is intentionally deferred. Per-event/campaign scheduling, automatic indicator refresh, event-score
API filters, dashboards, reports, and notifications remain outside Phase 9D.

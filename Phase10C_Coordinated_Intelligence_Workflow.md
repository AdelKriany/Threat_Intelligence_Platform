# Phase 10C - Coordinated End-to-End Intelligence Workflow

Date: 2026-10-07

## Purpose

Phase 10C connects the already implemented ThreatLens stages so one scheduled run can move newly
ingested reporting through the complete intelligence path:

```text
ingestion -> IOC extraction -> enrichment -> indicator scoring
          -> exact-CVE correlation -> event scoring
```

The coordinator reuses the existing stage services. It does not change Formula v1, event-scoring
semantics, provider mappings, exact-CVE event keys, rules, titles, relationships, or uniqueness
handling.

## Durable interface

Two Celery tasks form the public worker interface:

```text
start_intelligence_workflow_task(as_of=None) -> structured run state
advance_intelligence_workflow_task(run_id) -> structured run state
```

The start task creates one active run or recovers the existing active run. It snapshots the logical
UTC timestamp and configured page limits, commits that state, and then queues the first/current page.
The advance task executes exactly one stage or bounded page, commits its result, and queues the next
page only when the durable row remains active.

## Persistence added

Migration `7d3e1a9c5b20` adds `intelligence_workflow_runs` with:

- `run_id` and workflow version;
- overall and current-stage status;
- current stage and ascending-ID `after_id` cursor;
- one logical scoring/correlation timestamp;
- a page-limit snapshot;
- accumulated per-stage outcomes and counters;
- terminal error type/message;
- created, started, updated, and completed timestamps;
- a nullable unique active slot, which permits only one non-terminal run.

Statuses make queued, running, skipped, completed, and failed work visible without adding an API in
this phase. Concurrent start attempts rely on the named active-slot constraint; only that exact
conflict is interpreted as reuse of the winning run.

## Stage and transaction behavior

### Ingestion and IOC extraction

The coordinator calls the existing ingestion service for all configured feeds. IOC extraction and
canonical indicator persistence remain in `FeedManager`. Per-article enrichment fan-out is disabled
for this call because the next coordinated stage owns enrichment. Existing content hashes and
canonical indicator constraints make replay safe. Feed-level errors remain isolated and are recorded
as a degraded ingestion outcome; successfully ingested reporting continues through later stages.

### Enrichment

If enrichment is disabled, the run records an explicit skipped outcome and proceeds. If enabled, the
coordinator repeatedly calls the existing pending-enrichment selector. In coordinated mode the
selected page is committed atomically rather than committing once per indicator. Provider result and
EPSS upserts retain their existing concurrency behavior. A full page causes another bounded page;
a short/empty page completes the stage. Enrichment-lock contention is recorded and retried.

### Indicator scoring, correlation, and event scoring

Each invocation calls exactly one existing bounded backfill in apply mode:

```text
backfill_indicator_scores(...)
backfill_cve_correlations(...)
backfill_event_scores(...)
```

The domain writes, accumulated outcome, and next cursor commit together in one transaction. The
logical timestamp remains stable across the entire run. Existing evidence hashes, stable CVE event
keys, and relationship constraints preserve idempotency during replay and concurrency.

## Scheduling and recovery

Coordinated scheduling is disabled by default:

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `INTELLIGENCE_WORKFLOW_SCHEDULE_ENABLED` | `false` | Enable the coordinated apply workflow |
| `INTELLIGENCE_WORKFLOW_SCHEDULE_INTERVAL_MINUTES` | `60` | Root/recovery interval |
| `INTELLIGENCE_WORKFLOW_RETRY_DELAY_SECONDS` | `30` | Delay after stage-lock contention |

When coordinated mode is enabled, Beat installs only `run-intelligence-workflow`. It intentionally
does not install the separate ingestion, enrichment, indicator-scoring, correlation, or event-scoring
schedules, even if their individual flags are also true.

Every continuation is sent after commit. If a worker stops in the commit-to-publish gap, the next
scheduled root recovers the active row at its persisted stage/cursor. If a stage throws unexpectedly,
the page rolls back, the run becomes terminally failed, and no continuation is sent. A later root
creates a new run; domain idempotency makes that replay safe.

## Enabling the workflow

Apply the migration before enabling the schedule:

```bash
alembic upgrade head
```

Set the coordinated flag and restart worker/Beat:

```bash
INTELLIGENCE_WORKFLOW_SCHEDULE_ENABLED=true docker compose up -d --build \
  celery-worker celery-beat
```

The schedule performs database writes and may call configured feed/provider networks. Keep the flag
false until migrations, feed configuration, provider credentials, and rate limits are ready.

## Inspecting stored workflow state

From the PostgreSQL container:

```bash
docker compose exec -T postgres psql -U threatlens -d threatlens -X -c "
SELECT run_id, status, current_stage, stage_status, after_id,
       logical_as_of, error_type, error_message, created_at, updated_at, completed_at
FROM intelligence_workflow_runs
ORDER BY created_at DESC
LIMIT 20;"
```

Inspect per-stage counters/outcomes for one run:

```bash
docker compose exec -T postgres psql -U threatlens -d threatlens -X -c "
SELECT run_id, jsonb_pretty(stage_outcomes)
FROM intelligence_workflow_runs
ORDER BY created_at DESC
LIMIT 1;"
```

## Files and purpose

- `alembic/versions/20261007_phase10c_intelligence_workflow.py`: durable run-state migration.
- `alembic/env.py`: exposes the new model to migration metadata.
- `backend/app/models/intelligence_workflow.py`: workflow-run ORM model and constraints.
- `backend/app/services/intelligence_workflow.py`: state transitions, counters, cursor, and failure
  persistence.
- `backend/app/workers/intelligence_workflow_tasks.py`: start/recovery and one-page state machine.
- `backend/app/ingestion/scheduler.py`: reusable ingestion entry point with coordinated dispatch mode.
- `backend/app/ingestion/feed_manager.py`: explicit switch that prevents duplicate enrichment fan-out.
- `backend/app/ingestion/enrichment/service.py`: caller-selectable commit ownership.
- `backend/app/ingestion/enrichment/tasks.py`: shared atomic bounded batch entry point.
- `backend/app/core/config.py`, `.env.example`, and `docker-compose.yml`: default-off runtime settings.
- `backend/app/workers/celery_app.py`: registration and exclusive coordinated Beat schedule.
- `backend/tests/test_intelligence_workflow_tasks.py`: portable state-machine and real-service tests.
- `backend/tests/test_phase10c_postgres_migration.py`: protected migration and concurrent-start tests.
- `docs/architecture.md`: architecture and recovery contract.
- `notes.md`: append-only implementation and verification log.
- `Phase10C_Coordinated_Intelligence_Workflow.md`: this implementation/operator guide.

## Verification observed on 2026-10-07

The final exact commands and results are recorded in `notes.md`. The completed validation included
focused workflow/regression tests, the entire portable suite, the entire ownership-protected
PostgreSQL suite, Ruff, formatting, Mypy, compileall, Compose validation, migration head validation,
and whitespace/diff checks.

## Deliberate limits and next increment

Phase 10C does not add a workflow REST API, cancellation, manual retry endpoint, alerting, dashboard,
reports, authentication, fuzzy correlation, or new scoring behavior. Workflow history is queryable by
SQL and visible through Celery/logs. The recommended next increment is Phase 11: complete the stable
analyst read API, including bounded workflow-status visibility if operators need it outside SQL.

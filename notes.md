# ThreatLens Canonical Indicator Repair Verification Notes

## Canonical indicator repair work log

Pre-edit inspection found:

- Active ownership was `RawArticle -> Indicator` with `delete-orphan`; every indicator
  carried a non-null `raw_article_id`.
- The actual uniqueness rule was
  `(raw_article_id, indicator_type, indicator_value)`, so identical values in different
  articles intentionally received different IDs.
- Extraction normalizes CVEs to uppercase, hashes/domains/emails to lowercase, IPv4
  and IPv6 through Python's `ipaddress` canonical form, and leaves validated HTTP(S)
  URLs in their existing exact representation.
- Current enrichment upserts conflict on `(indicator_id, provider)`. EPSS history
  conflicts on `(indicator_id, model_date)`.
- `indicator_enrichments.indicator_id` and `epss_history.indicator_id` are the only
  active foreign keys referencing `indicators`.
- Migration risks are provider-row collisions after ID repointing, EPSS same-date
  collisions, accidental cascade deletion, invalid legacy values, and the inherently
  lossy downgrade from many article mentions back to one `raw_article_id`.

The repair uses `(indicator_type, indicator_value)` as the canonical identity after
applying the existing safe normalization rules. Invalid legacy values are preserved
verbatim instead of being cast or rejected during migration, so they cannot abort the
upgrade or be silently merged.

## Canonical repair checks actually run

Changed-file formatting:

```bash
ruff format --check \
  backend/app/ingestion/models.py \
  backend/app/ingestion/feed_manager.py \
  backend/app/ingestion/ioc/persistence.py \
  backend/app/ingestion/enrichment/tasks.py \
  backend/app/models/indicator.py \
  backend/tests/test_ioc_enrichment.py \
  backend/tests/test_phase5_enrichment.py \
  backend/tests/test_ingestion.py \
  backend/tests/test_canonical_indicators.py \
  alembic/versions/20260729_canonical_indicators.py
```

Expected and observed output:

```text
10 files already formatted
```

The repository-wide formatting command was also attempted. It reported only:

```text
Would reformat: backend/app/ingestion/rss_client.py
1 file would be reformatted, 71 files already formatted
```

That unrelated pre-existing file was deliberately not modified.

Repository-wide Ruff, Mypy, tests, compilation, migration head, Compose, and diff:

```bash
ruff check backend/app backend/tests alembic/versions
mypy backend
pytest -q
python -m compileall -q backend/app alembic/versions
alembic heads
docker compose config -q
git diff --check
```

Expected and observed significant output:

```text
All checks passed!
Success: no issues found in 65 source files
77 passed
b74f3c9a21de (head)
```

The final three commands other than `alembic heads` produce no output on success.

The migration was also tested against a separate disposable PostgreSQL 16 database
populated at revision `61b739ac42e5` with three articles, four old indicator rows,
conflicting NVD/KEV/EPSS statuses, and duplicate same-date EPSS history. Upgrade
produced these exact counts:

```text
canonical_indicators = 2
mentions             = 4
provider_rows        = 3
history_rows         = 1
orphan_count         = 0
```

`CVE-2026-15409` became one canonical row with three article associations. The retained
provider rows were NVD success, KEV successful negative, and EPSS success; newer
failure/rate-limit rows did not replace successes. The newest same-date EPSS observation
(`0.2000000`, percentile `0.6000000`) won. Downgrade to `61b739ac42e5` and re-upgrade
to head both completed successfully; as documented, downgrade necessarily loses
additional article associations.

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
  backend/tests/test_phase5_enrichment.py \
  alembic/versions/20260724_phase32_indicator_enrichments.py \
  alembic/versions/20260729_phase5_epss_history.py
```

Expected output:

```text
25 files already formatted
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
Success: no issues found in 65 source files
```

## 4. Compile the Python sources

```bash
python -m compileall -q backend/app alembic/versions
```

Expected output:

```text
```

No output and an exit status of zero means compilation succeeded.

## 5. Run the focused Phase 5 and regression tests

```bash
pytest -q \
  backend/tests/test_phase5_enrichment.py \
  backend/tests/test_ioc_enrichment.py \
  backend/tests/test_enrichment.py \
  backend/tests/test_ingestion.py \
  backend/tests/test_ioc_extraction.py
```

Expected output:

```text
.....................................................................    [100%]
70 passed
```

These tests cover:

- NVD value caching and per-CVE Redis locking
- CISA KEV positive, negative, malformed, oversized, timeout, 429, and 5xx responses
- EPSS batching, partial responses, exact decimal persistence, and daily history
- Provider enablement, IOC selection, and indicator/provider uniqueness
- Success, not-found, rate-limited, temporary-failure, and permanent-failure TTLs
- `Retry-After`, bounded exponential backoff, and idempotent refreshes
- Celery provider restriction, overlap locks, schedules, and database cleanup
- Existing RSS ingestion and IOC extraction regressions

## 6. Run the complete test suite

```bash
pytest -q
```

Expected output:

```text
......................................................................   [100%]
77 passed
```

The health test uses HTTPX's in-process ASGI transport because FastAPI's blocking
`TestClient` stalled with the available Python 3.14 runtime.

## 7. Verify the Alembic migration chain

```bash
alembic heads
```

Expected output:

```text
b74f3c9a21de (head)
```

To inspect the complete chain:

```bash
alembic history --verbose
```

The first revision in the output should be:

```text
Rev: b74f3c9a21de (head)
Parent: 61b739ac42e5
Path: .../alembic/versions/20260729_canonical_indicators.py
```

Apply the migration to a configured PostgreSQL database with:

```bash
alembic upgrade head
```

Expected successful final line:

```text
Running upgrade 61b739ac42e5 -> b74f3c9a21de, Canonicalize indicators and preserve article mentions in an association table.
```

The migration was applied only to the separate disposable
`threatlens_canonical_test` database. It was intentionally not applied to the populated
ThreatLens database. Downgrade and re-upgrade were both executed on that disposable
fixture.

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
 M backend/app/ingestion/enrichment/exceptions.py
 M backend/app/ingestion/enrichment/persistence.py
 M backend/app/ingestion/enrichment/providers/__init__.py
 M backend/app/ingestion/enrichment/providers/base.py
 M backend/app/ingestion/enrichment/providers/nvd.py
 M backend/app/ingestion/enrichment/registry.py
 M backend/app/ingestion/enrichment/service.py
 M backend/app/ingestion/enrichment/tasks.py
 M backend/app/ingestion/enrichment/types.py
 M backend/app/ingestion/models.py
 M backend/app/workers/celery_app.py
 M backend/tests/test_ioc_enrichment.py
 M docs/architecture.md
 M docker-compose.yml
 M notes.md
?? alembic/versions/20260729_phase5_epss_history.py
?? backend/app/ingestion/enrichment/cache.py
?? backend/app/ingestion/enrichment/providers/cisa_kev.py
?? backend/app/ingestion/enrichment/providers/epss.py
?? backend/tests/test_phase5_enrichment.py
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
settings.cisa_kev_enabled, settings.epss_enabled, \
settings.abuseipdb_enabled, settings.virustotal_enabled)"
```

Expected Phase 5 output with future providers safely disabled:

```text
True True True True False False
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
app.ingestion.enrichment.tasks.phase5_coverage_task
app.ingestion.enrichment.tasks.refresh_epss_batch_task
app.ingestion.enrichment.tasks.refresh_kev_catalog_task
```

The final runtime check returned:

```text
1 node online.
```

Run one known existing CVE first, explicitly restricting it to NVD:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_indicator_task \
  --args='[INDICATOR_ID,["nvd"]]'
```

Expected output is a Celery task UUID. Confirm that exact indicator before continuing:

```sql
SELECT indicator_id, provider, status, severity, error_code, error_message
FROM indicator_enrichments
WHERE indicator_id = :tested_indicator_id;
```

Only after observing that row, run a three-item NVD-only batch:

```bash
docker compose exec -T celery-worker \
  celery -A app.workers.celery_app call \
  app.ingestion.enrichment.tasks.enrich_pending_batch_task --args='[3,"nvd"]'
```

Expected worker result:

```text
{'indicators': 3, 'results': 3}
```

The bounded live smoke also completed three-item KEV and EPSS refreshes successfully.
The exact success/not-found distribution depends on the selected CVEs and the current
official catalogs.

## 10. Optional PostgreSQL verification

After applying the migration and running enrichment, inspect stored results:

```sql
SELECT
    indicator_id,
    provider,
    status,
    severity,
    error_code,
    enriched_at,
    expires_at
FROM indicator_enrichments
ORDER BY updated_at DESC
LIMIT 20;
```

Expected shape:

```text
 indicator_id | provider | status    | severity | error_code | enriched_at | expires_at
--------------+----------+-----------+----------+------------+-------------+------------
 ...          | nvd      | success   | ...      |            | ...         | ...
 ...          | cisa_kev | success   |          |            | ...         | ...
 ...          | epss     | not_found |          | not_found  | ...         | ...
```

Verify exact EPSS observations separately:

```sql
SELECT indicator_id, model_date, epss, percentile, fetched_at
FROM epss_history
ORDER BY fetched_at DESC
LIMIT 20;
```

Expected shape:

```text
 indicator_id | model_date |   epss    | percentile | fetched_at
--------------+------------+-----------+------------+------------
 ...          | 2026-..-.. | 0.......  | 0.......   | ...
```

Exact rows depend on the enabled providers, current upstream data, and extracted CVEs.
Phase 5 does not calculate a combined risk score; that remains Phase 6 work.

## Phase 6A IOC quality and read-only audit

Narrow tests were run first:

```bash
pytest -q \
  backend/tests/test_ioc_validation.py \
  backend/tests/test_ioc_extraction.py \
  backend/tests/test_enrichment.py
```

Expected and observed output:

```text
53 passed
```

Repository-wide verification:

```bash
ruff check backend/app backend/tests alembic/versions
mypy backend
pytest -q
```

Expected and observed output:

```text
All checks passed!
Success: no issues found in 67 source files
120 passed
```

Read-only database audit commands:

```bash
docker compose exec -T api \
  python -m app.ingestion.ioc.audit --format summary --sample-limit 3
docker compose exec -T api \
  python -m app.ingestion.ioc.audit --format json --sample-limit 1
```

Observed summary on 2026-08-09:

```text
total=1753 valid=1133 invalid=619 suspicious=1
invalid type=domain reason=domain_file_extension count=619
  id=19 value=11-old-microsoft-signed-linux-uefi.html
  id=20 value=148-npm-packages-disguised-as-student.html
  id=21 value=20-hijacked-government-websites.html
suspicious type=ipv4 reason=ip_non_public count=1
  id=23809 value=127.0.0.1
```

The audit selected only indicator IDs, types, and values. It did not update, delete, or
commit database records. Default exit status was zero despite findings. Cleanup remains
a separate migration requiring review.

Health verification inside the API container:

```bash
docker compose exec -T api python -c \
  "import urllib.request; response=urllib.request.urlopen(\
'http://127.0.0.1:8000/api/v1/health', timeout=5); \
print(response.status); print(response.read().decode())"
```

Observed output:

```text
200
{"status":"ok"}
```

## Phase 6A reviewed IOC cleanup — 2026-08-11

Architecture decision: use `app.ingestion.ioc.cleanup`, not an Alembic data migration.
No schema change was required, and destructive policy remains bound to a checksum-
verified reviewed audit rather than mutable historical migration behavior.

### Verified backup

PostgreSQL client and server were both `16.14`; Alembic was `b74f3c9a21de`.

```bash
docker compose exec -T postgres pg_dump \
  -U threatlens -d threatlens \
  --format=custom --no-owner --no-privileges \
  > backups/threatlens-before-ioc-cleanup-20260811-081350.dump
docker compose exec -T postgres pg_restore --list \
  < backups/threatlens-before-ioc-cleanup-20260811-081350.dump
sha256sum backups/threatlens-before-ioc-cleanup-20260811-081350.dump \
  > backups/threatlens-before-ioc-cleanup-20260811-081350.dump.sha256
```

Observed:

```text
size=10159970 bytes
sha256=52435114251dce89ce29452f33d113240f3378ff83b40063d60e47aa29b785a8
pg_restore catalog entries=61
```

The dump was restored into isolated database
`threatlens_ioc_cleanup_restore_20260811`. Live and restored counts matched exactly:

```text
indicators=1850 article_indicators=64490 indicator_enrichments=129
epss_history=256 raw_articles=384
```

The isolated restore database was then removed.

### Freeze and final reviewed audit

Only `api`, `celery-worker`, and `celery-beat` were stopped. PostgreSQL and Redis stayed
running; no queue was cleared.

Final audit artifact:

```text
backups/phase6a-ioc-audit-20260811-081519.json
sha256=96f65e971825f4acc25f51ef8f7c813176708ad9e4d6a525f32ab6be2c5155b1
```

Observed:

```text
total=1850 valid=1213 invalid=635 suspicious=2
invalid/domain/domain_file_extension=635 (635 samples present)
suspicious/ipv4/ip_non_public=1
suspicious/ipv6/ip_non_public=1
```

### Dry run and apply

The initial container dry run stopped before database access because the read-only bind
mount lacked an SELinux label. It returned `PermissionError` and changed nothing. The
correct mount is `:ro,z`.

Dry-run output:

```text
mode=dry-run candidates=635 article_relationships=25687 enrichments=0 epss_history=0 indicators_deleted=0 article_relationships_deleted=0 enrichments_deleted=0 epss_history_deleted=0
```

Apply output:

```text
mode=apply candidates=635 article_relationships=25687 enrichments=0 epss_history=0 indicators_deleted=635 article_relationships_deleted=25687 enrichments_deleted=0 epss_history_deleted=0
```

### Post-cleanup verification

Before restart:

```text
total=1215 valid=1213 invalid=0 suspicious=2
indicators=1215 article_indicators=38803 indicator_enrichments=129
epss_history=256 raw_articles=384
article association orphans=0 enrichment orphans=0 EPSS orphans=0
```

After restarting only the three paused services, the final audit remained:

```text
total=1215 valid=1213 invalid=0 suspicious=2
ipv4 suspicious: id=23809 value=127.0.0.1
ipv6 suspicious: id=63886 value=::c
```

API health returned `200 {"status":"ok"}` and Celery reported one node online with all
seven expected tasks registered.

Final checks:

```text
focused cleanup/validator/extraction tests: 57 passed
full test suite: 129 passed
Ruff: All checks passed!
Mypy: Success: no issues found in 69 source files
compileall: exit 0
docker compose config -q: exit 0
Alembic: b74f3c9a21de (head)
git diff --check: exit 0
```

The repository-wide format check still reports only the unrelated pre-existing
`backend/app/ingestion/rss_client.py`; nine changed Python files are formatted.

Recovery procedure: stop application writers, restore the verified custom-format dump
into a new database first, validate its counts, then switch database configuration or
restore the live database according to the deployment runbook. There is intentionally
no fake Alembic downgrade for deleted data.

## Phase 6B scoring-engine review fixes

Run these commands from the repository root:

```bash
cd /home/adel/programming/osint_tool/Threat_Intelligence_Platform
```

The first focused run exposed the missing-component explanation defect:

```bash
pytest -q backend/tests/test_scoring_engine.py
```

Expected at that intermediate stage, and observed:

```text
1 failed, 96 passed
```

The failure was
`test_no_evidence_is_zero_and_emits_fixed_cve_profile`: absent provider components
did not explicitly say that evidence was missing. The implementation was corrected;
the test was not weakened.

An intermediate lint/type pass also found one import-order error, four files needing
formatting, and four intentional float-rejection test inputs requiring type-checker
annotations. After the first correction, Mypy found three annotations placed on the
wrong lines. These were corrected before final verification.

Final focused scoring and IOC-validator regression command:

```bash
pytest -q backend/tests/test_scoring_engine.py backend/tests/test_ioc_validation.py
```

Expected and observed output:

```text
........................................................................ [ 51%]
....................................................................     [100%]
140 passed in 0.77s
```

Final lint and formatting commands:

```bash
ruff check backend/app/scoring backend/tests/test_scoring_engine.py
ruff format --check backend/app/scoring backend/tests/test_scoring_engine.py
```

Expected and observed output:

```text
All checks passed!
6 files already formatted
```

Final static-type command:

```bash
mypy backend
```

Expected and observed output:

```text
Success: no issues found in 75 source files
```

Compilation command:

```bash
python -m compileall -q backend/app/scoring backend/tests/test_scoring_engine.py
```

Expected and observed output:

```text
```

No output with exit status zero means compilation succeeded.

Final full backend test command:

```bash
pytest -q
```

Expected and observed output:

```text
........................................................................ [ 31%]
........................................................................ [ 63%]
........................................................................ [ 95%]
...........                                                              [100%]
227 passed in 4.32s
```

Final pre-commit inspection commands:

```bash
git status --short
git diff --check
git diff -- backend/app/scoring backend/tests/test_scoring_engine.py
```

Expected output: status lists the untracked Phase 6B files and the modified
`notes.md`; both diff commands exit successfully. Because the Phase 6B files are still
untracked, ordinary `git diff` does not print their contents until they are staged.
No files were staged and no commit was created. `docs/phase6b-spec.md` was read for
clarification and left untouched.

### Phase 6B specification reconciliation — 2026-08-17

The scoring engine was reconciled with `docs/phase6b-spec.md`: suspicious or
non-public validation status now has no scoring side effects. Non-public and globally
routable IPs use the same independent-source formula, and usable provider evidence is
weighted identically. Explicit provider expiry takes precedence over TTL-derived
expiry. The result serializer is documented as derived-output serialization, not as
the future persistence evidence-hash input.

Focused scoring tests:

```bash
pytest -q backend/tests/test_scoring_engine.py
```

Expected and observed output:

```text
........................................................................ [ 66%]
.....................................                                    [100%]
109 passed in 0.62s
```

Full backend suite:

```bash
pytest -q
```

Expected and observed output:

```text
........................................................................ [ 30%]
........................................................................ [ 60%]
........................................................................ [ 90%]
......................                                                   [100%]
238 passed in 4.26s
```

Quality checks:

```bash
ruff check backend/app/scoring backend/tests/test_scoring_engine.py
ruff format --check backend/app/scoring backend/tests/test_scoring_engine.py
mypy backend
python -m compileall -q backend/app/scoring backend/tests/test_scoring_engine.py
git diff --check
```

Expected and observed significant output:

```text
All checks passed!
6 files already formatted
Success: no issues found in 75 source files
```

`compileall` and `git diff --check` produced no output and exited zero. The first
format check identified two files requiring formatting; `ruff format` reformatted
them, after which the final format check passed. No migration, persistence work,
staging change, or commit was performed by Codex.

## Phase 6B persistence schema verification — 2026-08-17

This increment adds only ORM mappings, one migration, and database-level tests for
correlated-event links and explainable score history. Revision `c9f4e2a7b6d1` follows
`b74f3c9a21de`. No scorer orchestration, correlation logic, hash service, API, CLI, or
task was added.

Focused portable model tests:

```bash
pytest -q backend/tests/test_phase6b_persistence.py
```

Expected and observed output:

```text
...................                                                      [100%]
19 passed in 0.93s
```

The PostgreSQL-only test was run inside an ephemeral application container on the
Compose network. The repository was mounted read-only and both `DATABASE_URL` and
`PHASE6B_POSTGRES_URL` named only `threatlens_phase6b_test`:

```bash
python -m pytest -q -p no:cacheprovider \
  backend/tests/test_phase6b_postgres_migration.py
```

Expected and observed output after the final test hardening:

```text
.                                                                        [100%]
1 passed in 3.21s
```

That test reset only the safety-checked disposable database, upgraded from base to
head, inspected the schema, exercised PostgreSQL checks/partial indexes/JSONB/Decimal/
UTC/cascades, downgraded to `b74f3c9a21de`, verified prior tables remained, and
re-upgraded to head. Separate Alembic CLI downgrade and re-upgrade commands were also
executed against the same disposable database and reported:

```text
Running downgrade c9f4e2a7b6d1 -> b74f3c9a21de
version_num = b74f3c9a21de
prior tables retained: article_indicators, indicators, raw_articles
Running upgrade b74f3c9a21de -> c9f4e2a7b6d1
```

Direct PostgreSQL catalog inspection found all five tables, 21 named constraints, and
14 indexes including primary/unique indexes. `alembic check` reported:

```text
No new upgrade operations detected.
```

The final complete suite was run in the ephemeral container with the PostgreSQL-only
test enabled:

```bash
python -m pytest -q -p no:cacheprovider
```

Expected and observed output:

```text
........................................................................ [ 27%]
........................................................................ [ 55%]
........................................................................ [ 83%]
..........................................                               [100%]
258 passed in 8.21s
```

Host quality commands:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
ruff format --check \
  alembic/env.py \
  alembic/versions/20260817_phase6b_score_history.py \
  backend/app/models/__init__.py \
  backend/app/models/phase6b.py \
  backend/tests/test_phase6b_persistence.py \
  backend/tests/test_phase6b_postgres_migration.py
mypy backend
python -m compileall -q backend/app backend/tests alembic/versions
git diff --check
```

Expected output:

```text
All checks passed!
6 files already formatted
Success: no issues found in 78 source files
```

`compileall` and `git diff --check` have no output on success. The repository-wide
format check still identifies only the unrelated pre-existing
`backend/app/ingestion/rss_client.py`; it was not modified. The disposable PostgreSQL
database was dropped after verification. Real concurrent-transaction contention was
not simulated; PostgreSQL uniqueness and rollback behavior were verified sequentially.

## Phase 6B indicator-score orchestration — 2026-08-23

This increment adds only synchronous indicator evidence loading, canonical evidence
snapshot hashing, pure-engine invocation, append-only indicator score persistence, and
focused tests. It does not add event scoring/correlation, an API, CLI, worker, schedule,
trigger, backfill, migration, or schema change. Nothing was staged or committed, and
the existing `engineDElete.txt` and `modelsDElete.txt` files were not touched.

Created files:

```text
backend/app/scoring/evidence_snapshot.py
backend/app/services/indicator_scoring.py
backend/tests/test_indicator_scoring_service.py
backend/tests/test_indicator_scoring_postgres.py
```

Public service interfaces:

```python
calculate_and_persist_indicator_score(session, indicator_id, *, as_of)
load_indicator_scoring_evidence(session, indicator_id, *, as_of)
latest_provider_records(records, provider_names)
persist_indicator_score(session, *, indicator_id, score_result, snapshot)
PersistedIndicatorScore(score_history, components, created, evidence_hash)
IndicatorNotFoundError
```

Canonical-evidence interfaces:

```python
applicable_provider_names(ioc_type)
build_canonical_evidence_payload(evidence, *, formula_version=...)
canonical_serialize_evidence_payload(payload)
build_evidence_snapshot(evidence, *, formula_version=...)
CanonicalEvidenceSnapshot(canonical_bytes, evidence_hash)
```

The snapshot includes `formula_version`, `ioc_type`, `canonical_value`, normalized
`as_of`, normalized `source_names`, and a fixed ordered `providers` list. Each provider
entry contains `provider`, `status`, safe scoring `raw_input`, `evidence_at`, explicit
`expires_at`, and `effective_expiry`. These fields identify the evidence and reproduce
the freshness calculation. It excludes final/total score, severity, contribution,
explanation, database IDs, insertion timestamps, component rows, and raw provider
responses because those are derived output, storage identity, mutable data, or may
contain secrets. SHA-256 is calculated over strict sorted compact UTF-8 JSON bytes;
the logically identical decoded payload is stored in JSONB.

Status mapping is explicit:

```text
success + valid normalized data -> usable
success + invalid normalized data -> invalid
not_found -> missing
failed, rate_limited, auth_error, temporary_failure -> failed
permanent_failure, invalid, unknown status -> invalid
unsupported -> unsupported
```

Non-usable states carry no invented values or timestamps. Unsupported provider/IOC
pairings are not loaded. The service performs three evidence queries for provider-
backed IOC types (indicator, all applicable enrichments, all associated source names)
and two for email (indicator and sources), with no per-provider or per-source loop.
Latest provider selection is `enriched_at DESC, id DESC`.

Persistence uses a nested transaction/savepoint and flushes without committing the
caller's outer transaction. A pre-read permits fast reuse, while the PostgreSQL partial
unique index `uq_score_history_indicator_evidence` is the concurrency authority. Only
that exact uniqueness violation is treated as an idempotency race; the service then
re-queries and returns the existing immutable row. Other integrity failures are
re-raised. Components are reloaded with an explicit fixed-profile ordering rule.

### Terminal commands and expected/observed output

Focused orchestration and pure-engine tests:

```bash
pytest -q backend/tests/test_indicator_scoring_service.py
pytest -q backend/tests/test_scoring_engine.py
pytest -q backend/tests/test_phase6b_persistence.py
```

Expected and observed final output:

```text
47 passed in 1.42s
109 passed in 0.84s
19 passed in 0.95s
```

PostgreSQL was restricted by both environment variables to the safety-checked
`threatlens_phase6b_test` database. The repository was mounted read-only; only a
temporary log directory was writable and SELinux relabeled:

```bash
docker compose exec -T postgres dropdb --if-exists \
  -U threatlens threatlens_phase6b_test
docker compose exec -T postgres createdb \
  -U threatlens threatlens_phase6b_test
docker compose run --rm --no-deps -T --entrypoint sh -w /workspace \
  -v /home/adel/programming/osint_tool/Threat_Intelligence_Platform:/workspace:ro \
  -v /tmp/threatlens-phase6b-logs:/workspace/backend/logs:rw,z \
  -e DATABASE_URL=postgresql+psycopg://threatlens:threatlens@postgres:5432/threatlens_phase6b_test \
  -e PHASE6B_POSTGRES_URL=postgresql+psycopg://threatlens:threatlens@postgres:5432/threatlens_phase6b_test \
  api -c '/app/.venv/bin/python -m ensurepip --upgrade >/dev/null 2>&1 || true; \
  /app/.venv/bin/python -m pip install -q pytest; \
  PYTHONPATH=/workspace/backend /app/.venv/bin/python -m pytest -q \
  -p no:cacheprovider backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py'
```

Expected and observed final focused PostgreSQL output:

```text
...                                                                      [100%]
3 passed in 4.18s
```

This ran two real independent PostgreSQL sessions against the same snapshot. Both
callers returned the same score-history ID/hash, exactly one caller reported creation,
one history row and one email source component remained, no deadlock occurred, and
both unrelated caller-created articles survived.

Portable and PostgreSQL-enabled complete suites:

```bash
pytest -q
```

```text
304 passed, 3 skipped in 6.04s
```

The complete container command is the preceding Compose command with no test paths:

```bash
PYTHONPATH=/workspace/backend /app/.venv/bin/python -m pytest -q \
  -p no:cacheprovider
```

Expected and observed output:

```text
307 passed in 10.54s
```

Quality commands:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
ruff format --check \
  backend/app/scoring/evidence_snapshot.py \
  backend/app/services/indicator_scoring.py \
  backend/tests/test_indicator_scoring_service.py \
  backend/tests/test_indicator_scoring_postgres.py
mypy backend
python -m compileall -q backend/app backend/tests alembic/versions
git diff --check
```

Expected and observed significant output:

```text
All checks passed!
4 files already formatted
Success: no issues found in 82 source files
```

`compileall` and `git diff --check` produced no output and exited zero. The broader
format check reported `90 files already formatted` and only the unrelated pre-existing
`backend/app/ingestion/rss_client.py` as requiring formatting; it remains untouched.

### Problems encountered during verification

The first ephemeral-container attempt used its entrypoint/login-shell defaults, which
selected system Python and failed collection with `ModuleNotFoundError: pydantic`.
Using `/app/.venv/bin/python`, bypassing the entrypoint, and mounting the repository at
the actual working directory fixed the environment.

The first PostgreSQL rerun revealed that `alembic/env.py` replaces the URL supplied by
`Config.set_main_option()` with the already-loaded application `settings.database_url`.
Because the Compose service default was still present, its migration setup ran against
the local Compose development database while test queries used the disposable database;
the tests then failed with `relation "indicators" does not exist`. No production
database was involved. A later authoritative isolation-fix baseline, supplied by the
user and repeatedly verified read-only, is 60 raw articles, 456 indicators, 9,930
article-indicator links, zero indicator enrichments, and zero EPSS history rows. These
figures record current verified state only and do not establish the earlier incident's
data impact.

The existing migration lifecycle test initially failed after the scoring test because
the committed source-less email fixture correctly blocked downgrade of the canonical
indicator migration. The PostgreSQL scoring fixture now truncates only test rows from
the safety-checked disposable database during teardown. Running both test modules
together then passed. A complete-suite collection attempt also hit a permission error
for `/workspace/backend/logs/threatlens.log`; adding `,z` to the narrow temporary bind
mount fixed its SELinux label, after which all 307 tests passed.

The disposable `threatlens_phase6b_test` database was dropped after final verification.

## Phase 6B PostgreSQL isolation remediation — 2026-08-23

The exact root cause was the unconditional statement in `alembic/env.py`:

```python
config.set_main_option("sqlalchemy.url", settings.database_url)
```

It executed after programmatic callers had configured their Alembic `Config`, replacing
the intended disposable URL with the already-loaded Compose development URL. The fix
resolves URLs in this order: programmatic `Config.attributes` URL, `-x database_url`
CLI override, a non-placeholder `sqlalchemy.url`, then application settings fallback.
Percent signs are doubled only while stored in ConfigParser so URL-encoded passwords
round-trip without interpolation errors. Offline and online migrations consume the
same resolved value.

The shared PostgreSQL safety layer now:

* accepts only PostgreSQL database name `threatlens_phase6b_test` exactly;
* rejects missing/malformed URLs, SQLite, `threatlens`, `postgres`, templates, empty
  names, and unrelated `_test` databases before engine creation or Alembic calls;
* checks `SELECT current_database()` at DBAPI checkout and again immediately before
  every guarded Alembic operation, truncation, and cleanup;
* passes the expected database through Alembic Config so `env.py` checks the actual
  migration connection before running DDL;
* connects to exact administrative database `postgres`, verifies its identity, refuses
  a pre-existing disposable database, creates one exact database, and immediately adds
  a UUID ownership marker as its database comment;
* terminates connections and drops only the exact disposable name after both target
  identity and ownership marker match the current process;
* performs no fallback deletion if creation or cleanup fails.

An initial run of the new lifecycle created the exact disposable database but hit an
autobegin conflict before recording its first table marker. After explicit approval,
read-only checks showed the literal target, admin database `postgres`, no marker, zero
public tables, and zero user relations. Zero active connections were terminated and
only that literal database was dropped. Ownership marking was moved to an immediate
database comment. A later guarded migration attempt showed that the identity query's
read-only autobegin caused logged DDL to roll back; the guard now explicitly rolls back
that read-only transaction before Alembic begins its migration transaction. The owned
fixture cleaned up that failed disposable run itself.

Connection-free safety validation was run before any PostgreSQL integration test:

```bash
pytest -q \
  backend/tests/test_alembic_database_url.py \
  backend/tests/test_postgres_test_safety.py
ruff check \
  alembic/env.py \
  backend/app/database/alembic_runtime.py \
  backend/app/database/postgres_test_safety.py \
  backend/tests/conftest.py \
  backend/tests/test_alembic_database_url.py \
  backend/tests/test_postgres_test_safety.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
mypy \
  backend/app/database/alembic_runtime.py \
  backend/app/database/postgres_test_safety.py \
  backend/tests/conftest.py \
  backend/tests/test_alembic_database_url.py \
  backend/tests/test_postgres_test_safety.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
```

Expected and observed final output:

```text
24 passed in 0.07s
All checks passed!
Success: no issues found in 7 source files
```

Mocked sentinel tests prove a `threatlens` URL fails before engine creation or an
Alembic command, an exact test URL redirected to a connection reporting `threatlens`
fails before Alembic, an unrelated `_test` name fails the exact allowlist, missing and
malformed URLs fail closed, and an unowned/pre-existing database is not claimed.

Focused final tests:

```bash
pytest -q backend/tests/test_indicator_scoring_service.py
pytest -q backend/tests/test_scoring_engine.py
pytest -q backend/tests/test_phase6b_persistence.py
```

```text
47 passed in 1.54s
109 passed in 0.77s
19 passed in 1.01s
```

Focused PostgreSQL migration and concurrency tests were run in the read-only-mounted
Compose test container with both URLs naming only `threatlens_phase6b_test`. Database
creation and removal were performed exclusively by the session fixture:

```bash
python -m pytest -q -p no:cacheprovider \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
```

```text
3 passed in 3.51s
```

Complete suites:

```bash
pytest -q
python -m pytest -q -p no:cacheprovider  # owned PostgreSQL container
```

```text
328 passed, 3 skipped in 5.12s
331 passed in 14.49s
```

Final quality checks:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
ruff format --check \
  alembic/env.py \
  backend/app/database/alembic_runtime.py \
  backend/app/database/postgres_test_safety.py \
  backend/tests/conftest.py \
  backend/tests/test_alembic_database_url.py \
  backend/tests/test_postgres_test_safety.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
mypy backend
python -m compileall -q backend/app backend/tests alembic/versions
git diff --check
```

```text
All checks passed!
8 files already formatted
Success: no issues found in 86 source files
```

`compileall` and `git diff --check` exited zero without output. The repository-wide
format check still reports only the unrelated pre-existing
`backend/app/ingestion/rss_client.py`; it remains untouched.

Final development read-only verification before and after destructive disposable-only
tests was identical:

```text
current_database      = threatlens
raw_articles          = 60
indicators            = 456
article_indicators    = 9930
indicator_enrichments = 0
epss_history          = 0
```

After each successful PostgreSQL run, the ownership-validated fixture removed
`threatlens_phase6b_test`; final administrative inspection returned database count zero.
No backup, recovery, development-data mutation, staging, or commit was performed.

## Phase 6C indicator scoring REST API — 2026-08-28

Phase 6C adds only the synchronous indicator scoring API, explicit Pydantic response
contracts, a request-scoped SQLAlchemy dependency, stable safe API errors, focused
portable/PostgreSQL tests, and API documentation. No migration was required. The API
delegates evidence loading, Formula v1 calculation, canonical snapshot construction,
SHA-256 hashing, component persistence, savepoint handling, and concurrency resolution
unchanged to Phase 6B.

Endpoints:

```text
POST /api/v1/indicators/{indicator_id}/score?force_refresh=false
GET  /api/v1/indicators/{indicator_id}/score
GET  /api/v1/indicators/{indicator_id}/score/history?limit=20&offset=0
```

POST returns `200` with `{created, score}`. The endpoint owns one outer transaction,
constructs the response after the Phase 6B flush, commits once, and rolls back every
failure. The default supplies the latest persisted calculation time to Phase 6B so
unchanged stored evidence reproduces its canonical snapshot; evidence that postdates
that context is retried at current UTC. `force_refresh=true` uses current UTC through
the same orchestration entry point. It never calls enrichment providers or bypasses
canonical evidence uniqueness, so it can return `created: false`. Latest/history GETs
never score or write. Both order by
`calculated_at DESC, id DESC`; history bounds `limit` to 1–100 and counts in SQL.

Errors use `404 INDICATOR_NOT_FOUND`, `404 SCORE_NOT_FOUND`, and
`422 INDICATOR_UNSCORABLE`; normal FastAPI validation remains `422`, and unexpected
errors retain the sanitized centralized `500` response. Full canonical evidence and
raw enrichment responses are not exposed. Latest uses two SELECTs and history uses
four SELECTs independent of the number of score rows/components on the requested page.

Validation was run in the required order:

```bash
pytest -q backend/tests/test_indicator_score_schemas.py
pytest -q backend/tests/test_indicator_scores_api.py
pytest -q backend/tests/test_indicator_scores_api.py -k 'failure or integrity'
pytest -q backend/tests/test_indicator_scores_api.py -k 'latest or history'
pytest -q backend/tests/test_indicator_scores_api.py -k 'queries_are_constant'
pytest -q backend/tests/test_indicator_score_schemas.py backend/tests/test_indicator_scores_api.py
pytest -q backend/tests/test_indicator_scoring_service.py
pytest -q backend/tests/test_scoring_engine.py
pytest -q backend/tests/test_phase6b_persistence.py
```

Observed results were respectively 3 passed; 21 passed; 2 passed/19 deselected;
10 passed/11 deselected; 1 passed/20 deselected; 24 passed; 47 passed; 109 passed;
and 19 passed.

The guarded PostgreSQL runs used only `threatlens_phase6b_test` over Docker's internal
network. The focused run included the router transaction race, existing Phase 6B
orchestration race, and migration lifecycle:

```bash
docker compose run --rm --no-deps -T --entrypoint sh -w /workspace \
  -v "$PWD:/workspace:ro" \
  -v /tmp/threatlens-phase6c-logs:/workspace/backend/logs:rw,z \
  -e DATABASE_URL=postgresql+psycopg://threatlens:threatlens@postgres:5432/threatlens_phase6b_test \
  -e PHASE6B_POSTGRES_URL=postgresql+psycopg://threatlens:threatlens@postgres:5432/threatlens_phase6b_test \
  api -c 'PYTHONPATH=/workspace/backend /app/.venv/bin/python -m pytest -q \
  -p no:cacheprovider backend/tests/test_indicator_scores_api_postgres.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py'
```

Observed focused PostgreSQL result: 4 passed in 7.16s. The full suites were:

```bash
pytest -q
# same guarded disposable-container environment, then:
python -m pytest -q -p no:cacheprovider
```

Final observed results: 352 passed, 4 PostgreSQL-only skipped in 5.90s; then 356 passed
in 15.00s with PostgreSQL enabled. The first full container attempt stopped during
collection because its temporary log mount lacked SELinux relabeling; rerunning with
`:rw,z` passed. No application change was made for that environment-only failure.

Quality checks:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
ruff format --check <nine changed Python files>
black --check <each changed Python file>
mypy backend
python -m compileall -q backend/app backend/tests alembic/versions
git diff --check
```

Observed results: Ruff passed; Ruff reported all 9 files formatted; Black reported all
9 files unchanged; Mypy reported no issues in 91 source files; compileall and
`git diff --check` exited zero without output.

Read-only development counts before and after were identical:

```text
raw_articles          = 60
indicators            = 456
article_indicators    = 9930
indicator_enrichments = 0
epss_history          = 0
```

The owned disposable fixture removed `threatlens_phase6b_test` after each successful
run. Nothing was staged, committed, or pushed; `engineDElete.txt` and
`modelsDElete.txt` were not touched.

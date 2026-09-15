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











# Phase 7B — bounded CVE correlation backfill

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

## Phase 8 — correlated-event REST API — 2026-09-10

Implemented a typed, read-only FastAPI interface for persisted correlated events. It
does not invoke correlation/backfill, calculate scores, call providers, write rows, or
commit transactions. Existing schema and indexes were sufficient; no migration or
speculative index was added.

Endpoints:

```text
GET /api/v1/events
GET /api/v1/events/{event_id}
GET /api/v1/events/{event_id}/articles
GET /api/v1/events/{event_id}/indicators
```

Collections use `limit` 1–100 (default 20), non-negative `offset`, SQL totals, and
deterministic ordering. Events order by `updated_at DESC, id DESC`; articles by
`COALESCE(published_at, fetched_at) DESC, id DESC`; indicators by type, value, ID.
List filters are exact canonical uppercase `cve`, exact linked `source_name`, and
inclusive timezone-aware `updated_from`/`updated_to`. `EXISTS` filters prevent source
matches from duplicating events.

Latest persisted event/indicator scores use `calculated_at DESC, id DESC` window
ranking and expose only score, severity, formula version, and timestamp. Missing
scores are `null`. Raw article content, enrichment/provider responses, canonical
evidence, evidence hashes, and components are excluded. Stable errors are
`EVENT_NOT_FOUND`, `INVALID_CVE_FILTER`, and `INVALID_EVENT_FILTER`.

Files created or modified:

- `backend/app/api/v1/events.py`: thin read-only router and safe validation/errors.
- `backend/app/api/v1/router.py`: event-router registration.
- `backend/app/schemas/events.py`: typed UTC response/page contracts.
- `backend/app/services/event_queries.py`: bounded aggregate, filter, ordering, and
  latest-score queries.
- `backend/tests/test_event_schemas.py`: schema tests.
- `backend/tests/test_events_api.py`: portable API/filter/order/privacy/read-only/query
  tests.
- `backend/tests/test_events_api_postgres.py`: guarded PostgreSQL ordering, source
  de-duplication, and tied-score tests.
- `docs/architecture.md`: endpoint/query/error/read-only/deferred contracts.
- `Phase8_Correlated_Event_REST_API.md`: focused phase record.
- `notes.md`: this log.
- `Phase7B_CVE_Correlation_Backfill.md`: internal Phase 7B naming correction after
  external commit `0bf5e9a` appeared during this task.

Observed query counts are fixed: event list two SELECTs, detail one, articles two,
indicators two. Grouped counts, correlated `EXISTS`, and window-ranked scores avoid
N+1 queries.

Exact verification commands and observed results:

```bash
pytest -q backend/tests/test_event_schemas.py backend/tests/test_events_api.py
# 24 passed in 1.39s

pytest -q backend/tests/test_indicator_score_schemas.py backend/tests/test_indicator_scores_api.py
# 24 passed in 1.50s

pytest -q backend/tests/test_cve_correlation_service.py
# 14 passed in 0.75s

pytest -q backend/tests/test_cve_correlation_backfill.py
# 9 passed in 0.65s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_events_api_postgres.py
# 1 passed in 1.50s

pytest -q
# 399 passed, 7 skipped in 6.99s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 406 passed in 9.86s

ruff check backend/app backend/tests alembic/versions alembic/env.py
# All checks passed.

ruff format --check <seven Phase 8 Python files>
# 7 files already formatted.

black --check <each of those files, serially>
# Each would be left unchanged.

mypy backend
# Success: no issues found in 103 source files.

python -m compileall -q backend/app backend/tests alembic
# Exit 0, no output.

git diff --check
# Exit 0, no output.
```

The repository-wide Ruff format check reported 111 formatted files and only the known
unrelated `backend/app/ingestion/rss_client.py` as requiring formatting; it remained
untouched. The initial API query-count test had 20 passes and one failure because its
recorder included SQLite `BEGIN`; counting SELECTs per the Phase 6C convention fixed
the test. The focused suite then passed all 24 tests.

PostgreSQL isolation was preserved. Before and after testing, the exact fixture name
`threatlens_phase6b_test` was absent. Only the hardened fixture created, marked, and
removed it; no manual database cleanup ran. Read-only development transactions were
rolled back and returned identical observations:

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

Event-score calculation/persistence, score/severity filters, writes, authentication,
automatic correlation, dashboards, and non-CVE/fuzzy rules remain deferred. The next
recommended increment is a separately specified event-scoring workflow.

Summary: added four read-only event endpoints with typed safe responses, exact
filters, deterministic pagination, optional persisted-score summaries, and bounded
queries; final results were 399 passed/7 skipped portable and 406 passed PostgreSQL;
event scoring and score filtering remain unfinished. Nothing was staged, committed,
or pushed by Codex.
Final working diff: 11 files, 1,805 additions, and 11 deletions.

## Phase 9A — explainable event scoring and persistence — 2026-09-11

Phase 8 was verified as commit `4d6927b` before implementation, and initial `git status --short`
reported a clean tree. The final audit revealed pre-existing modifications to
`docs/architecture.md` and `notes.md` hidden by Git `assume-unchanged` flags. Only those two flags
were cleared, without staging; the earlier Phase 8 documentation was preserved and is consequently
included in the final visible diff. The Phase 6B models already contained event-target score history, component persistence, and
the partial unique index `uq_score_history_event_evidence`; therefore this increment required no
schema or migration change.

### What was implemented and why

Phase 9A implements deterministic scoring and append-only persistence for Phase 7 exact-CVE events.
It gives persisted correlated events an explainable priority score while retaining the existing
indicator score as the sole member-risk input:

```text
event score = latest persisted matching CVE indicator score * 0.90
            + min(max(distinct normalized sources - 1, 0), 4) / 4 * 10
```

The separate formula version is `phase9a-event-v1`. Decimal arithmetic is used throughout; the
combined result is clamped to `0.00..100.00`, rounded once with `ROUND_HALF_UP`, and classified by
the existing severity thresholds. For example, member score 80 with one source is 72.00, with two
sources is 74.50, and a missing member with three sources is 5.00. A missing member component is
recorded as missing with zero contribution and an explicit warning; it never triggers indicator
scoring or provider access.

Only `cve:<CANONICAL-UPPERCASE-CVE>` events with rule `shared-cve:v1` are supported. The loader
requires exactly one canonical CVE relationship matching the key. Typed errors distinguish a
missing event, unsupported rule/type, invalid key, missing relationship, ambiguous relationships,
inconsistent relationships, and invalid stored member-score evidence. The latest member indicator
score uses `target_kind='indicator'` and ordering `calculated_at DESC, id DESC`.

Source names are loaded through `event_articles`. Null/blank values do not count. The existing
normalizer trims, collapses internal whitespace, case-folds, de-duplicates, and sorts names, which
also makes evidence hashing deterministic.

The canonical snapshot contains event ID/key/rule, formula, canonical CVE ID/value, `as_of`, sorted
normalized sources, and either explicit member absence or its score-history identity, indicator
identity, score, severity, formula, evidence hash, and timestamp. It excludes final event output,
derived ratios/contributions, full member evidence documents, provider responses, secrets, and ORM
objects. Strict sorted compact UTF-8 JSON is SHA-256 hashed, and stored JSON is produced from those
same bytes. The derived-result serializer is explicitly documented as unsuitable for evidence
hashing.

Public service interface:

```python
calculate_and_persist_event_score(
    session: Session,
    event_id: int,
    *,
    as_of: datetime,
) -> PersistedEventScore
```

The result exposes the persisted `ScoreHistory`, ordered component rows, creation/reuse status, and
evidence hash. The service flushes but does not commit. Identical event/formula/hash evidence is
reused; a changed latest member, source set, or `as_of` context appends history. A savepoint handles
only the exact named event uniqueness race and re-queries the winner. Unrelated integrity errors
propagate, unrelated caller work remains in the outer transaction, and caller rollback removes all
new event-score rows/components.

### Files created or modified

- `backend/app/scoring/event_models.py`: immutable event evidence, member evidence, and result types.
- `backend/app/scoring/event_engine.py`: pure Event Formula v1 calculation, components, warnings,
  rounding/severity, and deterministic derived-result serialization.
- `backend/app/scoring/event_evidence_snapshot.py`: canonical evidence payload and SHA-256 hash.
- `backend/app/services/event_scoring.py`: invariant-aware evidence loading and append/reuse service.
- `backend/tests/test_event_scoring.py`: pure formula, source caps, normalization, severity boundaries,
  numeric/time validation, missing evidence, component order, and determinism.
- `backend/tests/test_event_scoring_service.py`: portable service, snapshot, idempotency, append,
  rollback, preservation, and typed-error coverage.
- `backend/tests/test_event_scoring_postgres.py`: guarded two-session uniqueness race and unrelated
  caller-work preservation.
- `backend/tests/test_events_api.py`: Phase 8 regression showing a persisted Phase 9A score through
  the existing read-only detail contract.
- `docs/architecture.md`: Event Formula v1, snapshot, transactions, concurrency, and boundaries.
- `Phase9A_Event_Scoring_and_Persistence.md`: focused implementation and verification record.
- `notes.md`: this dated development log.

### Problems encountered and resolutions

1. The first portable service run passed 24 tests and failed the caller-rollback assertion because
   Python's SQLite legacy mode does not begin a database transaction for SELECT before a savepoint.
   The test now establishes the caller-owned outer `BEGIN`, matching the repository's indicator
   persistence test. The next focused run passed all 25 tests then present; final split runs passed
   19 pure and 11 service tests.
2. One combined verification command used the nonexistent filename `backend/tests/test_scoring.py`.
   Pure and service tests in that command passed, then pytest exited 4 before indicator collection.
   The command was corrected to `test_scoring_engine.py`; 180 indicator-scoring tests passed.
3. The first sandboxed PostgreSQL attempt could not connect to local port 5433 and ended with one
   setup error. It was rerun through the approved local-access path; the guarded focused race passed.
4. The first combined PostgreSQL order ran indicator modules before the older bounded backfill
   module. Rows intentionally committed by those earlier modules entered that module's unscoped
   first page, so it reported one forecast instead of two: 7 tests passed and 1 failed. The same
   eight modules were rerun in repository isolation order and all 8 passed. No production or
   historical test was altered for this ordering-only interaction.
5. A multi-file Black check could not create its sandbox worker process (`PermissionError`) before
   formatting results. The identical eight file checks were executed serially; every file passed.
6. The repository-wide Ruff format check still reports the known unrelated
   `backend/app/ingestion/rss_client.py`; it was not modified.
7. Git initially hid `docs/architecture.md` and `notes.md` because both were marked
   `assume-unchanged`. The flags were cleared only for those paths so the required Phase 9A edits
   and the preserved earlier Phase 8 documentation will be visible to a future commit. Nothing was
   staged.

### Exact verification commands and observed results

Focused pure and service tests:

```bash
pytest -q backend/tests/test_event_scoring.py
# 19 passed in 0.33s

pytest -q backend/tests/test_event_scoring_service.py
# 11 passed in 0.66s
```

Existing behavior regressions:

```bash
pytest -q backend/tests/test_scoring_engine.py \
  backend/tests/test_indicator_scoring_service.py \
  backend/tests/test_indicator_score_schemas.py \
  backend/tests/test_indicator_scores_api.py
# 180 passed in 2.29s

pytest -q backend/tests/test_event_schemas.py backend/tests/test_events_api.py
# 25 passed in 1.49s

pytest -q backend/tests/test_cve_correlation_service.py \
  backend/tests/test_cve_correlation_backfill.py
# 23 passed in 0.87s
```

PostgreSQL tests used only the guarded environment variable below. The focused run passed 1 test;
the final combined run passed all 8 modules/tests:

```bash
PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_event_scoring_postgres.py
# 1 passed in 1.68s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_cve_correlation_backfill_postgres.py \
  backend/tests/test_cve_correlation_postgres.py \
  backend/tests/test_event_scoring_postgres.py \
  backend/tests/test_events_api_postgres.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_indicator_scores_api_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
# 8 passed in 4.39s
```

Final suites:

```bash
pytest -q
# 430 passed, 8 skipped in 7.81s

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 438 passed in 11.51s
```

The eight portable skips were the explicitly PostgreSQL-only tests. No final-suite test failed.

Quality checks:

```bash
ruff check backend/app backend/tests alembic/versions alembic/env.py
# All checks passed.

ruff format --check backend/app/scoring/event_models.py \
  backend/app/scoring/event_engine.py \
  backend/app/scoring/event_evidence_snapshot.py \
  backend/app/services/event_scoring.py \
  backend/tests/test_event_scoring.py \
  backend/tests/test_event_scoring_service.py \
  backend/tests/test_event_scoring_postgres.py \
  backend/tests/test_events_api.py
# 8 files already formatted.

# Black was run once per focused file to avoid sandbox multiprocessing.
black --check <each of the eight focused Python files, serially>
# Each file would be left unchanged.

mypy backend
# Success: no issues found in 110 source files.

python -m compileall -q backend/app backend/tests alembic
# Exit 0 with no output.

git diff --check
# Exit 0 with no output.

ruff format --check backend/app backend/tests alembic/versions alembic/env.py
# 118 files already formatted; only known unrelated rss_client.py would be reformatted.
```

### PostgreSQL isolation and development preservation

Administrative exact-name checks before and after validation both returned zero databases named
`threatlens_phase6b_test`. Each pytest invocation let `OwnedDisposablePostgres` create the exact
database, attach its per-run ownership marker, verify it on every guarded connection, and delete it
through ownership-validated cleanup. No manual create, drop, truncate, schema cleanup, wildcard,
volume, or fallback deletion was performed.

Read-only development transactions before and after validation returned identical observations:

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

Both transactions ended with `ROLLBACK`. The development database was not used for tests and was
not mutated.

### Remaining work and concise summary

Event-score write/read endpoints, event score filters, CLI/backfill scoring, tasks/schedules,
automatic triggers, provider access, non-CVE aggregation, fuzzy/campaign scoring, analyst
overrides, authentication, dashboards, and notifications remain unfinished. The next recommended
increment is a separately specified event-scoring API or bounded backfill, without combining the
two concerns.

Summary: Phase 9A added pure `phase9a-event-v1` calculation, canonical evidence hashing,
transaction-safe append/reuse persistence, typed exact-CVE invariants, API-read regression, and a
real two-session PostgreSQL race test. Final results were 430 passed/8 skipped portable and 438
passed with PostgreSQL; development counts were identical before/after, no schema changed, and no
work was staged, committed, or pushed. Event scoring automation and write APIs remain deferred.
The final diff includes the surfaced earlier documentation plus Phase 9A.
Final working diff: 11 files, 1,932 additions, and 1 deletion.

## Phase 9B — Event Scoring REST API — 2026-09-11

Phase 9A's pure engine, evidence snapshot, persistence service, and focused tests were confirmed in
commit `1e592e9`. The initial tree was not clean: the Phase 9A API regression in
`backend/tests/test_events_api.py`, both documentation files, and the untracked
`Phase9A_Event_Scoring_and_Persistence.md` remained. They were preserved. No schema gap was found,
so Phase 9B adds no migration or model change.

### Implementation and public contracts

Phase 9B adds:

```text
POST /api/v1/events/{event_id}/score?force_refresh=false
GET  /api/v1/events/{event_id}/score
GET  /api/v1/events/{event_id}/score/history?limit=20&offset=0
```

POST calls only `calculate_and_persist_event_score`. It builds the complete typed response before
committing exactly once; every expected or unexpected failure rolls back. Phase 9A still owns all
evidence loading, formula calculation, canonical hashing, append/reuse persistence, and exact
uniqueness-race handling.

Default POST reuses the latest persisted event score's `calculated_at` as `as_of`, normalized to
UTC; without a prior score it uses current UTC. A genuinely invalid reusable context retries once
at current UTC through the same service. `force_refresh=true` uses current UTC immediately. Neither
flag bypasses hashing: identical evidence plus identical context returns `created=false`. Neither
mode runs correlation/backfill, indicator scoring, enrichment, provider clients, or network calls.

Latest/history filter `target_kind='event'`, the requested event ID, and `indicator_id IS NULL`,
ordered by `calculated_at DESC, id DESC`. History enforces limit 1–100, offset >=0, and SQL total.
Latest uses two SELECTs and history three, independent of page/component size.

`EventScoreResponse` contains score-history ID, event ID/key/title, score, severity, formula,
evidence hash, UTC `as_of`/calculation timestamps, and fixed-profile components. The POST wrapper
adds `created`; history adds event ID, page fields, and total. Components expose only safe formula
input, normalized input, weight, contribution, freshness, status, optional provider/timestamp, and
explanation. Member status comes from the safe snapshot state, including explicit `missing`.
Canonical evidence, raw enrichment/provider data, credentials, and internal errors are excluded.

Stable API errors are `404 EVENT_NOT_FOUND`, `404 EVENT_SCORE_NOT_FOUND`, and
`422 EVENT_UNSCORABLE`. Unsupported/invalid keys or rules, missing/ambiguous/inconsistent CVE
relationships, invalid member-score evidence, and typed scoring inputs map to the safe unscorable
message. Unexpected failures retain the centralized sanitized 500 response.

### Files created or modified and purpose

- `backend/app/schemas/event_scores.py`: event-specific Pydantic score/component/POST/history models.
- `backend/app/services/event_score_queries.py`: safe latest/history SQL, UTC reusable context,
  deterministic component ordering/status, and response mapping.
- `backend/app/api/v1/event_scores.py`: thin transaction and error-mapping router.
- `backend/app/api/v1/router.py`: registers the new routes before existing Phase 8 event routes.
- `backend/tests/test_event_score_schemas.py`: schema, Decimal, UTC, hash, exclusion, and bounds tests.
- `backend/tests/test_event_scores_api.py`: portable endpoint, force/reuse, transaction, error,
  ordering, pagination, safety, query-count, OpenAPI, route, and boundary tests.
- `backend/tests/test_event_scores_api_postgres.py`: concurrent real-API PostgreSQL uniqueness race.
- `docs/architecture.md`: Phase 9B API, transactions, errors, queries, safety, and deferred scope.
- `Phase9B_Event_Scoring_REST_API.md`: focused phase implementation and verification record.
- `notes.md`: this appended development log.

The pre-existing Phase 9A changes listed above remain visible in the final working tree.

### Problems encountered and resolutions

1. The first full API run produced 9 passes and 4 failures. SQLite returned the prior score time
   without timezone metadata, tracking counters incremented a sessionmaker subclass, and default
   `CorrelatedEvent` select-in relationships expanded latest reads to six queries. The reusable time
   is now normalized to UTC, counters target the base tracking session, and relationship loading is
   explicitly suppressed. The final counts are two SELECTs for latest and three for history.
2. Two combined schema/API invocations stalled while transitioning modules in the command runner
   and were manually interrupted without reported test failures. The modules ran independently and
   passed 4 and 13 tests in final focused runs.
3. Ruff reported initial import-order findings in the new router/test modules. Imports were corrected
   before the final lint run.
4. The known repository-wide formatting difference in `backend/app/ingestion/rss_client.py` remains
   untouched.

### Exact verification commands and observed results

```bash
pytest -q backend/tests/test_event_score_schemas.py
# 4 passed in 0.34s

pytest -q backend/tests/test_event_scores_api.py
# 13 passed in 1.37s

pytest -q <four explicit Phase 9B failure/rollback tests>
# 4 passed in 0.90s

pytest -q <three explicit Phase 9B latest/history tests>
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
  pytest -q backend/tests/test_cve_correlation_backfill_postgres.py \
  backend/tests/test_cve_correlation_postgres.py \
  backend/tests/test_event_scores_api_postgres.py \
  backend/tests/test_event_scoring_postgres.py \
  backend/tests/test_events_api_postgres.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_indicator_scores_api_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
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
# Exit 0 before documentation append; repeated after the final diff.

ruff format --check backend/app backend/tests alembic/versions alembic/env.py
# 124 files already formatted; only the known unrelated rss_client.py would be reformatted.
```

The two interrupted combined runs and the initial 9-pass/4-failure development run are not claimed
as passing checks. All final focused and full-suite results above were observed directly.

### PostgreSQL isolation and development database

Administrative exact-name queries before and after returned zero databases named
`threatlens_phase6b_test`. Only `OwnedDisposablePostgres` created and marked that exact database,
validated ownership, and removed it through guarded cleanup. No manual create, drop, truncate,
rename, schema cleanup, wildcard, fallback deletion, or volume operation occurred.

Read-only development transactions before and after PostgreSQL validation both returned:

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

Both ended with rollback. Development data was neither tested against nor changed during the
validation window.

### Remaining limitations and summary

Event-score list filtering, scoring CLI/backfill, automatic scoring, Celery tasks/schedules,
correlation changes, indicator-formula changes, provider calls, non-CVE/campaign scoring,
authentication, dashboards, reports, and notifications remain deferred.

Summary: Phase 9B adds typed POST/latest/history event-score endpoints, safe deterministic
components, reusable/forced calculation contexts, one-commit transaction ownership, stable errors,
bounded reads, OpenAPI/route verification, and a real concurrent PostgreSQL POST test. Final suites
passed 447 tests with 9 PostgreSQL-only skips portably and all 456 tests with PostgreSQL. No schema,
correlation, indicator scoring, enrichment, or development data changed; nothing was staged,
committed, or pushed.
Final visible working diff (including preserved Phase 9A leftovers): 12 files, 2,538 additions,
and 1 deletion.

## Phase 9C — Bounded Dry-Run/Apply Event-Scoring Backfill — 2026-09-15

### What was implemented and why

Phase 9C adds one bounded operator-controlled page around the existing Phase 9A event-score service.
The command defaults to a rollback-only dry-run and requires `--apply` before it can commit. It
selects exact-CVE-family candidates in ascending event ID order, supports `--limit` and
`--after-id`, forecasts the resulting score and score-history create/reuse decision, and reports
unsupported, malformed, and unscorable candidates separately.

The implementation intentionally calls `calculate_and_persist_event_score` for every scoreable
candidate in both modes. Dry-run calls it inside a savepoint and rolls that savepoint back after
capturing immutable scalar results. Apply leaves all rows for the bounded page in the caller-owned
transaction; the CLI performs one commit only after the page completes. Unexpected failures abort
and roll back the entire page. The backfill contains no formula, canonical snapshot, component,
hashing, or uniqueness implementation of its own.

Repeated calls use the latest persisted event score's calculation time as the reusable `as_of`
context. This prevents the invocation clock alone from creating a new canonical snapshot. Changed
member/source evidence still changes the Phase 9A snapshot, while concurrent identical calls rely
on the existing event/formula/evidence-hash uniqueness constraint and narrow conflict recovery.

Candidate selection includes a `cve:` key or `shared-cve` rule. This is broad enough to surface and
count malformed or unsupported historical exact-CVE candidates but excludes unrelated campaign
events. Bounds are limit 1–1000 and non-negative `after_id`. The service reads `limit + 1` IDs only
to calculate `has_more`, returns no more than the requested limit, and never commits.

No correlation, indicator score calculation, enrichment, provider/network client, API, automatic
hook, task, schedule, deletion, merge, repair, model, migration, or schema change was added.

### Files created or modified and purpose

- `backend/app/services/event_scoring_backfill.py`: bounded service, immutable result contracts,
  ordered candidate query, typed classification, rollback-only dry-run, single-page CLI, bounds,
  JSON output, and atomic transaction boundary.
- `backend/tests/test_event_scoring_backfill.py`: ten portable tests for create/reuse forecasts,
  no durable dry-run writes, exact numeric output, ascending bounded paging, cursor behavior,
  classifications, unrelated exclusion, repeated idempotency, caller rollback, default/explicit CLI
  modes, unsafe bounds, unexpected-error rollback, and prohibited service calls.
- `backend/tests/test_event_scoring_backfill_postgres.py`: one protected integration test for dry-run
  and two simultaneous apply sessions, including one score row, unique components, reuse, and
  preservation of unrelated caller inserts.
- `docs/architecture.md`: appended Phase 9C service, selection, transaction, idempotency, result, and
  scope contracts without reorganizing the existing document.
- `Phase9C_Event_Scoring_Backfill.md`: focused implementation/operator guide explaining every file,
  interface, CLI use, actual verification, database safety, and deferred work.
- `notes.md`: this append-only development record.

The previously modified `docs/architecture.md`/`notes.md` and untracked Phase 9A/9B guide files were
already present at task start and were preserved. Phase 9C did not modify any Phase 9A/9B API,
formula, persistence, database model, migration, ingestion, or provider file.

### Service and CLI behavior

```text
backfill_event_scores(session, *, apply, limit=100, after_id=0, as_of)
    -> EventScoreBackfillResult

PYTHONPATH=backend python -m app.services.event_scoring_backfill
PYTHONPATH=backend python -m app.services.event_scoring_backfill --dry-run --limit 100 --after-id 0
PYTHONPATH=backend python -m app.services.event_scoring_backfill --apply --limit 100 --after-id 0
```

The result includes mode, requested bounds, scanned/scoreable/classification counts, first and last
scanned IDs, continuation state, create/reuse forecast and applied counts, and ordered item details.
Scoreable items contain the score, severity, formula version, and evidence hash returned by the
existing orchestration. Dry-run never commits; apply commits exactly one successfully completed
page. Operators must deliberately invoke the next page using the returned cursor.

### Problems encountered and resolutions

1. An initial focused regression command named a nonexistent `test_cve_correlation.py`; pytest
   stopped before collection. The verified filename is `test_cve_correlation_service.py`, and the
   corrected focused command passed 105 tests.
2. Two combined PostgreSQL attempts inside the restricted sandbox produced ten setup errors each
   because psycopg could not connect to the local administrative database. The container itself was
   healthy and accepting connections. The identical command was rerun with approved local database
   access and all ten tests passed. These setup errors are recorded, not presented as product test
   failures or passing checks.
3. Black's multi-file check first failed because its multiprocessing listener is prohibited by the
   sandbox. A serial check then showed one nested conditional formatting difference from Ruff. The
   outcome selection was rewritten as a clear `if/else`, after which both formatters passed the
   focused files.
4. The repository-wide Ruff format check still identifies the known unrelated
   `backend/app/ingestion/rss_client.py`. It was not changed.

### Exact verification commands and observed results

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
  pytest -q backend/tests/test_cve_correlation_backfill_postgres.py \
  backend/tests/test_cve_correlation_postgres.py \
  backend/tests/test_event_scores_api_postgres.py \
  backend/tests/test_event_scoring_backfill_postgres.py \
  backend/tests/test_event_scoring_postgres.py \
  backend/tests/test_events_api_postgres.py \
  backend/tests/test_indicator_scoring_postgres.py \
  backend/tests/test_indicator_scores_api_postgres.py \
  backend/tests/test_phase6b_postgres_migration.py
# 10 passed in 4.20s with approved local PostgreSQL access.

pytest -q
# 457 passed, 10 skipped in 9.39s.
# The skipped items are the environment-gated PostgreSQL tests.

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q
# 467 passed in 13.27s.

ruff check .
# All checks passed.

ruff format --check backend/app/services/event_scoring_backfill.py \
  backend/tests/test_event_scoring_backfill.py \
  backend/tests/test_event_scoring_backfill_postgres.py
# 3 files already formatted before the small conditional refactor; repeated below after all edits.

black --check --no-cache <each of the three Phase 9C Python files separately>
# Two files initially passed; the service reported one conditional layout difference.
# The conditional was refactored and the final serial check is recorded below.

mypy backend
# Success: no issues found in 119 source files.

python -m compileall -q backend
# Exit 0 with no output.

ruff format --check .
# 128 files already formatted; only unrelated backend/app/ingestion/rss_client.py would reformat.
```

Observed non-passing setup/check attempts are deliberately included above and are not counted as
passes. Final post-documentation focused tests, format checks, CLI help, `git diff --check`, and diff
summary are appended to the end of this section after they are run.

### PostgreSQL isolation and development-database checks

An administrative exact-name query returned zero databases named `threatlens_phase6b_test` before
the PostgreSQL runs. Each successful test invocation used only `OwnedDisposablePostgres`, which
created the exact disposable database, stored and validated its ownership marker, and removed it
through guarded cleanup. No manual create/drop/truncate/rename/schema cleanup, wildcard, fallback
deletion, or volume operation was performed. The exact-name query returned zero after validation.

Read-only development transactions before and after successful PostgreSQL validation observed
identical values:

```text
current_database      = threatlens
raw_articles          = 246
indicators            = 1223
article_indicators    = 37451
indicator_enrichments = 144
epss_history          = 256
correlated_events     = 0
event_articles        = 0
event_indicators      = 0
score_history         = 1
```

Both checks ended in `ROLLBACK`. The development database was not selected as a test target and was
not mutated by Phase 9C validation.

### Remaining work and next recommended increment

Phase 9C intentionally leaves scheduling/Celery, an API trigger, automatic hooks, event-list score
filters, non-CVE or campaign scoring, indicator-score refresh, correlation, enrichment, provider
access, dashboards, reports, authentication, and notifications unfinished. A future increment can
add an explicitly scheduled operator workflow around this bounded command without changing its
one-page transaction contract.

### Final post-documentation verification

```bash
pytest -q backend/tests/test_event_scoring_backfill.py
# 10 passed in 0.89s.

PHASE6B_POSTGRES_URL='postgresql+psycopg://threatlens:threatlens@127.0.0.1:5433/threatlens_phase6b_test' \
  pytest -q backend/tests/test_event_scoring_backfill_postgres.py
# 1 passed in 1.32s.

ruff check .
# All checks passed.

ruff format --check <the three Phase 9C Python files>
# 3 files already formatted.

black --check --no-cache <each Phase 9C Python file separately>
# Each of the 3 files would be left unchanged.

mypy backend
# Success: no issues found in 119 source files.

python -m compileall -q backend
# Exit 0 with no output.

PYTHONPATH=backend python -m app.services.event_scoring_backfill --help
# Exit 0; help showed dry-run/apply, limit, and after-id options.

git diff --check
# Exit 0 with no output before this final notes append; repeated afterward.
```

The final PostgreSQL cleanup query again returned zero exact databases named
`threatlens_phase6b_test`. The final read-only development query returned the same counts documented
above and rolled back.

Final visible working tree: 8 modified/untracked files, 2,448 additions, and 1 deletion, including
the preserved earlier Phase 9A/9B documentation. No file is staged.

Summary: Phase 9C adds a default-safe dry-run and explicit-apply exact-CVE event-score backfill,
bounded ascending cursor pages, exact create/reuse forecasts, separate data-quality counts, atomic
caller-owned persistence, and protected concurrent PostgreSQL coverage. Focused tests passed 10
portable and 1 PostgreSQL test; regression/full runs passed 105, 457 portable, and 467 with
PostgreSQL. No schema, correlation, indicator scoring, enrichment, network path, or development data
changed. Scheduling and non-CVE scoring remain unfinished; nothing was staged, committed, or pushed.

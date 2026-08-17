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

# Problems Found

## 1) Enrichment extraction tests are failing (5 failures)
- **Evidence:** `pytest -q` fails in `backend/tests/test_enrichment.py` for CVE, IPv4, URL, email, and SHA256 extraction.
- **Cause:** The enrichment implementation is still placeholder code:
  - `backend/app/enrichment/extractor.py` returns `[]` for all extractors.
  - `backend/app/enrichment/regex.py` sets all patterns to `None`.
  - This guarantees no indicator is ever extracted, so expected test values are never returned.

## 2) Type checking fails (`mypy backend` has 10 errors)
- **Evidence:** `mypy backend` reports errors in `normalizer.py`, `exceptions.py`, `scheduler.py`, `celery_app.py`, and `test_ingestion.py`.
- **Cause:**
  - `feedparser` and `celery` are untyped third-party packages, and current mypy settings do not ignore missing stubs (`import-untyped` errors).
  - `backend/app/ingestion/normalizer.py` builds `categories` through optional text normalization, so inferred type becomes `list[str | None]` while `NormalizedArticle.categories` expects `list[str]`.
  - `backend/app/core/exceptions.py` registers a handler typed with `fastapi.exceptions.HTTPException`, which mismatches the expected Starlette exception handler signature.
  - `backend/tests/test_ingestion.py` contains test functions without full type annotations while `disallow_untyped_defs = true` is enabled.
  - `IngestionService` currently requires `rss_client: RSSClient | None`; tests inject `FakeClient`, causing a concrete-type mismatch instead of using a protocol/base interface.

## 3) Linting fails (`ruff check .` has 22 errors)
- **Evidence:** Ruff reports `E402`, `I001`, and `F401` across Alembic files, ingestion modules, tests, and `scripts/celery_wrapper.py`.
- **Cause:**
  - Multiple files have unsorted imports (`I001`) and unused imports (`F401`).
  - `E402` appears where path mutation is done before later imports (e.g., `alembic/env.py`, `scripts/celery_wrapper.py`), which violates module-import-at-top rules.

## 4) Formatting/import style checks fail
- **Evidence:**
  - `black --check .` reports **14 files** would be reformatted.
  - `isort --check-only .` reports import-order violations in multiple files.
- **Cause:** Current code style in several files does not match the configured Black + isort formatting rules in `pyproject.toml`.

## 5) Deprecation warnings during tests
- **Evidence:** Pytest warnings include:
  - Starlette `TestClient` deprecation path around httpx usage.
  - SQLAlchemy warning due `datetime.utcnow()` defaults.
- **Cause:**
  - Dependency/API version behavior around test client internals.
  - Model defaults in `backend/app/ingestion/models.py` use `datetime.utcnow`, which is being deprecated in newer Python runtime guidance.

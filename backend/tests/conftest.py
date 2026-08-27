from __future__ import annotations

import os
from collections.abc import Generator

import pytest

from app.core.config import settings
from app.database.postgres_test_safety import (
    OwnedDisposablePostgres,
    UnsafePostgresTestTarget,
)


@pytest.fixture(autouse=True)
def disable_runtime_enrichment_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests isolated from the real Celery broker and provider configuration."""

    monkeypatch.setattr(settings, "enrichment_enabled", False)


@pytest.fixture(scope="session")
def phase6b_postgres_database() -> Generator[OwnedDisposablePostgres, None, None]:
    raw_url = os.getenv("PHASE6B_POSTGRES_URL")
    if not raw_url:
        pytest.skip("PHASE6B_POSTGRES_URL is not configured; PostgreSQL tests are disabled")
    try:
        owned = OwnedDisposablePostgres.create(raw_url)
    except UnsafePostgresTestTarget as exc:
        pytest.fail(str(exc), pytrace=False)
    try:
        yield owned
    finally:
        owned.drop()

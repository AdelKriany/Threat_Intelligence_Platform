from __future__ import annotations

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def disable_runtime_enrichment_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests isolated from the real Celery broker and provider configuration."""

    monkeypatch.setattr(settings, "enrichment_enabled", False)

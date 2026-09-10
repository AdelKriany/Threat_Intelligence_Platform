from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.schemas.events import (
    EventListResponse,
    EventSummaryResponse,
    PersistedScoreSummary,
)
from app.scoring.models import Severity

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


def _event() -> EventSummaryResponse:
    return EventSummaryResponse(
        id=1,
        event_key="cve:CVE-2026-82001",
        title="CVE-2026-82001 vulnerability",
        rule_name="shared-cve",
        rule_version="v1",
        created_at=datetime(2026, 9, 10, 12),
        updated_at=NOW,
        article_count=2,
        indicator_count=1,
        latest_score=PersistedScoreSummary(
            score=Decimal("87.40"),
            severity=Severity.CRITICAL,
            formula_version="event-v1",
            calculated_at=NOW,
        ),
    )


def test_event_schema_serializes_scores_and_utc_timestamps() -> None:
    payload = _event().model_dump(mode="json")

    assert payload["created_at"] == "2026-09-10T12:00:00Z"
    assert payload["latest_score"]["score"] == 87.4
    assert payload["latest_score"]["severity"] == "critical"


def test_event_list_schema_enforces_pagination_bounds() -> None:
    with pytest.raises(ValidationError):
        EventListResponse(items=[_event()], limit=101, offset=0, total=1)
    with pytest.raises(ValidationError):
        EventListResponse(items=[_event()], limit=20, offset=-1, total=1)


def test_event_schema_forbids_evidence_payloads() -> None:
    payload = _event().model_dump()
    payload["canonical_evidence"] = {"secret": True}

    with pytest.raises(ValidationError):
        EventSummaryResponse.model_validate(payload)

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.schemas.event_scores import (
    EventScoreComponentResponse,
    EventScoreHistoryResponse,
    EventScoreResponse,
)
from app.scoring.models import EvidenceStatus, Severity

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)


def _component() -> EventScoreComponentResponse:
    return EventScoreComponentResponse(
        name="member_indicator_score",
        raw_input={"score": "80.00"},
        normalized_value="0.8",
        weight=Decimal("90.000000"),
        contribution=Decimal("72.000000"),
        freshness_multiplier=Decimal("1.000000"),
        status=EvidenceStatus.USABLE,
        provider=None,
        evidence_at=NOW,
        explanation="Latest persisted matching CVE score contributes 90%",
    )


def test_event_score_schema_serializes_safe_decimals_enums_and_utc() -> None:
    score = EventScoreResponse(
        id=9,
        event_id=4,
        event_key="cve:CVE-2026-94001",
        event_title="CVE-2026-94001 vulnerability",
        score=Decimal("74.50"),
        severity=Severity.HIGH,
        formula_version="phase9a-event-v1",
        evidence_hash="a" * 64,
        as_of=NOW,
        calculated_at=NOW,
        components=[_component()],
    )

    payload = score.model_dump(mode="json")
    assert payload["score"] == 74.5
    assert payload["severity"] == "high"
    assert payload["as_of"] == "2026-09-11T12:00:00Z"
    assert payload["components"][0]["contribution"] == 72.0
    assert "canonical_evidence" not in payload


def test_event_score_schema_normalizes_naive_database_timestamps_as_utc() -> None:
    component = _component().model_copy(update={"evidence_at": datetime(2026, 9, 11, 12)})
    validated = EventScoreComponentResponse.model_validate(component.model_dump())
    assert validated.evidence_at is not None
    assert validated.evidence_at.utcoffset() is not None


def test_event_score_schema_rejects_extra_fields_and_bad_hashes() -> None:
    with pytest.raises(ValidationError):
        EventScoreResponse(
            id=1,
            event_id=1,
            event_key="cve:CVE-2026-94002",
            event_title="CVE-2026-94002 vulnerability",
            score=Decimal("1"),
            severity=Severity.LOW,
            formula_version="phase9a-event-v1",
            evidence_hash="not-a-hash",
            as_of=NOW,
            calculated_at=NOW,
            components=[],
            canonical_evidence={},  # type: ignore[call-arg]
        )


def test_event_score_history_schema_enforces_pagination_bounds() -> None:
    with pytest.raises(ValidationError):
        EventScoreHistoryResponse(event_id=1, items=[], limit=101, offset=0, total=0)

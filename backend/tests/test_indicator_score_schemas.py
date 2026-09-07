from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.ingestion.models import IOCType
from app.schemas.indicator_scores import (
    IndicatorScoreHistoryResponse,
    IndicatorScoreResponse,
    ScoreComponentResponse,
)
from app.scoring.models import EvidenceStatus, Severity

NOW = datetime(2026, 8, 28, 12, tzinfo=UTC)


def _component() -> ScoreComponentResponse:
    return ScoreComponentResponse(
        name="nvd_cvss",
        raw_input={"cvss_base_score": "9.8"},
        normalized_value="0.98",
        weight=Decimal("40.000000"),
        contribution=Decimal("39.200000"),
        freshness_multiplier=Decimal("1.000000"),
        status=EvidenceStatus.USABLE,
        provider="nvd",
        evidence_at=NOW,
        explanation="Exact Formula v1 contribution",
    )


def test_score_schema_serializes_decimals_enums_and_utc_timestamps() -> None:
    score = IndicatorScoreResponse(
        id=456,
        indicator_id=123,
        indicator_type=IOCType.CVE,
        indicator_value="CVE-2026-12345",
        score=Decimal("87.40"),
        severity=Severity.CRITICAL,
        formula_version="phase6b-v1",
        evidence_hash="a" * 64,
        as_of=NOW,
        calculated_at=NOW,
        components=[_component()],
    )

    payload = score.model_dump(mode="json")

    assert payload["score"] == 87.4
    assert payload["severity"] == "critical"
    assert payload["indicator_type"] == "cve"
    assert payload["as_of"] == "2026-08-28T12:00:00Z"
    assert payload["components"][0]["status"] == "usable"
    assert payload["components"][0]["contribution"] == 39.2


def test_score_schema_treats_naive_database_timestamps_as_utc() -> None:
    component = _component().model_copy(update={"evidence_at": datetime(2026, 8, 28, 12)})
    validated = ScoreComponentResponse.model_validate(component.model_dump())

    assert validated.evidence_at is not None
    assert validated.evidence_at.utcoffset() is not None


def test_history_schema_enforces_bounded_pagination() -> None:
    with pytest.raises(ValidationError):
        IndicatorScoreHistoryResponse(
            indicator_id=1,
            items=[],
            limit=101,
            offset=0,
            total=0,
        )

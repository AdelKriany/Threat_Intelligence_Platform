from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from app.scoring.event_engine import (
    EVENT_FORMULA_VERSION,
    calculate_event_score,
    canonical_serialize_event_result,
)
from app.scoring.event_models import EventScoringEvidence, MemberIndicatorScoreEvidence
from app.scoring.models import EvidenceStatus, ScoringInputError, Severity

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


def _member(score: str = "80") -> MemberIndicatorScoreEvidence:
    return MemberIndicatorScoreEvidence(
        score_history_id=4,
        indicator_id=2,
        score=Decimal(score),
        severity=Severity.CRITICAL,
        formula_version="phase6b-v1",
        evidence_hash="a" * 64,
        calculated_at=NOW,
    )


def _evidence(
    *, member: MemberIndicatorScoreEvidence | None = None, sources: tuple[str, ...] = ()
) -> EventScoringEvidence:
    return EventScoringEvidence(
        event_id=1,
        event_key="cve:CVE-2026-90001",
        rule_name="shared-cve",
        rule_version="v1",
        cve_indicator_id=2,
        canonical_cve="CVE-2026-90001",
        as_of=NOW,
        member_score=member,
        source_names=sources,
    )


def test_member_score_contributes_ninety_percent() -> None:
    result = calculate_event_score(_evidence(member=_member("80")))

    assert result.formula_version == EVENT_FORMULA_VERSION == "phase9a-event-v1"
    assert result.final_score == Decimal("72.00")
    assert result.components[0].name == "member_indicator_score"
    assert result.components[0].normalized_value == Decimal("0.8")
    assert result.components[0].weight == Decimal("90")
    assert result.components[0].contribution == Decimal("72.0")


@pytest.mark.parametrize(
    ("count", "expected"),
    [(0, "0.00"), (1, "0.00"), (2, "2.50"), (3, "5.00"), (4, "7.50"), (5, "10.00"), (8, "10.00")],
)
def test_source_corroboration_cap(count: int, expected: str) -> None:
    sources = tuple(f"Source {position}" for position in range(count))
    result = calculate_event_score(_evidence(sources=sources))

    assert result.final_score == Decimal(expected)
    assert result.components[1].raw_input == (("count", count),)
    assert result.components[1].contribution == Decimal(expected)


def test_source_normalization_is_trimmed_casefolded_deduplicated_and_sorted() -> None:
    result = calculate_event_score(
        _evidence(sources=(" Source B ", "source   a", "SOURCE A", "", "source b"))
    )

    assert result.normalized_source_names == ("source a", "source b")
    assert result.final_score == Decimal("2.50")


def test_missing_member_allows_source_only_score_and_warning() -> None:
    result = calculate_event_score(_evidence(sources=("a", "b", "c")))

    assert result.final_score == Decimal("5.00")
    assert result.components[0].status is EvidenceStatus.MISSING
    assert result.components[0].contribution == Decimal("0")
    assert result.warnings == ("member_indicator_score_missing",)


def test_rounds_once_half_up_and_uses_existing_severity_boundaries() -> None:
    result = calculate_event_score(_evidence(member=_member("27.775")))

    assert result.final_score == Decimal("25.00")
    assert result.severity is Severity.MEDIUM


@pytest.mark.parametrize(
    ("member_score", "expected_score", "expected_severity"),
    [
        ("0", "0.00", Severity.NONE),
        ("1", "0.90", Severity.LOW),
        ("27.773", "25.00", Severity.MEDIUM),
        ("55.55", "50.00", Severity.HIGH),
        ("83.33", "75.00", Severity.CRITICAL),
    ],
)
def test_event_score_uses_existing_severity_boundaries(
    member_score: str,
    expected_score: str,
    expected_severity: Severity,
) -> None:
    result = calculate_event_score(_evidence(member=_member(member_score)))
    assert result.final_score == Decimal(expected_score)
    assert result.severity is expected_severity


def test_maximum_is_clamped_to_one_hundred() -> None:
    result = calculate_event_score(_evidence(member=_member("100"), sources=tuple("abcdef")))
    assert result.final_score == Decimal("100.00")
    assert result.severity is Severity.CRITICAL


def test_component_order_and_result_serialization_are_deterministic() -> None:
    result = calculate_event_score(_evidence(member=_member(), sources=("B", "A")))
    assert tuple(item.name for item in result.components) == (
        "member_indicator_score",
        "independent_sources",
    )
    assert canonical_serialize_event_result(result) == canonical_serialize_event_result(result)


def test_timezone_and_numeric_validation() -> None:
    with pytest.raises(ScoringInputError, match="timezone-aware"):
        replace(_evidence(), as_of=datetime(2026, 9, 10, 12))
    with pytest.raises(ScoringInputError, match="finite Decimal"):
        _member("NaN")
    with pytest.raises(ScoringInputError, match="between 0 and 100"):
        calculate_event_score(_evidence(member=_member("101")))

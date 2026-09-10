from __future__ import annotations

import json
from datetime import UTC
from decimal import Decimal
from typing import Any

from app.scoring.event_models import EventScoreResult, EventScoringEvidence
from app.scoring.models import EvidenceStatus, ScoreComponent, ScoringInputError
from app.scoring.normalization import normalize_sources, round_and_clamp, severity_for, source_ratio

EVENT_FORMULA_VERSION = "phase9a-event-v1"
MEMBER_WEIGHT = Decimal("90")
SOURCE_WEIGHT = Decimal("10")
ONE = Decimal("1")
ZERO = Decimal("0")


def calculate_event_score(evidence: EventScoringEvidence) -> EventScoreResult:
    member = evidence.member_score
    if member is not None and not ZERO <= member.score <= Decimal("100"):
        raise ScoringInputError("member score must be between 0 and 100")
    sources = normalize_sources(evidence.source_names)
    member_component = ScoreComponent(
        name="member_indicator_score",
        status=EvidenceStatus.USABLE if member else EvidenceStatus.MISSING,
        raw_input=(("score", member.score if member else None),),
        normalized_value=member.score / Decimal("100") if member else None,
        weight=MEMBER_WEIGHT,
        freshness_multiplier=ONE,
        contribution=member.score * Decimal("0.90") if member else ZERO,
        provider=None,
        evidence_at=member.calculated_at if member else None,
        effective_expiry=None,
        explanation=(
            "Latest persisted matching CVE indicator score contributes 90%"
            if member
            else "Matching CVE has no persisted indicator score; no member contribution"
        ),
    )
    ratio = source_ratio(len(sources))
    source_component = ScoreComponent(
        name="independent_sources",
        status=EvidenceStatus.USABLE,
        raw_input=(("count", len(sources)),),
        normalized_value=ratio,
        weight=SOURCE_WEIGHT,
        freshness_multiplier=ONE,
        contribution=ratio * SOURCE_WEIGHT,
        provider=None,
        evidence_at=None,
        effective_expiry=None,
        explanation="Capped exact-normalized independent source corroboration",
    )
    final = round_and_clamp(member_component.contribution + source_component.contribution)
    return EventScoreResult(
        formula_version=EVENT_FORMULA_VERSION,
        event_id=evidence.event_id,
        event_key=evidence.event_key,
        canonical_cve=evidence.canonical_cve,
        final_score=final,
        severity=severity_for(final),
        calculated_at=evidence.as_of.astimezone(UTC),
        components=(member_component, source_component),
        normalized_source_names=sources,
        warnings=("member_indicator_score_missing",) if member is None else (),
    )


def canonical_serialize_event_result(result: EventScoreResult) -> bytes:
    """Serialize derived output deterministically; never use for evidence hashing."""

    payload: dict[str, Any] = {
        "calculated_at": result.calculated_at.isoformat().replace("+00:00", "Z"),
        "canonical_cve": result.canonical_cve,
        "components": [
            {
                "contribution": format(item.contribution, "f"),
                "name": item.name,
                "normalized_value": (
                    format(item.normalized_value, "f")
                    if item.normalized_value is not None
                    else None
                ),
                "status": item.status.value,
                "weight": format(item.weight, "f"),
            }
            for item in result.components
        ],
        "event_id": result.event_id,
        "event_key": result.event_key,
        "final_score": format(result.final_score, "f"),
        "formula_version": result.formula_version,
        "normalized_source_names": list(result.normalized_source_names),
        "severity": result.severity.value,
        "warnings": list(result.warnings),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


__all__ = ["EVENT_FORMULA_VERSION", "calculate_event_score", "canonical_serialize_event_result"]

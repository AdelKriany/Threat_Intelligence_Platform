from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from app.scoring.constants import HUNDRED, ZERO
from app.scoring.models import ScoreComponent, ScoreResult, Severity


def normalize_sources(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = {re.sub(r"\s+", " ", value.strip().casefold()) for value in values}
    return tuple(sorted(value for value in normalized if value))


def source_ratio(count: int) -> Decimal:
    return Decimal(min(max(count - 1, 0), 4)) / Decimal("4")


def round_and_clamp(value: Decimal) -> Decimal:
    return min(max(value, ZERO), HUNDRED).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def severity_for(score: Decimal) -> Severity:
    if score == ZERO:
        return Severity.NONE
    if score < Decimal("25"):
        return Severity.LOW
    if score < Decimal("50"):
        return Severity.MEDIUM
    if score < Decimal("75"):
        return Severity.HIGH
    return Severity.CRITICAL


def decimal_text(value: Decimal | None) -> str | None:
    if value is not None and (not isinstance(value, Decimal) or not value.is_finite()):
        raise TypeError("canonical decimal values must be finite Decimal instances")
    return format(value, "f") if value is not None else None


def utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("canonical datetime values must be timezone-aware datetime instances")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def canonical_serialize_result(result: ScoreResult) -> bytes:
    """Serialize derived scoring output deterministically.

    This is not the canonical evidence snapshot used for a future persistence hash.
    Persistence must serialize raw evidence separately and exclude derived score output.
    """

    def component(item: ScoreComponent) -> dict[str, Any]:
        return {
            "name": item.name,
            "status": item.status.value,
            "raw_input": [[key, _json_value(value)] for key, value in item.raw_input],
            "normalized_value": decimal_text(item.normalized_value),
            "weight": decimal_text(item.weight),
            "freshness_multiplier": decimal_text(item.freshness_multiplier),
            "contribution": decimal_text(item.contribution),
            "provider": item.provider,
            "evidence_at": utc_text(item.evidence_at),
            "effective_expiry": utc_text(item.effective_expiry),
            "explanation": item.explanation,
        }

    payload = {
        "formula_version": result.formula_version,
        "ioc_type": result.ioc_type.value,
        "canonical_value": result.canonical_value,
        "unrounded_total": decimal_text(result.unrounded_total),
        "final_score": decimal_text(result.final_score),
        "severity": result.severity.value,
        "components": [component(item) for item in result.components],
        "normalized_source_names": list(result.normalized_source_names),
        "as_of": utc_text(result.as_of),
        "warnings": list(result.warnings),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return decimal_text(value)
    if isinstance(value, datetime):
        return utc_text(value)
    if value is None or type(value) in {str, int, bool}:
        return value
    raise TypeError(f"unsupported canonical serialization value: {type(value).__name__}")


# Backward-compatible result-serialization alias; never use this as an evidence hash input.
canonical_serialize = canonical_serialize_result

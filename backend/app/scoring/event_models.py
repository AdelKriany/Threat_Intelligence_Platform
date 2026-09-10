from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from app.scoring.models import ScoreComponent, ScoringInputError, Severity


def _aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ScoringInputError(f"{name} must be timezone-aware")


def _finite(value: Decimal, name: str) -> None:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ScoringInputError(f"{name} must be a finite Decimal")


@dataclass(frozen=True, slots=True)
class MemberIndicatorScoreEvidence:
    score_history_id: int
    indicator_id: int
    score: Decimal
    severity: Severity
    formula_version: str
    evidence_hash: str
    calculated_at: datetime

    def __post_init__(self) -> None:
        if self.score_history_id <= 0 or self.indicator_id <= 0:
            raise ScoringInputError("member score and indicator IDs must be positive")
        _finite(self.score, "member score")
        if not isinstance(self.severity, Severity):
            raise ScoringInputError("member severity must be a Severity")
        if not self.formula_version:
            raise ScoringInputError("member formula_version must be non-empty")
        if len(self.evidence_hash) != 64 or any(
            c not in "0123456789abcdef" for c in self.evidence_hash
        ):
            raise ScoringInputError("member evidence_hash must be lowercase SHA-256")
        _aware(self.calculated_at, "member calculated_at")


@dataclass(frozen=True, slots=True)
class EventScoringEvidence:
    event_id: int
    event_key: str
    rule_name: str
    rule_version: str
    cve_indicator_id: int
    canonical_cve: str
    as_of: datetime
    member_score: MemberIndicatorScoreEvidence | None
    source_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.event_id <= 0 or self.cve_indicator_id <= 0:
            raise ScoringInputError("event and CVE indicator IDs must be positive")
        if not all(
            isinstance(value, str) and value
            for value in (self.event_key, self.rule_name, self.rule_version, self.canonical_cve)
        ):
            raise ScoringInputError("event identity fields must be non-empty strings")
        _aware(self.as_of, "as_of")
        if (
            self.member_score is not None
            and self.member_score.indicator_id != self.cve_indicator_id
        ):
            raise ScoringInputError("member score indicator does not match event CVE")
        if type(self.source_names) is not tuple or not all(
            isinstance(v, str) for v in self.source_names
        ):
            raise ScoringInputError("source_names must be a tuple of strings")


@dataclass(frozen=True, slots=True)
class EventScoreResult:
    formula_version: str
    event_id: int
    event_key: str
    canonical_cve: str
    final_score: Decimal
    severity: Severity
    calculated_at: datetime
    components: tuple[ScoreComponent, ...]
    normalized_source_names: tuple[str, ...]
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        _finite(self.final_score, "final_score")
        _aware(self.calculated_at, "calculated_at")

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TypeAlias

from app.ingestion.models import IOCType


class EvidenceStatus(StrEnum):
    USABLE = "usable"
    MISSING = "missing"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"
    STALE = "stale"


class Severity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoringInputError(ValueError):
    pass


RawScalar: TypeAlias = str | int | bool | Decimal | datetime | None
RawInput: TypeAlias = tuple[tuple[str, RawScalar], ...]


def _aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ScoringInputError(f"{name} must be timezone-aware")


def _decimal(value: Decimal | None, name: str) -> None:
    if value is not None and (not isinstance(value, Decimal) or not value.is_finite()):
        raise ScoringInputError(f"{name} must be a finite Decimal")


def _raw_scalar(value: object, name: str) -> None:
    if isinstance(value, Decimal):
        _decimal(value, name)
    elif isinstance(value, datetime):
        _aware(value, name)
    elif value is not None and type(value) not in {str, int, bool}:
        raise ScoringInputError(f"{name} contains an unsupported raw scalar")


def _status_invariants(item: EvidenceBase, values: tuple[RawScalar, ...]) -> None:
    if item.status is EvidenceStatus.STALE:
        raise ScoringInputError("stale is a derived status and cannot be supplied")
    if item.status is EvidenceStatus.USABLE:
        if any(value is None for value in values):
            raise ScoringInputError("usable evidence requires all provider values")
        if item.evidence_at is None:
            raise ScoringInputError("usable evidence requires evidence_at")
    elif any(value is not None for value in values) or item.evidence_at or item.expires_at:
        raise ScoringInputError("non-usable evidence cannot carry values or timestamps")


@dataclass(frozen=True, slots=True)
class EvidenceBase:
    status: EvidenceStatus = EvidenceStatus.USABLE
    evidence_at: datetime | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, EvidenceStatus):
            raise ScoringInputError("status must be an EvidenceStatus")
        if self.evidence_at is not None:
            _aware(self.evidence_at, "evidence_at")
        if self.expires_at is not None:
            _aware(self.expires_at, "expires_at")
        if self.evidence_at and self.expires_at and self.expires_at < self.evidence_at:
            raise ScoringInputError("expires_at cannot precede evidence_at")


@dataclass(frozen=True, slots=True)
class NVDEvidence(EvidenceBase):
    cvss_base_score: Decimal | None = None

    def __post_init__(self) -> None:
        super(NVDEvidence, self).__post_init__()
        _decimal(self.cvss_base_score, "cvss_base_score")
        _status_invariants(self, (self.cvss_base_score,))


@dataclass(frozen=True, slots=True)
class KEVEvidence(EvidenceBase):
    known_exploited: bool | None = None

    def __post_init__(self) -> None:
        super(KEVEvidence, self).__post_init__()
        if self.known_exploited is not None and type(self.known_exploited) is not bool:
            raise ScoringInputError("known_exploited must be a bool")
        _status_invariants(self, (self.known_exploited,))


@dataclass(frozen=True, slots=True)
class EPSSEvidence(EvidenceBase):
    probability: Decimal | None = None
    percentile: Decimal | None = None

    def __post_init__(self) -> None:
        super(EPSSEvidence, self).__post_init__()
        _decimal(self.probability, "probability")
        _decimal(self.percentile, "percentile")
        _status_invariants(self, (self.probability, self.percentile))


@dataclass(frozen=True, slots=True)
class VirusTotalEvidence(EvidenceBase):
    malicious: int | None = None
    total_analyzed_engines: int | None = None
    suspicious: int | None = None

    def __post_init__(self) -> None:
        super(VirusTotalEvidence, self).__post_init__()
        values = (self.malicious, self.total_analyzed_engines, self.suspicious)
        if any(value is not None and type(value) is not int for value in values):
            raise ScoringInputError("VirusTotal counts must be integers")
        _status_invariants(self, values)


@dataclass(frozen=True, slots=True)
class AbuseIPDBEvidence(EvidenceBase):
    abuse_confidence_score: Decimal | None = None

    def __post_init__(self) -> None:
        super(AbuseIPDBEvidence, self).__post_init__()
        _decimal(self.abuse_confidence_score, "abuse_confidence_score")
        _status_invariants(self, (self.abuse_confidence_score,))


@dataclass(frozen=True, slots=True)
class ScoringEvidence:
    ioc_type: IOCType
    canonical_value: str
    as_of: datetime
    source_names: tuple[str, ...] = ()
    nvd: NVDEvidence | None = None
    kev: KEVEvidence | None = None
    epss: EPSSEvidence | None = None
    virustotal: VirusTotalEvidence | None = None
    abuseipdb: AbuseIPDBEvidence | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ioc_type, IOCType):
            raise ScoringInputError("ioc_type must be an IOCType")
        if not isinstance(self.canonical_value, str) or not self.canonical_value:
            raise ScoringInputError("canonical_value must be a non-empty string")
        if not isinstance(self.as_of, datetime):
            raise ScoringInputError("as_of must be a datetime")
        _aware(self.as_of, "as_of")
        if type(self.source_names) is not tuple or not all(
            isinstance(value, str) for value in self.source_names
        ):
            raise ScoringInputError("source_names must be a tuple of strings")
        expected = (
            ("nvd", self.nvd, NVDEvidence),
            ("kev", self.kev, KEVEvidence),
            ("epss", self.epss, EPSSEvidence),
            ("virustotal", self.virustotal, VirusTotalEvidence),
            ("abuseipdb", self.abuseipdb, AbuseIPDBEvidence),
        )
        for name, value, cls in expected:
            if value is not None and not isinstance(value, cls):
                raise ScoringInputError(f"{name} has the wrong evidence type")


@dataclass(frozen=True, slots=True)
class ScoreComponent:
    name: str
    status: EvidenceStatus
    raw_input: RawInput
    normalized_value: Decimal | None
    weight: Decimal
    freshness_multiplier: Decimal
    contribution: Decimal
    provider: str | None
    evidence_at: datetime | None
    effective_expiry: datetime | None
    explanation: str

    def __post_init__(self) -> None:
        if type(self.raw_input) is not tuple:
            raise ScoringInputError("raw_input must be a tuple")
        for entry in self.raw_input:
            if type(entry) is not tuple or len(entry) != 2 or not isinstance(entry[0], str):
                raise ScoringInputError("raw_input entries must be (string, scalar) tuples")
            _raw_scalar(entry[1], "raw_input")
        for name, value in (
            ("normalized_value", self.normalized_value),
            ("weight", self.weight),
            ("freshness_multiplier", self.freshness_multiplier),
            ("contribution", self.contribution),
        ):
            _decimal(value, name)
        if self.evidence_at is not None:
            _aware(self.evidence_at, "evidence_at")
        if self.effective_expiry is not None:
            _aware(self.effective_expiry, "effective_expiry")


@dataclass(frozen=True, slots=True)
class ScoreResult:
    formula_version: str
    ioc_type: IOCType
    canonical_value: str
    unrounded_total: Decimal
    final_score: Decimal
    severity: Severity
    components: tuple[ScoreComponent, ...]
    normalized_source_names: tuple[str, ...]
    as_of: datetime
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        _decimal(self.unrounded_total, "unrounded_total")
        _decimal(self.final_score, "final_score")
        _aware(self.as_of, "as_of")
        if type(self.components) is not tuple or not all(
            isinstance(value, ScoreComponent) for value in self.components
        ):
            raise ScoringInputError("components must be a tuple of ScoreComponent values")
        if type(self.normalized_source_names) is not tuple or not all(
            isinstance(value, str) for value in self.normalized_source_names
        ):
            raise ScoringInputError("normalized_source_names must be a tuple of strings")
        if type(self.warnings) is not tuple or not all(
            isinstance(value, str) for value in self.warnings
        ):
            raise ScoringInputError("warnings must be a tuple of strings")

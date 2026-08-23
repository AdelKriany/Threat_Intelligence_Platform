from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Final, TypedDict, cast

from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, noload

from app.ingestion.models import ArticleIndicator, Indicator, IndicatorEnrichment, RawArticle
from app.models.phase6b import ScoreComponentRecord, ScoreHistory
from app.scoring.engine import calculate_score
from app.scoring.evidence_snapshot import (
    CanonicalEvidenceSnapshot,
    applicable_provider_names,
    build_evidence_snapshot,
)
from app.scoring.models import (
    AbuseIPDBEvidence,
    EPSSEvidence,
    EvidenceStatus,
    KEVEvidence,
    NVDEvidence,
    ScoreComponent,
    ScoreResult,
    ScoringEvidence,
    ScoringInputError,
    VirusTotalEvidence,
)

INDICATOR_EVIDENCE_UNIQUE_INDEX: Final = "uq_score_history_indicator_evidence"
_STATUS_MAP: Final = MappingProxyType(
    {
        "success": EvidenceStatus.USABLE,
        "not_found": EvidenceStatus.MISSING,
        "failed": EvidenceStatus.FAILED,
        "rate_limited": EvidenceStatus.FAILED,
        "auth_error": EvidenceStatus.FAILED,
        "temporary_failure": EvidenceStatus.FAILED,
        "permanent_failure": EvidenceStatus.INVALID,
        "invalid": EvidenceStatus.INVALID,
        "unsupported": EvidenceStatus.UNSUPPORTED,
    }
)


class IndicatorNotFoundError(LookupError):
    pass


class _EvidenceTimes(TypedDict):
    evidence_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class PersistedIndicatorScore:
    score_history: ScoreHistory
    components: tuple[ScoreComponentRecord, ...]
    created: bool
    evidence_hash: str


def calculate_and_persist_indicator_score(
    session: Session,
    indicator_id: int,
    *,
    as_of: datetime,
) -> PersistedIndicatorScore:
    """Load, hash, score, and atomically append or reuse one indicator snapshot.

    The caller owns the outer transaction. This function flushes but never commits it.
    """

    evidence = load_indicator_scoring_evidence(session, indicator_id, as_of=as_of)
    snapshot = build_evidence_snapshot(evidence)
    score_result = calculate_score(evidence)
    return persist_indicator_score(
        session,
        indicator_id=indicator_id,
        score_result=score_result,
        snapshot=snapshot,
    )


def load_indicator_scoring_evidence(
    session: Session,
    indicator_id: int,
    *,
    as_of: datetime,
) -> ScoringEvidence:
    as_of_utc = _aware_utc(as_of, "as_of")
    indicator = session.scalar(select(Indicator).where(Indicator.id == indicator_id))
    if indicator is None:
        raise IndicatorNotFoundError(f"indicator {indicator_id} was not found")

    provider_names = applicable_provider_names(indicator.indicator_type)
    records: list[IndicatorEnrichment] = []
    if provider_names:
        records = list(
            session.scalars(
                select(IndicatorEnrichment)
                .where(
                    IndicatorEnrichment.indicator_id == indicator.id,
                    IndicatorEnrichment.provider.in_(provider_names),
                )
                .order_by(
                    IndicatorEnrichment.provider,
                    IndicatorEnrichment.enriched_at.desc(),
                    IndicatorEnrichment.id.desc(),
                )
            )
        )
    latest = latest_provider_records(records, provider_names)

    source_names = tuple(
        cast(str, value)
        for value in session.scalars(
            select(RawArticle.source_name)
            .join(
                ArticleIndicator,
                ArticleIndicator.raw_article_id == RawArticle.id,
            )
            .where(
                ArticleIndicator.indicator_id == indicator.id,
                RawArticle.source_name.is_not(None),
                func.length(func.trim(RawArticle.source_name)) > 0,
            )
            .order_by(RawArticle.source_name, RawArticle.id)
        )
    )

    return ScoringEvidence(
        ioc_type=indicator.indicator_type,
        canonical_value=indicator.indicator_value,
        as_of=as_of_utc,
        source_names=source_names,
        nvd=_map_nvd(latest.get("nvd")) if "nvd" in provider_names else None,
        kev=_map_kev(latest.get("cisa_kev")) if "cisa_kev" in provider_names else None,
        epss=_map_epss(latest.get("epss")) if "epss" in provider_names else None,
        virustotal=(
            _map_virustotal(latest.get("virustotal")) if "virustotal" in provider_names else None
        ),
        abuseipdb=(
            _map_abuseipdb(latest.get("abuseipdb")) if "abuseipdb" in provider_names else None
        ),
    )


def latest_provider_records(
    records: Iterable[IndicatorEnrichment],
    provider_names: Iterable[str],
) -> dict[str, IndicatorEnrichment]:
    """Select latest evidence by enriched time, then stable primary-key tie-breaker."""

    applicable = frozenset(provider_names)
    selected: dict[str, IndicatorEnrichment] = {}
    for record in records:
        if record.provider not in applicable:
            continue
        current = selected.get(record.provider)
        if current is None or _record_order(record) > _record_order(current):
            selected[record.provider] = record
    return selected


def persist_indicator_score(
    session: Session,
    *,
    indicator_id: int,
    score_result: ScoreResult,
    snapshot: CanonicalEvidenceSnapshot,
) -> PersistedIndicatorScore:
    existing = _find_existing(session, indicator_id, score_result.formula_version, snapshot)
    if existing is not None:
        return _persisted_result(session, existing, score_result, snapshot, created=False)

    component_rows = [_component_record(component) for component in score_result.components]
    history = ScoreHistory(
        target_kind="indicator",
        indicator_id=indicator_id,
        event_id=None,
        score=score_result.final_score,
        severity=score_result.severity.value,
        formula_version=score_result.formula_version,
        evidence_hash=snapshot.evidence_hash,
        canonical_evidence=snapshot.payload(),
        calculated_at=_aware_utc(score_result.as_of, "score_result.as_of"),
        components=component_rows,
    )
    try:
        with session.begin_nested():
            session.add(history)
            session.flush()
    except IntegrityError as exc:
        if not _is_indicator_idempotency_violation(exc):
            raise
        existing = _find_existing(session, indicator_id, score_result.formula_version, snapshot)
        if existing is None:
            raise
        return _persisted_result(session, existing, score_result, snapshot, created=False)

    return PersistedIndicatorScore(
        score_history=history,
        components=tuple(component_rows),
        created=True,
        evidence_hash=snapshot.evidence_hash,
    )


def _find_existing(
    session: Session,
    indicator_id: int,
    formula_version: str,
    snapshot: CanonicalEvidenceSnapshot,
) -> ScoreHistory | None:
    with session.no_autoflush:
        return session.scalar(
            select(ScoreHistory)
            .options(
                noload(ScoreHistory.components),
                noload(ScoreHistory.indicator),
                noload(ScoreHistory.event),
            )
            .where(
                ScoreHistory.target_kind == "indicator",
                ScoreHistory.indicator_id == indicator_id,
                ScoreHistory.formula_version == formula_version,
                ScoreHistory.evidence_hash == snapshot.evidence_hash,
            )
        )


def _persisted_result(
    session: Session,
    history: ScoreHistory,
    score_result: ScoreResult,
    snapshot: CanonicalEvidenceSnapshot,
    *,
    created: bool,
) -> PersistedIndicatorScore:
    order = {component.name: position for position, component in enumerate(score_result.components)}
    ordering = case(order, value=ScoreComponentRecord.component_name, else_=len(order))
    rows = tuple(
        session.scalars(
            select(ScoreComponentRecord)
            .where(ScoreComponentRecord.score_history_id == history.id)
            .order_by(ordering, ScoreComponentRecord.component_name)
        )
    )
    expected_names = tuple(component.name for component in score_result.components)
    if tuple(row.component_name for row in rows) != expected_names:
        raise RuntimeError("persisted score components do not match the fixed scoring profile")
    return PersistedIndicatorScore(
        score_history=history,
        components=rows,
        created=created,
        evidence_hash=snapshot.evidence_hash,
    )


def _component_record(component: ScoreComponent) -> ScoreComponentRecord:
    return ScoreComponentRecord(
        component_name=component.name,
        raw_input={key: _json_scalar(value) for key, value in component.raw_input},
        normalized_input=_json_scalar(component.normalized_value),
        weight=component.weight,
        contribution=component.contribution,
        freshness_multiplier=component.freshness_multiplier,
        explanation=component.explanation,
        provider=component.provider,
        evidence_at=(
            _aware_utc(component.evidence_at, f"{component.name}.evidence_at")
            if component.evidence_at is not None
            else None
        ),
    )


def _map_nvd(record: IndicatorEnrichment | None) -> NVDEvidence | None:
    if record is None:
        return None
    status = _mapped_status(record.status)
    if status is not EvidenceStatus.USABLE:
        return NVDEvidence(status=status)
    times = _usable_times(record)
    try:
        value = _finite_decimal(record.normalized_data.get("cvss_score"), "nvd.cvss_score")
    except ScoringInputError:
        return NVDEvidence(status=EvidenceStatus.INVALID)
    return NVDEvidence(cvss_base_score=value, **times)


def _map_kev(record: IndicatorEnrichment | None) -> KEVEvidence | None:
    if record is None:
        return None
    status = _mapped_status(record.status)
    if status is not EvidenceStatus.USABLE:
        return KEVEvidence(status=status)
    times = _usable_times(record)
    value = record.normalized_data.get("known_exploited")
    if type(value) is not bool:
        return KEVEvidence(status=EvidenceStatus.INVALID)
    return KEVEvidence(known_exploited=value, **times)


def _map_epss(record: IndicatorEnrichment | None) -> EPSSEvidence | None:
    if record is None:
        return None
    status = _mapped_status(record.status)
    if status is not EvidenceStatus.USABLE:
        return EPSSEvidence(status=status)
    times = _usable_times(record)
    try:
        probability = _finite_decimal(record.normalized_data.get("epss"), "epss.epss")
        percentile = _finite_decimal(record.normalized_data.get("percentile"), "epss.percentile")
    except ScoringInputError:
        return EPSSEvidence(status=EvidenceStatus.INVALID)
    return EPSSEvidence(probability=probability, percentile=percentile, **times)


def _map_virustotal(record: IndicatorEnrichment | None) -> VirusTotalEvidence | None:
    if record is None:
        return None
    status = _mapped_status(record.status)
    if status is not EvidenceStatus.USABLE:
        return VirusTotalEvidence(status=status)
    times = _usable_times(record)
    stats = record.normalized_data.get("analysis_stats")
    if not isinstance(stats, dict):
        return VirusTotalEvidence(status=EvidenceStatus.INVALID)
    try:
        counts = {key: _nonnegative_int(value, f"virustotal.{key}") for key, value in stats.items()}
        malicious = counts.get("malicious", 0)
        suspicious = counts.get("suspicious", 0)
        total = sum(counts.values())
    except ScoringInputError:
        return VirusTotalEvidence(status=EvidenceStatus.INVALID)
    return VirusTotalEvidence(
        malicious=malicious,
        suspicious=suspicious,
        total_analyzed_engines=total,
        **times,
    )


def _map_abuseipdb(record: IndicatorEnrichment | None) -> AbuseIPDBEvidence | None:
    if record is None:
        return None
    status = _mapped_status(record.status)
    if status is not EvidenceStatus.USABLE:
        return AbuseIPDBEvidence(status=status)
    times = _usable_times(record)
    try:
        value = _finite_decimal(
            record.normalized_data.get("abuse_confidence_score"),
            "abuseipdb.abuse_confidence_score",
        )
    except ScoringInputError:
        return AbuseIPDBEvidence(status=EvidenceStatus.INVALID)
    return AbuseIPDBEvidence(abuse_confidence_score=value, **times)


def _mapped_status(value: str) -> EvidenceStatus:
    return cast(EvidenceStatus, _STATUS_MAP.get(value, EvidenceStatus.INVALID))


def _usable_times(record: IndicatorEnrichment) -> _EvidenceTimes:
    evidence_at = _aware_utc(record.enriched_at, f"{record.provider}.enriched_at")
    expires_at = (
        _aware_utc(record.expires_at, f"{record.provider}.expires_at")
        if record.expires_at is not None
        else None
    )
    if expires_at is not None and expires_at < evidence_at:
        raise ScoringInputError(f"{record.provider}.expires_at cannot precede enriched_at")
    return {"evidence_at": evidence_at, "expires_at": expires_at}


def _finite_decimal(value: object, name: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ScoringInputError(f"{name} must be numeric")
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ScoringInputError(f"{name} must be numeric") from exc
    if not parsed.is_finite():
        raise ScoringInputError(f"{name} must be finite")
    return parsed


def _nonnegative_int(value: object, name: str) -> int:
    if type(value) is not int or cast(int, value) < 0:
        raise ScoringInputError(f"{name} must be a non-negative integer")
    return cast(int, value)


def _record_order(record: IndicatorEnrichment) -> tuple[datetime, int]:
    return (_aware_utc(record.enriched_at, f"{record.provider}.enriched_at"), record.id or -1)


def _aware_utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ScoringInputError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        # SQLite drops timezone offsets; repository persistence treats those values as UTC.
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _json_scalar(value: object) -> str | int | bool | None:
    if value is None or type(value) in {str, int, bool}:
        return cast(str | int | bool | None, value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ScoringInputError("component Decimal values must be finite")
        return format(value, "f")
    if isinstance(value, datetime):
        return _aware_utc(value, "component datetime").isoformat().replace("+00:00", "Z")
    raise ScoringInputError(f"unsupported component scalar: {type(value).__name__}")


def _is_indicator_idempotency_violation(exc: IntegrityError) -> bool:
    diagnostic = getattr(exc.orig, "diag", None)
    constraint_name = getattr(diagnostic, "constraint_name", None)
    if constraint_name is not None:
        return constraint_name == INDICATOR_EVIDENCE_UNIQUE_INDEX
    message = str(exc.orig).casefold()
    return (
        "score_history.indicator_id" in message
        and "score_history.formula_version" in message
        and "score_history.evidence_hash" in message
    )


__all__ = [
    "IndicatorNotFoundError",
    "PersistedIndicatorScore",
    "calculate_and_persist_indicator_score",
    "latest_provider_records",
    "load_indicator_scoring_evidence",
    "persist_indicator_score",
]

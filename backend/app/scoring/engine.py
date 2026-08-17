from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import cast

from app.ingestion.ioc.validators import ValidationStatus, validate_indicator
from app.ingestion.models import IOCType
from app.scoring.constants import (
    CVE_WEIGHTS,
    FORMULA_VERSION,
    IP_PROVIDER_WEIGHT,
    NON_CVE_SOURCE_WEIGHT,
    NON_CVE_VT_WEIGHT,
    ONE,
    PROVIDER_TTL_SECONDS,
    STALE_WINDOW_DAYS,
    ZERO,
)
from app.scoring.models import (
    AbuseIPDBEvidence,
    EPSSEvidence,
    EvidenceBase,
    EvidenceStatus,
    KEVEvidence,
    NVDEvidence,
    RawScalar,
    ScoreComponent,
    ScoreResult,
    ScoringEvidence,
    ScoringInputError,
    VirusTotalEvidence,
)
from app.scoring.normalization import normalize_sources, round_and_clamp, severity_for, source_ratio

_VT_TYPES = {
    IOCType.IPV4,
    IOCType.IPV6,
    IOCType.DOMAIN,
    IOCType.URL,
    IOCType.MD5,
    IOCType.SHA1,
    IOCType.SHA256,
}
_IP_TYPES = {IOCType.IPV4, IOCType.IPV6}


def calculate_score(evidence: ScoringEvidence) -> ScoreResult:
    as_of = _aware(evidence.as_of, "as_of")
    validation = validate_indicator(evidence.ioc_type, evidence.canonical_value)
    if validation.status is ValidationStatus.INVALID:
        raise ScoringInputError("canonical IOC value is invalid")
    if evidence.canonical_value != validation.normalized_value:
        raise ScoringInputError("canonical IOC value is not in canonical form")
    _validate_pairings(evidence)
    sources = normalize_sources(evidence.source_names)
    components: list[ScoreComponent] = []
    if evidence.ioc_type is IOCType.CVE:
        components.extend(_cve_components(evidence, as_of))
        source_weight = CVE_WEIGHTS["independent_sources"]
    elif evidence.ioc_type in _IP_TYPES:
        components.append(_vt_component(evidence.virustotal, IP_PROVIDER_WEIGHT, as_of))
        components.append(_abuse_component(evidence.abuseipdb, IP_PROVIDER_WEIGHT, as_of))
        source_weight = NON_CVE_SOURCE_WEIGHT
    elif evidence.ioc_type in _VT_TYPES:
        components.append(_vt_component(evidence.virustotal, NON_CVE_VT_WEIGHT, as_of))
        source_weight = NON_CVE_SOURCE_WEIGHT
    else:
        source_weight = NON_CVE_SOURCE_WEIGHT

    source_normalized = source_ratio(len(sources))
    components.append(
        ScoreComponent(
            name="independent_sources",
            status=EvidenceStatus.USABLE,
            raw_input=(("count", len(sources)),),
            normalized_value=source_normalized,
            weight=source_weight,
            freshness_multiplier=ONE,
            contribution=source_normalized * source_weight,
            provider=None,
            evidence_at=None,
            effective_expiry=None,
            explanation="Capped exact-normalized independent source corroboration",
        )
    )
    ordered = tuple(components)
    total = sum((item.contribution for item in ordered), ZERO)
    final = round_and_clamp(total)
    return ScoreResult(
        formula_version=FORMULA_VERSION,
        ioc_type=evidence.ioc_type,
        canonical_value=evidence.canonical_value,
        unrounded_total=total,
        final_score=final,
        severity=severity_for(final),
        components=ordered,
        normalized_source_names=sources,
        as_of=as_of,
        warnings=(),
    )


def _cve_components(evidence: ScoringEvidence, as_of: datetime) -> list[ScoreComponent]:
    return [
        _numeric_component("nvd_cvss", "nvd", evidence.nvd, CVE_WEIGHTS["nvd_cvss"], as_of),
        _kev_component(evidence.kev, CVE_WEIGHTS["cisa_kev"], as_of),
        _epss_component(
            "epss_probability", "probability", evidence.epss, CVE_WEIGHTS["epss_probability"], as_of
        ),
        _epss_component(
            "epss_percentile", "percentile", evidence.epss, CVE_WEIGHTS["epss_percentile"], as_of
        ),
    ]


def _numeric_component(
    name: str, provider: str, item: NVDEvidence | None, weight: Decimal, as_of: datetime
) -> ScoreComponent:
    raw = item.cvss_base_score if item else None
    if item and item.status is EvidenceStatus.USABLE and raw is not None:
        _range(raw, ZERO, Decimal("10"), name)
        normalized = raw / Decimal("10")
    else:
        normalized = None
    return _provider_component(
        name, provider, item, (("cvss_base_score", raw),), normalized, weight, as_of
    )


def _kev_component(item: KEVEvidence | None, weight: Decimal, as_of: datetime) -> ScoreComponent:
    normalized = (
        ONE
        if item and item.status is EvidenceStatus.USABLE and item.known_exploited is True
        else ZERO
        if item and item.status is EvidenceStatus.USABLE
        else None
    )
    return _provider_component(
        "cisa_kev",
        "cisa_kev",
        item,
        (("known_exploited", item.known_exploited if item else None),),
        normalized,
        weight,
        as_of,
    )


def _epss_component(
    name: str, field: str, item: EPSSEvidence | None, weight: Decimal, as_of: datetime
) -> ScoreComponent:
    raw = getattr(item, field) if item else None
    if item and item.status is EvidenceStatus.USABLE and raw is not None:
        _range(raw, ZERO, ONE, name)
        normalized = raw
    else:
        normalized = None
    return _provider_component(name, "epss", item, ((field, raw),), normalized, weight, as_of)


def _vt_component(
    item: VirusTotalEvidence | None, weight: Decimal, as_of: datetime
) -> ScoreComponent:
    malicious = item.malicious if item else None
    total = item.total_analyzed_engines if item else None
    suspicious = item.suspicious if item else None
    normalized = None
    if item and item.status is EvidenceStatus.USABLE:
        malicious_count = cast(int, malicious)
        total_count = cast(int, total)
        suspicious_count = cast(int, suspicious)
        if (
            malicious_count < 0
            or total_count < 0
            or suspicious_count < 0
            or malicious_count + suspicious_count > total_count
        ):
            raise ScoringInputError("invalid VirusTotal counts")
        normalized = Decimal(malicious_count + suspicious_count) / Decimal(max(total_count, 1))
    return _provider_component(
        "virustotal",
        "virustotal",
        item,
        (
            ("malicious", malicious),
            ("suspicious", suspicious),
            ("total_analyzed_engines", total),
        ),
        normalized,
        weight,
        as_of,
    )


def _abuse_component(
    item: AbuseIPDBEvidence | None, weight: Decimal, as_of: datetime
) -> ScoreComponent:
    raw = item.abuse_confidence_score if item else None
    normalized = None
    if item and item.status is EvidenceStatus.USABLE:
        assert raw is not None
        _range(raw, ZERO, Decimal("100"), "abuse_confidence_score")
        normalized = raw / Decimal("100")
    return _provider_component(
        "abuseipdb",
        "abuseipdb",
        item,
        (("abuse_confidence_score", raw),),
        normalized,
        weight,
        as_of,
    )


def _provider_component(
    name: str,
    provider: str,
    item: EvidenceBase | None,
    raw: tuple[tuple[str, RawScalar], ...],
    normalized: Decimal | None,
    weight: Decimal,
    as_of: datetime,
) -> ScoreComponent:
    status = item.status if item else EvidenceStatus.MISSING
    evidence_at = item.evidence_at if item else None
    expiry = item.expires_at if item else None
    multiplier = ZERO
    if status is EvidenceStatus.USABLE:
        if normalized is None:
            status = EvidenceStatus.INVALID
        elif evidence_at is None:
            status = EvidenceStatus.INVALID
        else:
            evidence_at = _aware(evidence_at, f"{provider}.evidence_at")
            if evidence_at > as_of:
                raise ScoringInputError(f"{provider}.evidence_at cannot be in the future")
            expiry = (
                _aware(expiry, f"{provider}.expires_at")
                if expiry
                else evidence_at + timedelta(seconds=PROVIDER_TTL_SECONDS[provider])
            )
            overdue = as_of - expiry
            if overdue <= timedelta(0):
                multiplier = ONE
            elif overdue <= timedelta(days=STALE_WINDOW_DAYS):
                multiplier = Decimal("0.50")
                status = EvidenceStatus.STALE
            else:
                multiplier = Decimal("0.25")
                status = EvidenceStatus.STALE
    contribution = (
        (normalized or ZERO) * weight * multiplier
        if status in {EvidenceStatus.USABLE, EvidenceStatus.STALE}
        else ZERO
    )
    explanation = (
        f"{name} provider evidence is missing; no contribution"
        if status is EvidenceStatus.MISSING
        else f"{name} provider evidence is {status.value}; no contribution"
        if status in {EvidenceStatus.FAILED, EvidenceStatus.INVALID, EvidenceStatus.UNSUPPORTED}
        else f"{name} weighted provider evidence"
    )
    return ScoreComponent(
        name,
        status,
        raw,
        normalized,
        weight,
        multiplier,
        contribution,
        provider,
        evidence_at,
        expiry,
        explanation,
    )


def _validate_pairings(evidence: ScoringEvidence) -> None:
    if evidence.ioc_type is IOCType.CVE:
        if evidence.virustotal is not None or evidence.abuseipdb is not None:
            raise ScoringInputError("unsupported provider for CVE profile")
    else:
        if any(item is not None for item in (evidence.nvd, evidence.kev, evidence.epss)):
            raise ScoringInputError("CVE provider evidence supplied for non-CVE IOC")
        if evidence.virustotal is not None and evidence.ioc_type not in _VT_TYPES:
            raise ScoringInputError("VirusTotal unsupported for IOC type")
        if evidence.abuseipdb is not None and evidence.ioc_type not in _IP_TYPES:
            raise ScoringInputError("AbuseIPDB unsupported for IOC type")


def _range(value: Decimal, minimum: Decimal, maximum: Decimal, name: str) -> None:
    if (
        not isinstance(value, Decimal)
        or not value.is_finite()
        or value < minimum
        or value > maximum
    ):
        raise ScoringInputError(f"{name} is outside supported bounds")


def _aware(value: datetime | None, name: str) -> datetime:
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        raise ScoringInputError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)

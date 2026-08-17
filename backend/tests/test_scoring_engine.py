from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import TypedDict

import pytest

from app.ingestion.models import IOCType
from app.scoring import (
    AbuseIPDBEvidence,
    EPSSEvidence,
    EvidenceStatus,
    KEVEvidence,
    NVDEvidence,
    ScoringEvidence,
    ScoringInputError,
    VirusTotalEvidence,
    calculate_score,
    canonical_serialize,
    canonical_serialize_result,
)
from app.scoring.constants import CVE_WEIGHTS, PROVIDER_TTL_SECONDS
from app.scoring.models import Severity
from app.scoring.normalization import _json_value, round_and_clamp, severity_for

NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)


class _FreshKwargs(TypedDict):
    evidence_at: datetime
    expires_at: datetime


def _fresh_kwargs() -> _FreshKwargs:
    return {"evidence_at": NOW - timedelta(hours=1), "expires_at": NOW + timedelta(hours=1)}


def _cve(**kwargs: object) -> ScoringEvidence:
    return ScoringEvidence(IOCType.CVE, "CVE-2026-12345", NOW, **kwargs)  # type: ignore[arg-type]


def _vt(malicious: int = 0, suspicious: int = 0, total: int = 10) -> VirusTotalEvidence:
    return VirusTotalEvidence(
        malicious=malicious,
        suspicious=suspicious,
        total_analyzed_engines=total,
        **_fresh_kwargs(),
    )


def test_no_evidence_is_zero_and_emits_fixed_cve_profile() -> None:
    result = calculate_score(_cve())
    assert result.unrounded_total == Decimal("0")
    assert result.final_score == Decimal("0.00")
    assert result.severity is Severity.NONE
    assert [item.name for item in result.components] == [
        "nvd_cvss",
        "cisa_kev",
        "epss_probability",
        "epss_percentile",
        "independent_sources",
    ]
    for item in result.components[:-1]:
        assert item.status is EvidenceStatus.MISSING
        assert item.contribution == Decimal("0")
        assert item.provider is not None
        assert item.evidence_at is None
        assert item.effective_expiry is None
        assert "missing" in item.explanation.casefold()


@pytest.mark.parametrize(
    ("ioc_type", "value", "names"),
    [
        (IOCType.IPV4, "8.8.8.8", ["virustotal", "abuseipdb", "independent_sources"]),
        (IOCType.IPV6, "2001:4860:4860::8888", ["virustotal", "abuseipdb", "independent_sources"]),
        (IOCType.DOMAIN, "example.com", ["virustotal", "independent_sources"]),
        (IOCType.URL, "https://example.com/", ["virustotal", "independent_sources"]),
        (IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e", ["virustotal", "independent_sources"]),
        (IOCType.SHA1, "a" * 40, ["virustotal", "independent_sources"]),
        (IOCType.SHA256, "a" * 64, ["virustotal", "independent_sources"]),
        (IOCType.EMAIL, "analyst@example.com", ["independent_sources"]),
    ],
)
def test_every_ioc_has_a_fixed_ordered_profile(
    ioc_type: IOCType, value: str, names: list[str]
) -> None:
    result = calculate_score(ScoringEvidence(ioc_type, value, NOW))
    assert [item.name for item in result.components] == names


def test_maximum_cve_evidence_is_exactly_100() -> None:
    result = calculate_score(
        _cve(
            nvd=NVDEvidence(cvss_base_score=Decimal("10"), **_fresh_kwargs()),
            kev=KEVEvidence(known_exploited=True, **_fresh_kwargs()),
            epss=EPSSEvidence(probability=Decimal("1"), percentile=Decimal("1"), **_fresh_kwargs()),
            source_names=("a", "b", "c", "d", "e", "f"),
        )
    )
    assert result.unrounded_total == Decimal("100")
    assert result.final_score == Decimal("100.00")


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (EvidenceStatus.MISSING, EvidenceStatus.MISSING),
        (EvidenceStatus.FAILED, EvidenceStatus.FAILED),
        (EvidenceStatus.INVALID, EvidenceStatus.INVALID),
        (EvidenceStatus.UNSUPPORTED, EvidenceStatus.UNSUPPORTED),
    ],
)
def test_nonusable_statuses_contribute_zero(
    status: EvidenceStatus, expected: EvidenceStatus
) -> None:
    component = calculate_score(_cve(nvd=NVDEvidence(status=status))).components[0]
    assert component.status is expected
    assert component.contribution == Decimal("0")
    assert component.freshness_multiplier == Decimal("0")


def test_explicit_missing_and_absent_provider_are_semantically_equivalent() -> None:
    absent = calculate_score(_cve()).components[0]
    explicit = calculate_score(_cve(nvd=NVDEvidence(status=EvidenceStatus.MISSING))).components[0]
    assert absent == explicit


@pytest.mark.parametrize(
    ("expiry", "expected", "multiplier"),
    [
        (NOW + timedelta(microseconds=1), Decimal("35.00"), Decimal("1")),
        (NOW, Decimal("35.00"), Decimal("1")),
        (NOW - timedelta(microseconds=1), Decimal("17.50"), Decimal("0.50")),
        (NOW - timedelta(days=30), Decimal("17.50"), Decimal("0.50")),
        (NOW - timedelta(days=30, microseconds=1), Decimal("8.75"), Decimal("0.25")),
    ],
)
def test_freshness_boundaries(expiry: datetime, expected: Decimal, multiplier: Decimal) -> None:
    result = calculate_score(
        _cve(
            nvd=NVDEvidence(
                cvss_base_score=Decimal("10"),
                evidence_at=NOW - timedelta(days=40),
                expires_at=expiry,
            )
        )
    )
    assert result.final_score == expected
    assert result.components[0].freshness_multiplier == multiplier
    assert result.components[0].status is (
        EvidenceStatus.USABLE if multiplier == Decimal("1") else EvidenceStatus.STALE
    )


def test_missing_expiry_uses_immutable_provider_ttl() -> None:
    result = calculate_score(
        _cve(nvd=NVDEvidence(cvss_base_score=Decimal("10"), evidence_at=NOW - timedelta(hours=23)))
    )
    assert result.components[0].effective_expiry == NOW + timedelta(hours=1)
    assert result.final_score == Decimal("35.00")


@pytest.mark.parametrize(
    ("evidence_at", "multiplier"),
    [
        (NOW - timedelta(days=1), Decimal("1")),
        (NOW - timedelta(days=1, microseconds=1), Decimal("0.50")),
        (NOW - timedelta(days=31), Decimal("0.50")),
        (NOW - timedelta(days=31, microseconds=1), Decimal("0.25")),
    ],
)
def test_ttl_derived_expiry_uses_the_same_exact_freshness_boundaries(
    evidence_at: datetime, multiplier: Decimal
) -> None:
    component = calculate_score(
        _cve(nvd=NVDEvidence(cvss_base_score=Decimal("10"), evidence_at=evidence_at))
    ).components[0]
    assert component.effective_expiry == evidence_at + timedelta(days=1)
    assert component.freshness_multiplier == multiplier


def test_explicit_expiry_takes_precedence_over_provider_ttl() -> None:
    evidence_at = NOW - timedelta(days=60)
    explicit_expiry = NOW + timedelta(hours=1)
    component = calculate_score(
        _cve(
            nvd=NVDEvidence(
                cvss_base_score=Decimal("10"),
                evidence_at=evidence_at,
                expires_at=explicit_expiry,
            )
        )
    ).components[0]
    assert evidence_at + timedelta(days=1) < NOW
    assert component.effective_expiry == explicit_expiry
    assert component.freshness_multiplier == Decimal("1")


@pytest.mark.parametrize("mapping", [PROVIDER_TTL_SECONDS, CVE_WEIGHTS])
def test_constant_maps_are_immutable(mapping: object) -> None:
    with pytest.raises(TypeError):
        mapping["changed"] = 1  # type: ignore[index]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: NVDEvidence(cvss_base_score=5.0, **_fresh_kwargs()),  # type: ignore[arg-type]
        lambda: EPSSEvidence(
            probability=0.2,  # type: ignore[arg-type]
            percentile=Decimal("0.5"),
            **_fresh_kwargs(),
        ),
        lambda: EPSSEvidence(
            probability=Decimal("0.2"),
            percentile=0.5,  # type: ignore[arg-type]
            **_fresh_kwargs(),
        ),
        lambda: AbuseIPDBEvidence(
            abuse_confidence_score=50.0,  # type: ignore[arg-type]
            **_fresh_kwargs(),
        ),
    ],
)
def test_float_decimal_fields_are_rejected(factory: Callable[[], object]) -> None:
    with pytest.raises(ScoringInputError, match="finite Decimal"):
        factory()


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
@pytest.mark.parametrize(
    "factory",
    [
        lambda value: NVDEvidence(cvss_base_score=value, **_fresh_kwargs()),
        lambda value: EPSSEvidence(probability=value, percentile=Decimal("0.5"), **_fresh_kwargs()),
        lambda value: AbuseIPDBEvidence(abuse_confidence_score=value, **_fresh_kwargs()),
    ],
)
def test_nonfinite_decimal_fields_are_rejected(
    value: Decimal, factory: Callable[[Decimal], object]
) -> None:
    with pytest.raises(ScoringInputError, match="finite Decimal"):
        factory(value)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: NVDEvidence(evidence_at=NOW),
        lambda: KEVEvidence(evidence_at=NOW),
        lambda: EPSSEvidence(probability=Decimal("0.1"), evidence_at=NOW),
        lambda: VirusTotalEvidence(malicious=1, suspicious=0, evidence_at=NOW),
        lambda: AbuseIPDBEvidence(evidence_at=NOW),
    ],
)
def test_usable_evidence_requires_all_provider_values(factory: Callable[[], object]) -> None:
    with pytest.raises(ScoringInputError, match="requires all provider values"):
        factory()


@pytest.mark.parametrize("status", [EvidenceStatus.MISSING, EvidenceStatus.FAILED])
def test_nonusable_evidence_rejects_values_and_timestamps(status: EvidenceStatus) -> None:
    with pytest.raises(ScoringInputError, match="cannot carry"):
        NVDEvidence(status=status, cvss_base_score=Decimal("5"), evidence_at=NOW)


def test_input_stale_status_is_rejected() -> None:
    with pytest.raises(ScoringInputError, match="derived"):
        NVDEvidence(status=EvidenceStatus.STALE)


def test_source_names_must_be_an_immutable_tuple_of_strings() -> None:
    with pytest.raises(ScoringInputError):
        ScoringEvidence(IOCType.CVE, "CVE-2026-12345", NOW, source_names=["a"])  # type: ignore[arg-type]
    with pytest.raises(ScoringInputError):
        ScoringEvidence(IOCType.CVE, "CVE-2026-12345", NOW, source_names=("a", 1))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ScoringEvidence(IOCType.CVE, "CVE-2026-12345", datetime(2026, 1, 1)),
        lambda: NVDEvidence(cvss_base_score=Decimal("5"), evidence_at=datetime(2026, 1, 1)),
        lambda: NVDEvidence(
            cvss_base_score=Decimal("5"), evidence_at=NOW, expires_at=datetime(2026, 1, 1)
        ),
    ],
)
def test_naive_datetimes_are_rejected(factory: Callable[[], object]) -> None:
    with pytest.raises(ScoringInputError, match="timezone-aware"):
        factory()


def test_invalid_expiry_order_and_future_evidence_are_rejected() -> None:
    with pytest.raises(ScoringInputError, match="cannot precede"):
        NVDEvidence(cvss_base_score=Decimal("5"), evidence_at=NOW, expires_at=NOW - timedelta(1))
    with pytest.raises(ScoringInputError, match="future"):
        calculate_score(
            _cve(nvd=NVDEvidence(cvss_base_score=Decimal("5"), evidence_at=NOW + timedelta(1)))
        )


@pytest.mark.parametrize(
    "evidence",
    [
        _cve(virustotal=_vt()),
        _cve(abuseipdb=AbuseIPDBEvidence(abuse_confidence_score=Decimal("1"), **_fresh_kwargs())),
        ScoringEvidence(
            IOCType.DOMAIN, "example.com", NOW, nvd=NVDEvidence(status=EvidenceStatus.MISSING)
        ),
        ScoringEvidence(
            IOCType.DOMAIN, "example.com", NOW, kev=KEVEvidence(status=EvidenceStatus.MISSING)
        ),
        ScoringEvidence(
            IOCType.DOMAIN, "example.com", NOW, epss=EPSSEvidence(status=EvidenceStatus.MISSING)
        ),
        ScoringEvidence(
            IOCType.DOMAIN,
            "example.com",
            NOW,
            abuseipdb=AbuseIPDBEvidence(status=EvidenceStatus.MISSING),
        ),
        ScoringEvidence(
            IOCType.EMAIL,
            "a@example.com",
            NOW,
            virustotal=VirusTotalEvidence(status=EvidenceStatus.MISSING),
        ),
        ScoringEvidence(
            IOCType.EMAIL,
            "a@example.com",
            NOW,
            abuseipdb=AbuseIPDBEvidence(status=EvidenceStatus.MISSING),
        ),
    ],
)
def test_unsupported_provider_pairings_are_rejected(evidence: ScoringEvidence) -> None:
    with pytest.raises(ScoringInputError, match="unsupported|CVE provider"):
        calculate_score(evidence)


def test_virustotal_uses_malicious_plus_suspicious_over_total() -> None:
    result = calculate_score(
        ScoringEvidence(IOCType.DOMAIN, "example.com", NOW, virustotal=_vt(2, 3, 10))
    )
    assert result.final_score == Decimal("40.00")
    assert dict(result.components[0].raw_input) == {
        "malicious": 2,
        "suspicious": 3,
        "total_analyzed_engines": 10,
    }


def test_virustotal_zero_total_is_deterministic_when_all_counts_are_zero() -> None:
    result = calculate_score(
        ScoringEvidence(IOCType.DOMAIN, "example.com", NOW, virustotal=_vt(0, 0, 0))
    )
    assert result.components[0].normalized_value == Decimal("0")
    assert result.final_score == Decimal("0.00")


@pytest.mark.parametrize(
    ("malicious", "suspicious", "total"),
    [(-1, 0, 10), (0, -1, 10), (0, 0, -1), (11, 0, 10), (0, 11, 10), (6, 5, 10), (1, 0, 0)],
)
def test_virustotal_rejects_invalid_count_combinations(
    malicious: int, suspicious: int, total: int
) -> None:
    with pytest.raises(ScoringInputError, match="VirusTotal counts"):
        calculate_score(
            ScoringEvidence(
                IOCType.DOMAIN, "example.com", NOW, virustotal=_vt(malicious, suspicious, total)
            )
        )


@pytest.mark.parametrize("field", ["malicious", "suspicious", "total_analyzed_engines"])
def test_virustotal_rejects_booleans_as_counts(field: str) -> None:
    values: dict[str, object] = {"malicious": 0, "suspicious": 0, "total_analyzed_engines": 10}
    values[field] = True
    with pytest.raises(ScoringInputError, match="integers"):
        VirusTotalEvidence(**values, **_fresh_kwargs())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "evidence",
    [
        _cve(nvd=NVDEvidence(cvss_base_score=Decimal("10.1"), **_fresh_kwargs())),
        _cve(
            epss=EPSSEvidence(
                probability=Decimal("-0.1"), percentile=Decimal("0.5"), **_fresh_kwargs()
            )
        ),
        _cve(
            epss=EPSSEvidence(
                probability=Decimal("0.1"), percentile=Decimal("1.1"), **_fresh_kwargs()
            )
        ),
        ScoringEvidence(
            IOCType.IPV4,
            "8.8.8.8",
            NOW,
            abuseipdb=AbuseIPDBEvidence(abuse_confidence_score=Decimal("101"), **_fresh_kwargs()),
        ),
    ],
)
def test_provider_numeric_ranges_are_enforced(evidence: ScoringEvidence) -> None:
    with pytest.raises(ScoringInputError, match="bounds"):
        calculate_score(evidence)


@pytest.mark.parametrize(
    "value",
    ["10.0.0.1", "240.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "192.0.2.1"],
)
def test_all_nonpublic_ip_classes_receive_normal_source_corroboration(value: str) -> None:
    result = calculate_score(
        ScoringEvidence(IOCType.IPV4, value, NOW, source_names=("a", "b", "c", "d", "e"))
    )
    assert result.normalized_source_names == ("a", "b", "c", "d", "e")
    assert result.components[-1].normalized_value == Decimal("1")
    assert result.components[-1].contribution == Decimal("10")
    assert result.warnings == ()


def test_nonpublic_validation_status_alone_adds_no_score() -> None:
    result = calculate_score(ScoringEvidence(IOCType.IPV4, "10.0.0.1", NOW))
    assert result.final_score == Decimal("0.00")
    assert all(component.contribution == Decimal("0") for component in result.components)


def test_nonpublic_ip_provider_and_sources_use_normal_formulas() -> None:
    result = calculate_score(
        ScoringEvidence(
            IOCType.IPV4,
            "10.0.0.1",
            NOW,
            source_names=("a", "b", "c", "d", "e"),
            virustotal=_vt(malicious=5, suspicious=0, total=10),
        )
    )
    assert result.components[0].contribution == Decimal("20")
    assert result.components[-1].contribution == Decimal("10")
    assert result.final_score == Decimal("30.00")
    assert result.warnings == ()


@pytest.mark.parametrize(
    "sources",
    [(), ("only",), ("a", "b"), (" A ", "a", "b", "c", "d", "e", "f")],
)
def test_global_and_nonpublic_ips_use_identical_source_normalization(
    sources: tuple[str, ...],
) -> None:
    public = calculate_score(ScoringEvidence(IOCType.IPV4, "8.8.8.8", NOW, source_names=sources))
    nonpublic = calculate_score(
        ScoringEvidence(IOCType.IPV4, "10.0.0.1", NOW, source_names=sources)
    )
    assert public.normalized_source_names == nonpublic.normalized_source_names
    assert public.components[-1] == nonpublic.components[-1]
    assert public.final_score == nonpublic.final_score


def test_source_normalization_is_deterministic_deduplicated_and_capped() -> None:
    result = calculate_score(
        ScoringEvidence(
            IOCType.EMAIL,
            "analyst@example.com",
            NOW,
            source_names=(" Source A ", "source   a", "B", "c", "D", "E", "F", ""),
        )
    )
    assert result.normalized_source_names == ("b", "c", "d", "e", "f", "source a")
    assert result.final_score == Decimal("10.00")


@pytest.mark.parametrize("value", ["not-a-cve", "CVE-2026-12345 ", "cve-2026-12345"])
def test_invalid_or_noncanonical_ioc_values_are_rejected(value: str) -> None:
    with pytest.raises(ScoringInputError, match="invalid|canonical form"):
        calculate_score(ScoringEvidence(IOCType.CVE, value, NOW))


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        ("0", Severity.NONE),
        ("0.01", Severity.LOW),
        ("24.99", Severity.LOW),
        ("25", Severity.MEDIUM),
        ("49.99", Severity.MEDIUM),
        ("50", Severity.HIGH),
        ("74.99", Severity.HIGH),
        ("75", Severity.CRITICAL),
        ("100", Severity.CRITICAL),
    ],
)
def test_all_severity_boundaries(score: str, severity: Severity) -> None:
    assert severity_for(Decimal(score)) is severity


def test_final_total_is_clamped_and_rounded_once_only() -> None:
    assert round_and_clamp(Decimal("-1")) == Decimal("0.00")
    assert round_and_clamp(Decimal("101")) == Decimal("100.00")
    result = calculate_score(
        _cve(
            nvd=NVDEvidence(cvss_base_score=Decimal("3.333"), **_fresh_kwargs()),
            epss=EPSSEvidence(
                probability=Decimal("0.333"), percentile=Decimal("0"), **_fresh_kwargs()
            ),
        )
    )
    assert result.components[0].contribution == Decimal("11.6655")
    assert result.components[2].contribution == Decimal("4.995")
    assert result.unrounded_total == Decimal("16.6605")
    assert result.final_score == Decimal("16.66")


def test_canonical_serialization_is_repeatable_utc_and_alias_compatible() -> None:
    shifted = timezone(timedelta(hours=3))
    evidence = ScoringEvidence(
        IOCType.CVE,
        "CVE-2026-12345",
        NOW.astimezone(shifted),
        source_names=("Z", "a"),
        nvd=NVDEvidence(
            cvss_base_score=Decimal("3.3"),
            evidence_at=(NOW - timedelta(hours=1)).astimezone(shifted),
            expires_at=(NOW + timedelta(hours=1)).astimezone(shifted),
        ),
    )
    first = calculate_score(evidence)
    second = calculate_score(evidence)
    assert first == second
    assert first.as_of == NOW
    assert first.components[0].evidence_at == NOW - timedelta(hours=1)
    assert canonical_serialize_result(first) == canonical_serialize_result(second)
    assert canonical_serialize(first) == canonical_serialize_result(first)
    assert b'"as_of":"2026-08-11T12:00:00Z"' in canonical_serialize_result(first)
    assert b'"final_score":"14.05"' in canonical_serialize_result(first)


def test_serializer_rejects_float_and_unsupported_raw_values() -> None:
    for value in (1.2, object()):
        with pytest.raises(TypeError, match="unsupported"):
            _json_value(value)


def test_component_model_rejects_mutable_or_unsupported_nested_raw_values() -> None:
    component = calculate_score(_cve()).components[0]
    with pytest.raises(ScoringInputError, match="raw_input"):
        replace(component, raw_input=[["bad", 1]])  # type: ignore[arg-type]
    with pytest.raises(ScoringInputError, match="unsupported raw scalar"):
        replace(component, raw_input=(("bad", object()),))  # type: ignore[arg-type]


def test_inputs_results_and_nested_data_are_deeply_immutable() -> None:
    evidence = _cve()
    result = calculate_score(evidence)
    with pytest.raises(FrozenInstanceError):
        evidence.canonical_value = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.final_score = Decimal("1")  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.components[0].raw_input[0] = ("changed", 1)  # type: ignore[index]

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.models import (
    ArticleIndicator,
    Indicator,
    IndicatorEnrichment,
    IOCType,
    RawArticle,
)
from app.models.phase6b import ScoreComponentRecord, ScoreHistory
from app.scoring.engine import calculate_score
from app.scoring.evidence_snapshot import (
    build_canonical_evidence_payload,
    build_evidence_snapshot,
    canonical_serialize_evidence_payload,
)
from app.scoring.models import (
    AbuseIPDBEvidence,
    EPSSEvidence,
    EvidenceStatus,
    KEVEvidence,
    NVDEvidence,
    ScoringEvidence,
    ScoringInputError,
    VirusTotalEvidence,
)
from app.services.indicator_scoring import (
    IndicatorNotFoundError,
    calculate_and_persist_indicator_score,
    latest_provider_records,
    load_indicator_scoring_evidence,
    persist_indicator_score,
)

NOW = datetime(2026, 8, 23, 12, tzinfo=UTC)


@pytest.fixture()
def scoring_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _indicator(session: Session, ioc_type: IOCType, value: str) -> Indicator:
    row = Indicator(indicator_type=ioc_type, indicator_value=value)
    session.add(row)
    session.flush()
    return row


def _sources(session: Session, indicator: Indicator, *names: str | None) -> None:
    for position, name in enumerate(names):
        article = RawArticle(
            source_id=f"source-{indicator.id}-{position}",
            source_name=name,
            title=f"Article {position}",
            fetched_at=NOW,
            content_hash=f"score-{indicator.id}-{position}",
        )
        session.add(article)
        session.flush()
        session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=indicator.id))


def _enrichment(
    indicator: Indicator,
    provider: str,
    *,
    status: str = "success",
    normalized_data: dict[str, Any] | None = None,
    enriched_at: datetime = NOW - timedelta(hours=1),
    expires_at: datetime | None = NOW + timedelta(hours=1),
    record_id: int | None = None,
) -> IndicatorEnrichment:
    return IndicatorEnrichment(
        id=record_id,
        indicator_id=indicator.id,
        provider=provider,
        status=status,
        normalized_data=normalized_data or {},
        raw_response={"secret": "must-not-be-hashed"},
        enriched_at=enriched_at,
        expires_at=expires_at,
    )


def _add_cve_evidence(session: Session, indicator: Indicator) -> None:
    session.add_all(
        [
            _enrichment(indicator, "nvd", normalized_data={"cvss_score": 8.0}),
            _enrichment(
                indicator,
                "cisa_kev",
                normalized_data={"known_exploited": True},
            ),
            _enrichment(
                indicator,
                "epss",
                normalized_data={"epss": "0.1", "percentile": "0.2"},
            ),
        ]
    )


def _add_ip_evidence(session: Session, indicator: Indicator) -> None:
    session.add_all(
        [
            _enrichment(
                indicator,
                "virustotal",
                normalized_data={
                    "analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 7,
                    }
                },
            ),
            _enrichment(
                indicator,
                "abuseipdb",
                normalized_data={"abuse_confidence_score": 50.0},
            ),
        ]
    )


def test_loads_cve_evidence_sources_and_excludes_unsupported_provider(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.CVE, "CVE-2026-12345")
        _sources(session, indicator, " Source A ", "source   a", "B", "", None)
        _add_cve_evidence(session, indicator)
        session.add(
            _enrichment(
                indicator,
                "virustotal",
                normalized_data={"analysis_stats": {"malicious": 10}},
            )
        )
        session.commit()

        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        assert evidence.nvd == NVDEvidence(
            cvss_base_score=Decimal("8.0"),
            evidence_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )
        assert evidence.kev == KEVEvidence(
            known_exploited=True,
            evidence_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )
        assert evidence.epss == EPSSEvidence(
            probability=Decimal("0.1"),
            percentile=Decimal("0.2"),
            evidence_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )
        assert evidence.virustotal is None
        assert evidence.source_names == (" Source A ", "B", "source   a")


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected_providers"),
    [
        (IOCType.CVE, "CVE-2026-12345", {"nvd", "cisa_kev", "epss"}),
        (IOCType.IPV4, "8.8.8.8", {"virustotal", "abuseipdb"}),
        (IOCType.IPV6, "2001:4860:4860::8888", {"virustotal", "abuseipdb"}),
        (IOCType.DOMAIN, "example.com", {"virustotal"}),
        (IOCType.URL, "https://example.com/", {"virustotal"}),
        (IOCType.MD5, "d41d8cd98f00b204e9800998ecf8427e", {"virustotal"}),
        (IOCType.SHA1, "a" * 40, {"virustotal"}),
        (IOCType.SHA256, "a" * 64, {"virustotal"}),
        (IOCType.EMAIL, "analyst@example.com", set()),
    ],
)
def test_provider_applicability_for_every_ioc_family(
    scoring_factory: sessionmaker[Session],
    ioc_type: IOCType,
    value: str,
    expected_providers: set[str],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, ioc_type, value)
        for provider in ("nvd", "cisa_kev", "epss", "virustotal", "abuseipdb"):
            session.add(_enrichment(indicator, provider, status="not_found"))
        session.commit()

        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        actual = {
            provider
            for provider, item in (
                ("nvd", evidence.nvd),
                ("cisa_kev", evidence.kev),
                ("epss", evidence.epss),
                ("virustotal", evidence.virustotal),
                ("abuseipdb", evidence.abuseipdb),
            )
            if item is not None
        }
        assert actual == expected_providers


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("not_found", EvidenceStatus.MISSING),
        ("failed", EvidenceStatus.FAILED),
        ("rate_limited", EvidenceStatus.FAILED),
        ("auth_error", EvidenceStatus.FAILED),
        ("temporary_failure", EvidenceStatus.FAILED),
        ("permanent_failure", EvidenceStatus.INVALID),
        ("invalid", EvidenceStatus.INVALID),
        ("unsupported", EvidenceStatus.UNSUPPORTED),
        ("unknown_future_status", EvidenceStatus.INVALID),
    ],
)
def test_provider_status_mapping(
    scoring_factory: sessionmaker[Session], status: str, expected: EvidenceStatus
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.CVE, "CVE-2026-12345")
        session.add(_enrichment(indicator, "nvd", status=status))
        session.commit()
        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        assert evidence.nvd is not None
        assert evidence.nvd.status is expected
        assert evidence.nvd.evidence_at is None
        assert evidence.nvd.expires_at is None


def test_success_with_invalid_normalized_data_maps_to_invalid(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.CVE, "CVE-2026-12345")
        session.add(_enrichment(indicator, "nvd", normalized_data={"cvss_score": "NaN"}))
        session.commit()
        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        assert evidence.nvd == NVDEvidence(status=EvidenceStatus.INVALID)


def test_virustotal_uses_all_analysis_counts_and_abuseipdb_decimal(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.IPV4, "8.8.8.8")
        _add_ip_evidence(session, indicator)
        session.commit()
        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        assert evidence.virustotal == VirusTotalEvidence(
            malicious=2,
            suspicious=1,
            total_analyzed_engines=10,
            evidence_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )
        assert evidence.abuseipdb == AbuseIPDBEvidence(
            abuse_confidence_score=Decimal("50.0"),
            evidence_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
        )


def test_latest_provider_selection_uses_timestamp_then_primary_key() -> None:
    indicator = Indicator(id=1, indicator_type=IOCType.CVE, indicator_value="CVE-2026-12345")
    older = _enrichment(
        indicator,
        "nvd",
        enriched_at=NOW - timedelta(days=1),
        record_id=99,
    )
    lower_id = _enrichment(indicator, "nvd", enriched_at=NOW, record_id=1)
    higher_id = _enrichment(indicator, "nvd", enriched_at=NOW, record_id=2)
    unsupported = _enrichment(indicator, "virustotal", record_id=100)
    selected = latest_provider_records(
        [higher_id, older, unsupported, lower_id],
        ("nvd",),
    )
    assert selected == {"nvd": higher_id}


def test_evidence_loading_is_bounded_and_has_no_component_n_plus_one(
    scoring_factory: sessionmaker[Session],
) -> None:
    engine = scoring_factory.kw["bind"]
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.CVE, "CVE-2026-12345")
        _sources(session, indicator, "A", "B", "C")
        _add_cve_evidence(session, indicator)
        session.commit()
        statements = 0

        @event.listens_for(engine, "before_cursor_execute")
        def _count_queries(*_args: object) -> None:
            nonlocal statements
            statements += 1

        try:
            load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        finally:
            event.remove(engine, "before_cursor_execute", _count_queries)
        assert statements == 3


def test_missing_indicator_uses_typed_error(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session, pytest.raises(IndicatorNotFoundError):
        load_indicator_scoring_evidence(session, 999, as_of=NOW)


def test_contradictory_provider_timestamps_are_rejected(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.CVE, "CVE-2026-12345")
        session.add(
            _enrichment(
                indicator,
                "nvd",
                normalized_data={"cvss_score": 5.0},
                enriched_at=NOW,
                expires_at=NOW - timedelta(seconds=1),
            )
        )
        session.commit()
        with pytest.raises(ScoringInputError, match="cannot precede"):
            load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)


def _snapshot_evidence(*, as_of: datetime = NOW) -> ScoringEvidence:
    return ScoringEvidence(
        ioc_type=IOCType.CVE,
        canonical_value="CVE-2026-12345",
        as_of=as_of,
        source_names=(" Source B ", "source a", "SOURCE   A"),
        nvd=NVDEvidence(
            cvss_base_score=Decimal("8.25"),
            evidence_at=NOW - timedelta(hours=1),
        ),
        kev=KEVEvidence(status=EvidenceStatus.MISSING),
        epss=EPSSEvidence(
            probability=Decimal("0.1234567"),
            percentile=Decimal("0.7654321"),
            evidence_at=NOW - timedelta(hours=2),
            expires_at=NOW + timedelta(hours=2),
        ),
    )


def test_canonical_snapshot_is_repeatable_strict_and_contains_only_inputs() -> None:
    snapshot = build_evidence_snapshot(_snapshot_evidence())
    assert snapshot == build_evidence_snapshot(_snapshot_evidence())
    assert len(snapshot.evidence_hash) == 64
    assert snapshot.evidence_hash == snapshot.evidence_hash.lower()
    assert set(snapshot.evidence_hash) <= set("0123456789abcdef")
    payload = snapshot.payload()
    assert payload["source_names"] == ["source a", "source b"]
    serialized = snapshot.canonical_bytes.decode()
    for excluded in (
        "final_score",
        "severity",
        "unrounded_total",
        "contribution",
        "explanation",
        "score_history_id",
        "raw_response",
        "secret",
    ):
        assert excluded not in serialized
    nvd = cast_provider(payload, "nvd")
    assert nvd["raw_input"] == {"cvss_base_score": "8.25"}
    assert nvd["expires_at"] is None
    assert nvd["effective_expiry"] == "2026-08-24T11:00:00Z"


def cast_provider(payload: dict[str, Any], name: str) -> dict[str, Any]:
    providers = payload["providers"]
    assert isinstance(providers, list)
    return next(item for item in providers if item["provider"] == name)


def test_canonical_json_ignores_dictionary_insertion_order() -> None:
    first = {"z": {"b": 2, "a": 1}, "a": "value"}
    second = {"a": "value", "z": {"a": 1, "b": 2}}
    assert canonical_serialize_evidence_payload(first) == canonical_serialize_evidence_payload(
        second
    )


def test_equivalent_timezones_and_source_order_have_identical_hashes() -> None:
    shifted = timezone(timedelta(hours=3))
    first = _snapshot_evidence()
    second = replace(
        first,
        as_of=NOW.astimezone(shifted),
        source_names=("SOURCE   A", "source a", " Source B "),
        nvd=replace(
            cast(NVDEvidence, first.nvd),
            evidence_at=(NOW - timedelta(hours=1)).astimezone(shifted),
        ),
        epss=replace(
            cast(EPSSEvidence, first.epss),
            evidence_at=(NOW - timedelta(hours=2)).astimezone(shifted),
            expires_at=(NOW + timedelta(hours=2)).astimezone(shifted),
        ),
    )
    assert build_evidence_snapshot(first) == build_evidence_snapshot(second)


@pytest.mark.parametrize(
    "changed",
    [
        replace(_snapshot_evidence(), as_of=NOW + timedelta(seconds=1)),
        replace(_snapshot_evidence(), source_names=("source a", "source c")),
        replace(_snapshot_evidence(), kev=KEVEvidence(status=EvidenceStatus.FAILED)),
        replace(
            _snapshot_evidence(),
            nvd=replace(
                cast(NVDEvidence, _snapshot_evidence().nvd),
                cvss_base_score=Decimal("8.26"),
            ),
        ),
        replace(
            _snapshot_evidence(),
            nvd=replace(
                cast(NVDEvidence, _snapshot_evidence().nvd),
                evidence_at=NOW - timedelta(hours=1, seconds=1),
            ),
        ),
        replace(
            _snapshot_evidence(),
            epss=replace(
                cast(EPSSEvidence, _snapshot_evidence().epss),
                expires_at=NOW + timedelta(hours=3),
            ),
        ),
    ],
)
def test_meaningful_evidence_changes_change_the_hash(changed: ScoringEvidence) -> None:
    assert (
        build_evidence_snapshot(changed).evidence_hash
        != build_evidence_snapshot(_snapshot_evidence()).evidence_hash
    )


@pytest.mark.parametrize("value", [1.25, float("nan"), object()])
def test_canonical_serializer_rejects_floats_and_unsupported_values(value: object) -> None:
    with pytest.raises(TypeError, match="unsupported"):
        canonical_serialize_evidence_payload({"value": value})


def test_payload_and_snapshot_bytes_are_logically_identical() -> None:
    evidence = _snapshot_evidence()
    payload = build_canonical_evidence_payload(evidence)
    snapshot = build_evidence_snapshot(evidence)
    assert snapshot.canonical_bytes == canonical_serialize_evidence_payload(payload)
    assert snapshot.payload() == payload


def test_cve_end_to_end_create_reuse_append_and_component_order(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.CVE, "CVE-2026-12345")
        _sources(session, indicator, "A", "B")
        _add_cve_evidence(session, indicator)
        session.commit()

        first = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert first.created is True
        assert first.score_history.score == Decimal("64.00")
        assert first.score_history.target_kind == "indicator"
        assert first.score_history.indicator_id == indicator.id
        assert first.score_history.event_id is None
        assert [item.component_name for item in first.components] == [
            "nvd_cvss",
            "cisa_kev",
            "epss_probability",
            "epss_percentile",
            "independent_sources",
        ]
        assert first.components[0].weight == Decimal("35")
        assert first.components[0].contribution == Decimal("28.0")
        assert first.components[2].normalized_input == "0.1"

        second = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert second.created is False
        assert second.score_history.id == first.score_history.id
        assert second.evidence_hash == first.evidence_hash
        assert session.scalar(select(func.count(ScoreHistory.id))) == 1
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 5

        nvd = session.scalar(
            select(IndicatorEnrichment).where(IndicatorEnrichment.provider == "nvd")
        )
        assert nvd is not None
        nvd.normalized_data = {"cvss_score": 9.0}
        third = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert third.created is True
        assert third.score_history.id != first.score_history.id
        assert third.score_history.score == Decimal("67.50")
        assert session.scalar(select(func.count(ScoreHistory.id))) == 2
        older = session.get(ScoreHistory, first.score_history.id)
        assert older is not None and older.score == Decimal("64.00")


@pytest.mark.parametrize(
    ("ioc_type", "value", "private", "expected"),
    [
        (IOCType.IPV4, "8.8.8.8", False, Decimal("34.50")),
        (IOCType.IPV4, "10.0.0.1", True, Decimal("34.50")),
        (IOCType.DOMAIN, "example.com", False, Decimal("26.50")),
        (IOCType.EMAIL, "analyst@example.com", False, Decimal("10.00")),
    ],
)
def test_representative_ioc_scoring_integration(
    scoring_factory: sessionmaker[Session],
    ioc_type: IOCType,
    value: str,
    private: bool,
    expected: Decimal,
) -> None:
    del private
    with scoring_factory() as session:
        indicator = _indicator(session, ioc_type, value)
        names = ("A", "B") if ioc_type is not IOCType.EMAIL else ("A", "B", "C", "D", "E")
        _sources(session, indicator, *names)
        if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
            _add_ip_evidence(session, indicator)
        elif ioc_type is not IOCType.EMAIL:
            session.add(
                _enrichment(
                    indicator,
                    "virustotal",
                    normalized_data={
                        "analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 7}
                    },
                )
            )
        session.commit()
        persisted = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        assert persisted.score_history.score == expected


def test_missing_stale_explicit_and_ttl_derived_provider_evidence(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        missing = _indicator(session, IOCType.CVE, "CVE-2026-20001")
        stale = _indicator(session, IOCType.CVE, "CVE-2026-20002")
        explicit = _indicator(session, IOCType.CVE, "CVE-2026-20003")
        ttl = _indicator(session, IOCType.CVE, "CVE-2026-20004")
        session.add(
            _enrichment(
                stale,
                "nvd",
                normalized_data={"cvss_score": 10.0},
                enriched_at=NOW - timedelta(days=2),
                expires_at=NOW - timedelta(days=1),
            )
        )
        session.add(
            _enrichment(
                explicit,
                "nvd",
                normalized_data={"cvss_score": 10.0},
                enriched_at=NOW - timedelta(days=10),
                expires_at=NOW + timedelta(hours=1),
            )
        )
        session.add(
            _enrichment(
                ttl,
                "nvd",
                normalized_data={"cvss_score": 10.0},
                enriched_at=NOW - timedelta(hours=23),
                expires_at=None,
            )
        )
        session.commit()
        assert calculate_and_persist_indicator_score(
            session, missing.id, as_of=NOW
        ).score_history.score == Decimal("0.00")
        stale_result = calculate_and_persist_indicator_score(session, stale.id, as_of=NOW)
        assert stale_result.score_history.score == Decimal("17.50")
        assert stale_result.components[0].freshness_multiplier == Decimal("0.50")
        assert calculate_and_persist_indicator_score(
            session, explicit.id, as_of=NOW
        ).score_history.score == Decimal("35.00")
        assert calculate_and_persist_indicator_score(
            session, ttl.id, as_of=NOW
        ).score_history.score == Decimal("35.00")


def test_persistence_formula_version_unrelated_target_and_rollback(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        first_indicator = _indicator(session, IOCType.EMAIL, "first@example.com")
        second_indicator = _indicator(session, IOCType.EMAIL, "second@example.com")
        session.commit()
        # Python's SQLite driver uses legacy transaction control and does not begin
        # for SELECT. Start the outer database transaction explicitly before the
        # service's savepoint so this portable test can prove caller rollback.
        session.connection().exec_driver_sql("BEGIN")
        first_evidence = load_indicator_scoring_evidence(session, first_indicator.id, as_of=NOW)
        first_score = calculate_score(first_evidence)
        snapshot_v1 = build_evidence_snapshot(first_evidence)
        first = persist_indicator_score(
            session,
            indicator_id=first_indicator.id,
            score_result=first_score,
            snapshot=snapshot_v1,
        )
        same_hash_other_target = persist_indicator_score(
            session,
            indicator_id=second_indicator.id,
            score_result=first_score,
            snapshot=snapshot_v1,
        )
        score_v2 = replace(first_score, formula_version="phase6b-v2")
        snapshot_v2 = build_evidence_snapshot(first_evidence, formula_version="phase6b-v2")
        second_formula = persist_indicator_score(
            session,
            indicator_id=first_indicator.id,
            score_result=score_v2,
            snapshot=snapshot_v2,
        )
        assert (
            len(
                {
                    first.score_history.id,
                    same_hash_other_target.score_history.id,
                    second_formula.score_history.id,
                }
            )
            == 3
        )
        assert session.in_transaction()
        session.rollback()
        assert session.scalar(select(func.count(ScoreHistory.id))) == 0
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 0


def test_unrelated_integrity_error_is_reraised_without_partial_history(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.EMAIL, "analyst@example.com")
        session.commit()
        evidence = load_indicator_scoring_evidence(session, indicator.id, as_of=NOW)
        result = calculate_score(evidence)
        duplicate_components = replace(
            result,
            components=(result.components[0], result.components[0]),
        )
        with pytest.raises(IntegrityError):
            persist_indicator_score(
                session,
                indicator_id=indicator.id,
                score_result=duplicate_components,
                snapshot=build_evidence_snapshot(evidence),
            )
        assert session.scalar(select(func.count(ScoreHistory.id))) == 0


def test_delete_score_cascades_only_components(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session:
        indicator = _indicator(session, IOCType.EMAIL, "analyst@example.com")
        session.commit()
        persisted = calculate_and_persist_indicator_score(session, indicator.id, as_of=NOW)
        session.delete(persisted.score_history)
        session.flush()
        assert session.get(Indicator, indicator.id) is not None
        assert session.scalar(select(func.count(ScoreComponentRecord.component_name))) == 0

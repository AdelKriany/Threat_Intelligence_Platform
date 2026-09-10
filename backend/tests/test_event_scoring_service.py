from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.models import Indicator, IndicatorEnrichment, IOCType, RawArticle
from app.models.phase6b import (
    CorrelatedEvent,
    EventArticle,
    EventIndicator,
    ScoreHistory,
)
from app.scoring.event_evidence_snapshot import build_event_evidence_snapshot
from app.scoring.models import ScoringInputError
from app.scoring.normalization import severity_for
from app.services.event_scoring import (
    AmbiguousEventRelationshipsError,
    EventNotFoundError,
    InconsistentEventRelationshipsError,
    InvalidEventKeyError,
    InvalidStoredScoreEvidenceError,
    MissingMatchingCVERelationshipError,
    UnsupportedEventError,
    calculate_and_persist_event_score,
    load_event_scoring_evidence,
)

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


@pytest.fixture()
def scoring_factory() -> Generator[sessionmaker[Session], None, None]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _foreign_keys(connection: object, _record: object) -> None:
        cursor = connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def _event_and_cve(session: Session, suffix: str = "91001") -> tuple[CorrelatedEvent, Indicator]:
    cve = f"CVE-2026-{suffix}"
    event_row = CorrelatedEvent(
        event_key=f"cve:{cve}",
        title=f"{cve} vulnerability",
        rule_name="shared-cve",
        rule_version="v1",
        created_at=NOW,
        updated_at=NOW,
    )
    indicator = Indicator(indicator_type=IOCType.CVE, indicator_value=cve, created_at=NOW)
    session.add_all([event_row, indicator])
    session.flush()
    session.add(
        EventIndicator(
            event_id=event_row.id,
            indicator_id=indicator.id,
            reason="shared_canonical_cve",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
        )
    )
    return event_row, indicator


def _indicator_score(
    session: Session, indicator: Indicator, score: str, sequence: int, *, at: datetime = NOW
) -> ScoreHistory:
    row = ScoreHistory(
        target_kind="indicator",
        indicator_id=indicator.id,
        event_id=None,
        score=Decimal(score),
        severity=severity_for(Decimal(score)).value,
        formula_version="phase6b-v1",
        evidence_hash=f"{sequence:064x}",
        canonical_evidence={"private": True},
        calculated_at=at,
    )
    session.add(row)
    session.flush()
    return row


def _source(session: Session, event_row: CorrelatedEvent, name: str | None, sequence: int) -> None:
    article = RawArticle(
        source_id=f"event-score-{sequence}",
        source_name=name,
        title="Event evidence",
        fetched_at=NOW,
        content_hash=f"event-score-{sequence}",
    )
    session.add(article)
    session.flush()
    session.add(
        EventArticle(
            event_id=event_row.id,
            article_id=article.id,
            reason="shared_canonical_cve",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
        )
    )


def test_loads_matching_cve_latest_score_and_normalized_sources(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        event_row, indicator = _event_and_cve(session)
        lower = _indicator_score(session, indicator, "20", 1)
        latest = _indicator_score(session, indicator, "80", 2)
        for position, name in enumerate((" Source A ", "source   a", "SOURCE B", "", None)):
            _source(session, event_row, name, position)
        session.commit()

        evidence = load_event_scoring_evidence(session, event_row.id, as_of=NOW)
        assert latest.id > lower.id
        assert evidence.member_score is not None
        assert evidence.member_score.score_history_id == latest.id
        assert evidence.member_score.score == Decimal("80.00")
        assert evidence.source_names == ("source a", "source b")


def test_missing_member_score_is_allowed(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session:
        event_row, _ = _event_and_cve(session, "91002")
        session.commit()
        evidence = load_event_scoring_evidence(session, event_row.id, as_of=NOW)
        assert evidence.member_score is None
        persisted = calculate_and_persist_event_score(session, event_row.id, as_of=NOW)
        assert persisted.score_history.score == Decimal("0.00")


def test_latest_score_tie_breaks_by_history_id(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session:
        event_row, indicator = _event_and_cve(session, "91003")
        _indicator_score(session, indicator, "30", 3)
        latest = _indicator_score(session, indicator, "90", 4)
        session.commit()
        evidence = load_event_scoring_evidence(session, event_row.id, as_of=NOW)
        assert evidence.member_score is not None
        assert evidence.member_score.score_history_id == latest.id


def test_event_structure_errors_are_explicit(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session:
        with pytest.raises(EventNotFoundError):
            load_event_scoring_evidence(session, 999, as_of=NOW)
        unsupported, _ = _event_and_cve(session, "91004")
        unsupported.rule_version = "v2"
        invalid_key, _ = _event_and_cve(session, "91005")
        invalid_key.event_key = "not-a-cve"
        no_relation = CorrelatedEvent(
            event_key="cve:CVE-2026-91006",
            title="x",
            rule_name="shared-cve",
            rule_version="v1",
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(no_relation)
        session.commit()
        with pytest.raises(UnsupportedEventError):
            load_event_scoring_evidence(session, unsupported.id, as_of=NOW)
        with pytest.raises(InvalidEventKeyError):
            load_event_scoring_evidence(session, invalid_key.id, as_of=NOW)
        with pytest.raises(MissingMatchingCVERelationshipError):
            load_event_scoring_evidence(session, no_relation.id, as_of=NOW)


def test_conflicting_and_inconsistent_cves_fail(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session:
        ambiguous, _ = _event_and_cve(session, "91007")
        other = Indicator(indicator_type=IOCType.CVE, indicator_value="CVE-2026-91999")
        session.add(other)
        session.flush()
        session.add(
            EventIndicator(
                event_id=ambiguous.id,
                indicator_id=other.id,
                reason="x",
                rule_name="shared-cve",
                rule_version="v1",
                created_at=NOW,
            )
        )
        inconsistent, related = _event_and_cve(session, "91008")
        related.indicator_value = "CVE-2026-91888"
        session.commit()
        with pytest.raises(AmbiguousEventRelationshipsError):
            load_event_scoring_evidence(session, ambiguous.id, as_of=NOW)
        with pytest.raises(InconsistentEventRelationshipsError):
            load_event_scoring_evidence(session, inconsistent.id, as_of=NOW)


def test_snapshot_is_stable_complete_and_excludes_derived_or_private_data(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        event_row, indicator = _event_and_cve(session, "91009")
        _indicator_score(session, indicator, "80", 9)
        _source(session, event_row, " B ", 91)
        _source(session, event_row, "a", 92)
        session.commit()
        evidence = load_event_scoring_evidence(session, event_row.id, as_of=NOW)
        snapshot = build_event_evidence_snapshot(evidence)
        payload = snapshot.payload()
        assert payload["source_names"] == ["a", "b"]
        assert payload["member_indicator_score"]["score_history_id"] > 0
        assert len(snapshot.evidence_hash) == 64
        assert snapshot == build_event_evidence_snapshot(evidence)
        text = snapshot.canonical_bytes.decode()
        for excluded in (
            "final_score",
            "event_severity",
            "contribution",
            "normalized_value",
            "canonical_evidence",
            "private",
        ):
            assert excluded not in text


def test_identical_reuses_and_changed_member_source_or_context_appends(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        event_row, indicator = _event_and_cve(session, "91010")
        _indicator_score(session, indicator, "80", 10)
        _source(session, event_row, "a", 101)
        session.commit()
        first = calculate_and_persist_event_score(session, event_row.id, as_of=NOW)
        session.commit()
        same = calculate_and_persist_event_score(session, event_row.id, as_of=NOW)
        assert same.created is False and same.score_history.id == first.score_history.id
        _indicator_score(session, indicator, "90", 11)
        changed_member = calculate_and_persist_event_score(session, event_row.id, as_of=NOW)
        assert changed_member.created is True
        _source(session, event_row, "b", 102)
        changed_source = calculate_and_persist_event_score(session, event_row.id, as_of=NOW)
        assert changed_source.created is True
        changed_context = calculate_and_persist_event_score(
            session, event_row.id, as_of=NOW + timedelta(seconds=1)
        )
        assert changed_context.created is True
        session.commit()
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.event_id == event_row.id)
            )
            == 4
        )


def test_components_persist_exact_decimals_and_caller_rollback_preserves_inputs(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        event_row, indicator = _event_and_cve(session, "91011")
        member = _indicator_score(session, indicator, "80", 12)
        _source(session, event_row, "a", 111)
        _source(session, event_row, "b", 112)
        enrichment = IndicatorEnrichment(
            indicator_id=indicator.id,
            provider="nvd",
            status="success",
            normalized_data={"cvss_score": 8},
            enriched_at=NOW,
        )
        session.add(enrichment)
        session.commit()
        # Python's SQLite driver does not begin a transaction for SELECT in legacy
        # mode. Establish the caller-owned transaction before the service savepoint.
        session.connection().exec_driver_sql("BEGIN")
        persisted = calculate_and_persist_event_score(session, event_row.id, as_of=NOW)
        assert [row.contribution for row in persisted.components] == [
            Decimal("72.000000"),
            Decimal("2.500000"),
        ]
        session.rollback()
        assert session.get(CorrelatedEvent, event_row.id) is not None
        assert session.get(Indicator, indicator.id) is not None
        assert session.get(ScoreHistory, member.id) is not None
        assert session.get(IndicatorEnrichment, enrichment.id) is not None
        assert (
            session.scalar(
                select(func.count(ScoreHistory.id)).where(ScoreHistory.event_id == event_row.id)
            )
            == 0
        )


def test_as_of_requires_timezone(scoring_factory: sessionmaker[Session]) -> None:
    with scoring_factory() as session:
        event_row, _ = _event_and_cve(session, "91012")
        session.commit()
        with pytest.raises(ScoringInputError, match="timezone-aware"):
            calculate_and_persist_event_score(session, event_row.id, as_of=datetime(2026, 9, 10))


def test_invalid_latest_indicator_score_evidence_is_explicit(
    scoring_factory: sessionmaker[Session],
) -> None:
    with scoring_factory() as session:
        event_row, indicator = _event_and_cve(session, "91014")
        latest = _indicator_score(session, indicator, "80", 14)
        latest.severity = "low"
        session.commit()

        with pytest.raises(InvalidStoredScoreEvidenceError):
            load_event_scoring_evidence(session, event_row.id, as_of=NOW)


def test_unrelated_integrity_error_propagates(
    scoring_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    with scoring_factory() as session:
        event_row, _ = _event_and_cve(session, "91013")
        session.commit()

        def fail() -> None:
            raise IntegrityError("insert", {}, RuntimeError("different constraint"))

        monkeypatch.setattr(session, "flush", fail)
        with pytest.raises(IntegrityError):
            calculate_and_persist_event_score(session, event_row.id, as_of=NOW)

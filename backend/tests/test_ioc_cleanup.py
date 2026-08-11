from __future__ import annotations

import io
import json
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.ioc.audit import audit_indicators
from app.ingestion.ioc.cleanup import (
    CleanupSafetyError,
    execute_cleanup,
    load_reviewed_audit,
    main,
    sha256_file,
)
from app.ingestion.models import (
    ArticleIndicator,
    EPSSHistory,
    Indicator,
    IndicatorEnrichment,
    IOCType,
    RawArticle,
)


@pytest.fixture()
def cleanup_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _foreign_keys(connection: object, _record: object) -> None:
        cursor = connection.cursor()  # type: ignore[attr-defined]
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)
    with factory() as session:
        article = RawArticle(
            source_id="cleanup",
            title="cleanup",
            fetched_at=now,
            content_hash="cleanup",
        )
        valid = Indicator(indicator_type=IOCType.DOMAIN, indicator_value="example.com")
        invalid = Indicator(indicator_type=IOCType.DOMAIN, indicator_value="malwares.jpg")
        suspicious = Indicator(indicator_type=IOCType.IPV4, indicator_value="127.0.0.1")
        other_invalid = Indicator(
            indicator_type=IOCType.DOMAIN,
            indicator_value="bad label.example",
        )
        session.add_all([article, valid, invalid, suspicious, other_invalid])
        session.flush()
        session.add(ArticleIndicator(raw_article_id=article.id, indicator_id=invalid.id))
        session.add(
            IndicatorEnrichment(
                indicator_id=invalid.id,
                provider="test",
                status="success",
                normalized_data={},
                enriched_at=now,
            )
        )
        session.add(
            EPSSHistory(
                indicator_id=invalid.id,
                epss=Decimal("0.1000000"),
                percentile=Decimal("0.5000000"),
                model_date=date.today(),
                fetched_at=now,
            )
        )
        session.commit()
    return factory


def _write_reviewed_audit(
    factory: sessionmaker[Session], directory: Path
) -> tuple[Path, Path, list[tuple[int, str]]]:
    with factory() as session:
        report = audit_indicators(session, sample_limit=100)
    # Review policy authorizes only domain_file_extension. Remove the deliberately
    # unrelated invalid test record from this synthetic reviewed report.
    target = next(group for group in report["groups"] if group["reason"] == "domain_file_extension")
    report["groups"] = [
        group for group in report["groups"] if group["status"] != "invalid" or group is target
    ]
    report["counts"]["invalid"] = target["count"]
    report["total"] = sum(report["counts"].values())
    audit_path = directory / "reviewed.json"
    audit_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    checksum_path = directory / "reviewed.json.sha256"
    checksum_path.write_text(f"{sha256_file(audit_path)}  {audit_path.name}\n", encoding="utf-8")
    candidates = sorted((sample["id"], sample["value"]) for sample in target["samples"])
    return audit_path, checksum_path, candidates


def _counts(session: Session) -> tuple[int, int, int, int]:
    return (
        int(session.scalar(select(func.count(Indicator.id))) or 0),
        int(session.scalar(select(func.count()).select_from(ArticleIndicator)) or 0),
        int(session.scalar(select(func.count(IndicatorEnrichment.id))) or 0),
        int(session.scalar(select(func.count(EPSSHistory.id))) or 0),
    )


def test_dry_run_is_deterministic_and_changes_nothing(
    cleanup_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    audit_path, checksum_path, reviewed = _write_reviewed_audit(cleanup_factory, tmp_path)
    assert load_reviewed_audit(audit_path, checksum_path) == reviewed
    with cleanup_factory() as session:
        before = _counts(session)
        first = execute_cleanup(
            session,
            reviewed_candidates=reviewed,
            expected_count=1,
            apply=False,
        )
        second = execute_cleanup(
            session,
            reviewed_candidates=reviewed,
            expected_count=1,
            apply=False,
        )
        assert _counts(session) == before
    assert first == second
    assert first["candidates"] == 1
    assert first["article_relationships"] == 1
    assert first["enrichments"] == 1
    assert first["epss_history"] == 1


def test_apply_requires_manifest_checksum_and_expected_count(
    cleanup_factory: sessionmaker[Session],
) -> None:
    stderr = io.StringIO()
    assert main(["--apply"], session_factory=cleanup_factory, stderr=stderr) == 2
    assert "requires" in stderr.getvalue()


def test_checksum_and_expected_count_mismatches_abort(
    cleanup_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    audit_path, checksum_path, reviewed = _write_reviewed_audit(cleanup_factory, tmp_path)
    checksum_path.write_text("0" * 64, encoding="utf-8")
    with pytest.raises(CleanupSafetyError, match="checksum mismatch"):
        load_reviewed_audit(audit_path, checksum_path)

    with cleanup_factory() as session, pytest.raises(CleanupSafetyError, match="expected 2"):
        execute_cleanup(
            session,
            reviewed_candidates=reviewed,
            expected_count=2,
            apply=True,
        )


@pytest.mark.parametrize("change", ["changed", "missing", "newly_valid"])
def test_changed_missing_or_newly_valid_candidate_aborts(
    cleanup_factory: sessionmaker[Session], tmp_path: Path, change: str
) -> None:
    _audit, _checksum, reviewed = _write_reviewed_audit(cleanup_factory, tmp_path)
    candidate_id = reviewed[0][0]
    with cleanup_factory() as session:
        candidate = session.get(Indicator, candidate_id)
        assert candidate is not None
        if change == "changed":
            candidate.indicator_value = "changed.gif"
        elif change == "newly_valid":
            candidate.indicator_value = "example.net"
        else:
            session.delete(candidate)
        session.commit()

    with cleanup_factory() as session, pytest.raises(CleanupSafetyError):
        execute_cleanup(
            session,
            reviewed_candidates=reviewed,
            expected_count=1,
            apply=True,
        )


def test_apply_removes_only_approved_rows_and_dependencies(
    cleanup_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    _audit, _checksum, reviewed = _write_reviewed_audit(cleanup_factory, tmp_path)
    with cleanup_factory() as session:
        summary = execute_cleanup(
            session,
            reviewed_candidates=reviewed,
            expected_count=1,
            apply=True,
        )
    assert summary["indicators_deleted"] == 1
    assert summary["article_relationships_deleted"] == 1
    assert summary["enrichments_deleted"] == 1
    assert summary["epss_history_deleted"] == 1

    with cleanup_factory() as session:
        values = set(session.scalars(select(Indicator.indicator_value)))
        assert "malwares.jpg" not in values
        assert "example.com" in values
        assert "127.0.0.1" in values
        assert "bad label.example" in values
        assert _counts(session) == (3, 0, 0, 0)
        report = audit_indicators(session, sample_limit=100)
        assert not any(group["reason"] == "domain_file_extension" for group in report["groups"])


def test_forced_failure_rolls_back_every_delete(
    cleanup_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    _audit, _checksum, reviewed = _write_reviewed_audit(cleanup_factory, tmp_path)
    with cleanup_factory() as session:
        before = _counts(session)

        def fail() -> None:
            raise RuntimeError("forced")

        with pytest.raises(RuntimeError, match="forced"):
            execute_cleanup(
                session,
                reviewed_candidates=reviewed,
                expected_count=1,
                apply=True,
                before_commit=fail,
            )
    with cleanup_factory() as session:
        assert _counts(session) == before


def test_second_apply_aborts_without_unintended_deletion(
    cleanup_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    _audit, _checksum, reviewed = _write_reviewed_audit(cleanup_factory, tmp_path)
    with cleanup_factory() as session:
        execute_cleanup(
            session,
            reviewed_candidates=reviewed,
            expected_count=1,
            apply=True,
        )
    with cleanup_factory() as session:
        before = _counts(session)
        with pytest.raises(CleanupSafetyError):
            execute_cleanup(
                session,
                reviewed_candidates=reviewed,
                expected_count=1,
                apply=True,
            )
    with cleanup_factory() as session:
        assert _counts(session) == before

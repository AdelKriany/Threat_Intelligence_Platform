"""Transaction-safe cleanup of reviewed filename-like domain false positives."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.database.session import SessionLocal
from app.ingestion.ioc.validators import (
    ValidationReason,
    ValidationStatus,
    validate_indicator,
)
from app.ingestion.models import (
    ArticleIndicator,
    EPSSHistory,
    Indicator,
    IndicatorEnrichment,
    IOCType,
)

Candidate = tuple[int, str]


class CleanupSafetyError(RuntimeError):
    """Raised when a cleanup invariant does not match the reviewed state."""


def _rowcount(result: Any) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_expected_checksum(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip().split()
    if not value or len(value[0]) != 64:
        raise CleanupSafetyError("audit checksum file is malformed")
    return value[0].lower()


def load_reviewed_audit(audit_path: Path, checksum_path: Path) -> list[Candidate]:
    """Verify a reviewed audit and return its exact ordered cleanup manifest."""

    actual_checksum = sha256_file(audit_path)
    expected_checksum = _read_expected_checksum(checksum_path)
    if actual_checksum != expected_checksum:
        raise CleanupSafetyError("audit SHA-256 checksum mismatch")

    try:
        report = json.loads(audit_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CleanupSafetyError(f"cannot read reviewed audit: {exc}") from exc
    if report.get("read_only") is not True or not isinstance(report.get("groups"), list):
        raise CleanupSafetyError("reviewed audit structure is invalid")

    invalid_count = report.get("counts", {}).get("invalid")
    target_groups = [
        group
        for group in report["groups"]
        if group.get("status") == ValidationStatus.INVALID.value
        and group.get("indicator_type") == IOCType.DOMAIN.value
        and group.get("reason") == ValidationReason.DOMAIN_FILE_EXTENSION.value
    ]
    other_invalid = [
        group
        for group in report["groups"]
        if group.get("status") == ValidationStatus.INVALID.value and group not in target_groups
    ]
    if len(target_groups) != 1 or other_invalid:
        raise CleanupSafetyError("audit contains unapproved invalid groups")
    group = target_groups[0]
    samples = group.get("samples")
    if not isinstance(samples, list) or group.get("count") != len(samples):
        raise CleanupSafetyError("audit does not contain every reviewed candidate")
    if invalid_count != group.get("count"):
        raise CleanupSafetyError("audit invalid count includes unapproved candidates")

    candidates: list[Candidate] = []
    seen_ids: set[int] = set()
    for sample in samples:
        indicator_id = sample.get("id") if isinstance(sample, dict) else None
        value = sample.get("value") if isinstance(sample, dict) else None
        if not isinstance(indicator_id, int) or not isinstance(value, str):
            raise CleanupSafetyError("audit candidate structure is invalid")
        if indicator_id in seen_ids:
            raise CleanupSafetyError("audit contains duplicate candidate IDs")
        seen_ids.add(indicator_id)
        candidates.append((indicator_id, value))
    return sorted(candidates)


def _current_candidates(session: Session, batch_size: int) -> list[Candidate]:
    statement = (
        select(Indicator.id, Indicator.indicator_type, Indicator.indicator_value)
        .order_by(Indicator.id)
        .execution_options(yield_per=batch_size)
    )
    candidates: list[Candidate] = []
    for indicator_id, indicator_type, indicator_value in session.execute(statement):
        validation = validate_indicator(indicator_type, indicator_value)
        if (
            validation.status is ValidationStatus.INVALID
            and validation.reason is ValidationReason.DOMAIN_FILE_EXTENSION
            and indicator_type is IOCType.DOMAIN
        ):
            candidates.append((indicator_id, indicator_value))
    return candidates


def _count_references(session: Session, candidate_ids: list[int]) -> dict[str, int]:
    if not candidate_ids:
        return {"article_relationships": 0, "enrichments": 0, "epss_history": 0}
    return {
        "article_relationships": int(
            session.scalar(
                select(func.count())
                .select_from(ArticleIndicator)
                .where(ArticleIndicator.indicator_id.in_(candidate_ids))
            )
            or 0
        ),
        "enrichments": int(
            session.scalar(
                select(func.count())
                .select_from(IndicatorEnrichment)
                .where(IndicatorEnrichment.indicator_id.in_(candidate_ids))
            )
            or 0
        ),
        "epss_history": int(
            session.scalar(
                select(func.count())
                .select_from(EPSSHistory)
                .where(EPSSHistory.indicator_id.in_(candidate_ids))
            )
            or 0
        ),
    }


def execute_cleanup(
    session: Session,
    *,
    reviewed_candidates: list[Candidate] | None,
    expected_count: int | None,
    apply: bool,
    batch_size: int = 500,
    before_commit: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Validate all invariants, optionally delete explicitly, and commit once."""

    try:
        current = _current_candidates(session, batch_size)
        candidates = reviewed_candidates if reviewed_candidates is not None else current
        if expected_count is not None and len(current) != expected_count:
            raise CleanupSafetyError(
                f"current candidate count {len(current)} does not match expected {expected_count}"
            )
        if reviewed_candidates is not None and current != reviewed_candidates:
            raise CleanupSafetyError("current candidates differ from the reviewed audit")
        if apply and (reviewed_candidates is None or expected_count is None):
            raise CleanupSafetyError("apply requires reviewed candidates and expected count")

        candidate_ids = [indicator_id for indicator_id, _value in candidates]
        if apply and candidate_ids:
            locked = list(
                session.execute(
                    select(Indicator.id, Indicator.indicator_type, Indicator.indicator_value)
                    .where(Indicator.id.in_(candidate_ids))
                    .order_by(Indicator.id)
                    .with_for_update()
                )
            )
            locked_manifest = [(row.id, row.indicator_value) for row in locked]
            if locked_manifest != candidates:
                raise CleanupSafetyError("candidate missing or changed while acquiring locks")
            for row in locked:
                validation = validate_indicator(row.indicator_type, row.indicator_value)
                if not (
                    row.indicator_type is IOCType.DOMAIN
                    and validation.status is ValidationStatus.INVALID
                    and validation.reason is ValidationReason.DOMAIN_FILE_EXTENSION
                ):
                    raise CleanupSafetyError(f"candidate {row.id} no longer matches cleanup policy")

        references = _count_references(session, candidate_ids)
        summary: dict[str, Any] = {
            "mode": "apply" if apply else "dry-run",
            "candidates": len(candidates),
            **references,
            "indicators_deleted": 0,
            "article_relationships_deleted": 0,
            "enrichments_deleted": 0,
            "epss_history_deleted": 0,
        }
        if not apply:
            session.rollback()
            return summary

        summary["epss_history_deleted"] = _rowcount(
            session.execute(delete(EPSSHistory).where(EPSSHistory.indicator_id.in_(candidate_ids)))
        )
        summary["enrichments_deleted"] = _rowcount(
            session.execute(
                delete(IndicatorEnrichment).where(
                    IndicatorEnrichment.indicator_id.in_(candidate_ids)
                )
            )
        )
        summary["article_relationships_deleted"] = _rowcount(
            session.execute(
                delete(ArticleIndicator).where(ArticleIndicator.indicator_id.in_(candidate_ids))
            )
        )
        summary["indicators_deleted"] = _rowcount(
            session.execute(delete(Indicator).where(Indicator.id.in_(candidate_ids)))
        )
        if before_commit is not None:
            before_commit()
        session.commit()
        return summary
    except Exception:
        session.rollback()
        raise


def _write_summary(summary: dict[str, Any], stream: TextIO) -> None:
    stream.write(" ".join(f"{key}={value}" for key, value in summary.items()) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Validate and count only (default).")
    mode.add_argument("--apply", action="store_true", help="Apply the reviewed cleanup.")
    parser.add_argument("--expected-count", type=int)
    parser.add_argument("--audit-file", type=Path)
    parser.add_argument("--audit-sha256", type=Path)
    parser.add_argument("--batch-size", type=int, default=500)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: sessionmaker[Session] = SessionLocal,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = build_parser().parse_args(argv)
    if args.batch_size < 1 or (args.expected_count is not None and args.expected_count < 0):
        stderr.write("cleanup arguments must be non-negative\n")
        return 2
    if args.apply and (
        args.expected_count is None or args.audit_file is None or args.audit_sha256 is None
    ):
        stderr.write("--apply requires --expected-count, --audit-file, and --audit-sha256\n")
        return 2
    if (args.audit_file is None) != (args.audit_sha256 is None):
        stderr.write("audit file and checksum must be supplied together\n")
        return 2

    try:
        reviewed = (
            load_reviewed_audit(args.audit_file, args.audit_sha256)
            if args.audit_file is not None and args.audit_sha256 is not None
            else None
        )
        with session_factory() as session:
            summary = execute_cleanup(
                session,
                reviewed_candidates=reviewed,
                expected_count=args.expected_count,
                apply=args.apply,
                batch_size=args.batch_size,
            )
    except Exception as exc:
        stderr.write(f"IOC cleanup aborted: {type(exc).__name__}: {exc}\n")
        return 2

    _write_summary(summary, stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

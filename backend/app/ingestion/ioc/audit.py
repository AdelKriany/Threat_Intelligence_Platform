"""Read-only audit of stored canonical indicators."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from typing import Any, TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.database.session import SessionLocal
from app.ingestion.ioc.validators import ValidationStatus, validate_indicator
from app.ingestion.models import Indicator


def audit_indicators(
    session: Session,
    *,
    sample_limit: int = 5,
    batch_size: int = 500,
) -> dict[str, Any]:
    """Return a deterministic report without mutating or loading the full table."""

    if sample_limit < 0 or batch_size < 1:
        raise ValueError("sample_limit must be >= 0 and batch_size must be >= 1")

    counts: Counter[str] = Counter({status.value: 0 for status in ValidationStatus})
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    statement = (
        select(Indicator.id, Indicator.indicator_type, Indicator.indicator_value)
        .order_by(Indicator.id)
        .execution_options(yield_per=batch_size)
    )
    for indicator_id, indicator_type, indicator_value in session.execute(statement):
        result = validate_indicator(indicator_type, indicator_value)
        counts[result.status.value] += 1
        if result.status is ValidationStatus.VALID:
            continue
        key = (result.status.value, indicator_type.value, result.reason.value)
        group = grouped.setdefault(
            key,
            {
                "status": result.status.value,
                "indicator_type": indicator_type.value,
                "reason": result.reason.value,
                "count": 0,
                "samples": [],
            },
        )
        group["count"] += 1
        if len(group["samples"]) < sample_limit:
            group["samples"].append({"id": indicator_id, "value": indicator_value})

    return {
        "total": sum(counts.values()),
        "counts": {status.value: counts[status.value] for status in ValidationStatus},
        "groups": [grouped[key] for key in sorted(grouped)],
        "read_only": True,
        "sample_limit": sample_limit,
    }


def _write_summary(report: dict[str, Any], stream: TextIO) -> None:
    counts = report["counts"]
    stream.write(
        f"total={report['total']} valid={counts['valid']} "
        f"invalid={counts['invalid']} suspicious={counts['suspicious']}\n"
    )
    for group in report["groups"]:
        stream.write(
            f"{group['status']} type={group['indicator_type']} "
            f"reason={group['reason']} count={group['count']}\n"
        )
        for sample in group["samples"]:
            stream.write(f"  id={sample['id']} value={sample['value']}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("summary", "json"), default="summary")
    parser.add_argument("--sample-limit", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument(
        "--fail-on",
        choices=("invalid", "suspicious", "any"),
        help="Optional CI failure policy; default audit always exits zero.",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: sessionmaker[Session] = SessionLocal,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        with session_factory() as session:
            report = audit_indicators(
                session,
                sample_limit=args.sample_limit,
                batch_size=args.batch_size,
            )
    except Exception as exc:
        stderr.write(f"IOC audit failed: {type(exc).__name__}: {exc}\n")
        return 2

    if args.format == "json":
        stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        _write_summary(report, stdout)

    counts = report["counts"]
    should_fail = (
        (args.fail_on == "invalid" and counts["invalid"] > 0)
        or (args.fail_on == "suspicious" and counts["suspicious"] > 0)
        or (args.fail_on == "any" and (counts["invalid"] > 0 or counts["suspicious"] > 0))
    )
    return 1 if should_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import hashlib
from datetime import UTC

from app.scoring.event_engine import EVENT_FORMULA_VERSION
from app.scoring.event_models import EventScoringEvidence
from app.scoring.evidence_snapshot import (
    CanonicalEvidenceSnapshot,
    canonical_serialize_evidence_payload,
)
from app.scoring.normalization import normalize_sources


def build_event_evidence_snapshot(evidence: EventScoringEvidence) -> CanonicalEvidenceSnapshot:
    member = evidence.member_score
    member_payload: dict[str, object] = {"status": "missing"}
    if member is not None:
        member_payload = {
            "calculated_at": member.calculated_at.astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "evidence_hash": member.evidence_hash,
            "formula_version": member.formula_version,
            "indicator_id": member.indicator_id,
            "score": format(member.score, "f"),
            "score_history_id": member.score_history_id,
            "severity": member.severity.value,
            "status": "present",
        }
    payload = {
        "as_of": evidence.as_of.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "canonical_cve": {
            "indicator_id": evidence.cve_indicator_id,
            "value": evidence.canonical_cve,
        },
        "event": {
            "event_key": evidence.event_key,
            "id": evidence.event_id,
            "rule_name": evidence.rule_name,
            "rule_version": evidence.rule_version,
        },
        "formula_version": EVENT_FORMULA_VERSION,
        "member_indicator_score": member_payload,
        "source_names": list(normalize_sources(evidence.source_names)),
    }
    canonical_bytes = canonical_serialize_evidence_payload(payload)
    return CanonicalEvidenceSnapshot(
        canonical_bytes=canonical_bytes,
        evidence_hash=hashlib.sha256(canonical_bytes).hexdigest(),
    )


__all__ = ["build_event_evidence_snapshot"]

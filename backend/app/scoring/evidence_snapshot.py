from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any

from app.ingestion.models import IOCType
from app.scoring.constants import FORMULA_VERSION, PROVIDER_TTL_SECONDS
from app.scoring.models import EvidenceBase, EvidenceStatus, ScoringEvidence, ScoringInputError
from app.scoring.normalization import normalize_sources

_PROVIDER_ORDER: dict[IOCType, tuple[str, ...]] = {
    IOCType.CVE: ("nvd", "cisa_kev", "epss"),
    IOCType.IPV4: ("virustotal", "abuseipdb"),
    IOCType.IPV6: ("virustotal", "abuseipdb"),
    IOCType.DOMAIN: ("virustotal",),
    IOCType.URL: ("virustotal",),
    IOCType.MD5: ("virustotal",),
    IOCType.SHA1: ("virustotal",),
    IOCType.SHA256: ("virustotal",),
    IOCType.EMAIL: (),
}


@dataclass(frozen=True, slots=True)
class CanonicalEvidenceSnapshot:
    canonical_bytes: bytes
    evidence_hash: str

    def payload(self) -> dict[str, Any]:
        """Return a fresh JSON-compatible payload identical to the hashed document."""

        value = json.loads(self.canonical_bytes)
        if not isinstance(value, dict):  # pragma: no cover - constructor guarantees this
            raise TypeError("canonical evidence payload must be an object")
        return value


def applicable_provider_names(ioc_type: IOCType) -> tuple[str, ...]:
    return _PROVIDER_ORDER[ioc_type]


def build_canonical_evidence_payload(
    evidence: ScoringEvidence,
    *,
    formula_version: str = FORMULA_VERSION,
) -> dict[str, Any]:
    """Build only the immutable calculation inputs used for evidence identity."""

    providers = [
        _provider_payload(name, _provider_evidence(evidence, name))
        for name in applicable_provider_names(evidence.ioc_type)
    ]
    raw_payload = {
        "as_of": _utc_text(evidence.as_of),
        "canonical_value": evidence.canonical_value,
        "formula_version": formula_version,
        "ioc_type": evidence.ioc_type.value,
        "providers": providers,
        "source_names": list(normalize_sources(evidence.source_names)),
    }
    payload = _canonical_value(raw_payload)
    if not isinstance(payload, dict):  # pragma: no cover - constructed as an object above
        raise TypeError("canonical evidence payload must be an object")
    return payload


def canonical_serialize_evidence_payload(payload: Mapping[str, object]) -> bytes:
    """Return strict canonical JSON bytes for evidence hashing."""

    canonical = _canonical_value(payload)
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_evidence_snapshot(
    evidence: ScoringEvidence,
    *,
    formula_version: str = FORMULA_VERSION,
) -> CanonicalEvidenceSnapshot:
    payload = build_canonical_evidence_payload(evidence, formula_version=formula_version)
    canonical_bytes = canonical_serialize_evidence_payload(payload)
    return CanonicalEvidenceSnapshot(
        canonical_bytes=canonical_bytes,
        evidence_hash=hashlib.sha256(canonical_bytes).hexdigest(),
    )


def _provider_evidence(evidence: ScoringEvidence, provider: str) -> EvidenceBase | None:
    if provider == "nvd":
        return evidence.nvd
    if provider == "cisa_kev":
        return evidence.kev
    if provider == "epss":
        return evidence.epss
    if provider == "virustotal":
        return evidence.virustotal
    if provider == "abuseipdb":
        return evidence.abuseipdb
    raise ScoringInputError(f"unsupported scoring provider: {provider}")


def _provider_payload(provider: str, item: EvidenceBase | None) -> dict[str, Any]:
    status = item.status if item is not None else EvidenceStatus.MISSING
    evidence_at = item.evidence_at if item is not None else None
    explicit_expiry = item.expires_at if item is not None else None
    effective_expiry = None
    if status is EvidenceStatus.USABLE and evidence_at is not None:
        effective_expiry = explicit_expiry or evidence_at + timedelta(
            seconds=PROVIDER_TTL_SECONDS[provider]
        )
    return {
        "effective_expiry": _utc_text(effective_expiry),
        "evidence_at": _utc_text(evidence_at),
        "expires_at": _utc_text(explicit_expiry),
        "provider": provider,
        "raw_input": _raw_provider_input(provider, item),
        "status": status.value,
    }


def _raw_provider_input(provider: str, item: EvidenceBase | None) -> dict[str, object]:
    if provider == "nvd":
        return {"cvss_base_score": getattr(item, "cvss_base_score", None)}
    if provider == "cisa_kev":
        return {"known_exploited": getattr(item, "known_exploited", None)}
    if provider == "epss":
        return {
            "percentile": getattr(item, "percentile", None),
            "probability": getattr(item, "probability", None),
        }
    if provider == "virustotal":
        return {
            "malicious": getattr(item, "malicious", None),
            "suspicious": getattr(item, "suspicious", None),
            "total_analyzed_engines": getattr(item, "total_analyzed_engines", None),
        }
    if provider == "abuseipdb":
        return {"abuse_confidence_score": getattr(item, "abuse_confidence_score", None)}
    raise ScoringInputError(f"unsupported scoring provider: {provider}")


def _canonical_value(value: object) -> Any:
    if value is None or type(value) in {str, int, bool}:
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise TypeError("canonical evidence Decimal values must be finite")
        return format(value, "f")
    if isinstance(value, datetime):
        return _utc_text(value)
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical evidence object keys must be strings")
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    raise TypeError(f"unsupported canonical evidence value: {type(value).__name__}")


def _utc_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("canonical evidence timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "CanonicalEvidenceSnapshot",
    "applicable_provider_names",
    "build_canonical_evidence_payload",
    "build_evidence_snapshot",
    "canonical_serialize_evidence_payload",
]

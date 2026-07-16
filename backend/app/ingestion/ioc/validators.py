from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.ingestion.models import IOCType


_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""


def normalize_indicator(indicator_type: IOCType, raw_value: str) -> str | None:
    """Normalize and validate one IOC candidate value."""

    candidate = raw_value.strip().strip(_TRAILING_PUNCTUATION)
    if not candidate:
        return None

    if indicator_type is IOCType.CVE:
        normalized = candidate.upper()
        return normalized if re.fullmatch(r"CVE-(?:19|20)\d{2}-\d{4,7}", normalized) else None

    if indicator_type is IOCType.IPV4:
        try:
            return str(ipaddress.IPv4Address(candidate))
        except ipaddress.AddressValueError:
            return None

    if indicator_type is IOCType.IPV6:
        try:
            return str(ipaddress.IPv6Address(candidate)).lower()
        except ipaddress.AddressValueError:
            return None

    if indicator_type is IOCType.URL:
        parsed = urlparse(candidate)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.netloc:
            return None
        return candidate

    if indicator_type is IOCType.EMAIL:
        return candidate.lower()

    if indicator_type is IOCType.DOMAIN:
        lowered = candidate.lower().rstrip(".")
        if "." not in lowered:
            return None
        return lowered

    if indicator_type is IOCType.MD5:
        normalized = candidate.lower()
        return normalized if re.fullmatch(r"[a-f0-9]{32}", normalized) else None

    if indicator_type is IOCType.SHA1:
        normalized = candidate.lower()
        return normalized if re.fullmatch(r"[a-f0-9]{40}", normalized) else None

    if indicator_type is IOCType.SHA256:
        normalized = candidate.lower()
        return normalized if re.fullmatch(r"[a-f0-9]{64}", normalized) else None

    return None

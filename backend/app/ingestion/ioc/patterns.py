from __future__ import annotations

import re
from dataclasses import dataclass

from app.ingestion.models import IOCType


@dataclass(frozen=True, slots=True)
class IOCPattern:
    """Regex definition for a supported IOC type."""

    indicator_type: IOCType
    expression: re.Pattern[str]


IOC_PATTERNS: tuple[IOCPattern, ...] = (
    IOCPattern(
        indicator_type=IOCType.CVE,
        expression=re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE),
    ),
    IOCPattern(
        indicator_type=IOCType.IPV4,
        expression=re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
    ),
    IOCPattern(
        indicator_type=IOCType.IPV6,
        expression=re.compile(
            r"(?<![0-9A-Fa-f:])(?:"
            r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
            r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
            r")(?![0-9A-Fa-f:])"
        ),
    ),
    IOCPattern(
        indicator_type=IOCType.URL,
        expression=re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE),
    ),
    IOCPattern(
        indicator_type=IOCType.EMAIL,
        expression=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"),
    ),
    IOCPattern(
        indicator_type=IOCType.DOMAIN,
        expression=re.compile(
            r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
        ),
    ),
    IOCPattern(
        indicator_type=IOCType.MD5,
        expression=re.compile(r"\b[a-fA-F0-9]{32}\b"),
    ),
    IOCPattern(
        indicator_type=IOCType.SHA1,
        expression=re.compile(r"\b[a-fA-F0-9]{40}\b"),
    ),
    IOCPattern(
        indicator_type=IOCType.SHA256,
        expression=re.compile(r"\b[a-fA-F0-9]{64}\b"),
    ),
)

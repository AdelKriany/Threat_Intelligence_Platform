"""IOC extraction helpers for enrichment workflows."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.enrichment.regex import (
    CVE_PATTERN,
    EMAIL_PATTERN,
    IPV4_PATTERN,
    SHA256_PATTERN,
    URL_PATTERN,
)

_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""


def _unique_in_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def extract_cves(text: str) -> list[str]:
    """Return extracted CVEs from text."""

    matches: list[str] = []
    for match in CVE_PATTERN.findall(text):
        normalized = match.upper()
        if re.fullmatch(r"CVE-(?:19|20)\d{2}-\d{4,7}", normalized):
            matches.append(normalized)
    return _unique_in_order(matches)


def extract_ipv4(text: str) -> list[str]:
    """Return extracted IPv4 addresses from text."""

    matches: list[str] = []
    for candidate in IPV4_PATTERN.findall(text):
        try:
            matches.append(str(ipaddress.IPv4Address(candidate)))
        except ipaddress.AddressValueError:
            continue
    return _unique_in_order(matches)


def extract_urls(text: str) -> list[str]:
    """Return extracted URLs from text."""

    matches: list[str] = []
    for raw_candidate in URL_PATTERN.findall(text):
        candidate = raw_candidate.rstrip(_TRAILING_PUNCTUATION)
        parsed = urlparse(candidate)
        if parsed.scheme.lower() not in {"http", "https"}:
            continue
        if not parsed.netloc:
            continue
        matches.append(candidate)
    return _unique_in_order(matches)


def extract_emails(text: str) -> list[str]:
    """Return extracted email addresses from text."""

    matches: list[str] = []
    for candidate in EMAIL_PATTERN.findall(text):
        normalized = candidate.lower()
        if re.fullmatch(EMAIL_PATTERN, normalized):
            matches.append(normalized)
    return _unique_in_order(matches)


def extract_sha256(text: str) -> list[str]:
    """Return extracted SHA-256 hashes from text."""

    matches: list[str] = []
    for candidate in SHA256_PATTERN.findall(text):
        normalized = candidate.lower()
        if re.fullmatch(r"[a-f0-9]{64}", normalized):
            matches.append(normalized)
    return _unique_in_order(matches)

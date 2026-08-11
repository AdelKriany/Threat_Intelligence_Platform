"""IOC extraction helpers for enrichment workflows."""

from __future__ import annotations

from app.enrichment.regex import (
    CVE_PATTERN,
    EMAIL_PATTERN,
    IPV4_PATTERN,
    SHA256_PATTERN,
    URL_PATTERN,
)
from app.ingestion.ioc.validators import normalize_indicator
from app.ingestion.models import IOCType


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
        normalized = normalize_indicator(IOCType.CVE, match)
        if normalized is not None:
            matches.append(normalized)
    return _unique_in_order(matches)


def extract_ipv4(text: str) -> list[str]:
    """Return extracted IPv4 addresses from text."""

    matches: list[str] = []
    for candidate in IPV4_PATTERN.findall(text):
        normalized = normalize_indicator(IOCType.IPV4, candidate)
        if normalized is not None:
            matches.append(normalized)
    return _unique_in_order(matches)


def extract_urls(text: str) -> list[str]:
    """Return extracted URLs from text."""

    matches: list[str] = []
    for raw_candidate in URL_PATTERN.findall(text):
        normalized = normalize_indicator(IOCType.URL, raw_candidate)
        if normalized is not None:
            matches.append(normalized)
    return _unique_in_order(matches)


def extract_emails(text: str) -> list[str]:
    """Return extracted email addresses from text."""

    matches: list[str] = []
    for candidate in EMAIL_PATTERN.findall(text):
        normalized = normalize_indicator(IOCType.EMAIL, candidate)
        if normalized is not None:
            matches.append(normalized)
    return _unique_in_order(matches)


def extract_sha256(text: str) -> list[str]:
    """Return extracted SHA-256 hashes from text."""

    matches: list[str] = []
    for candidate in SHA256_PATTERN.findall(text):
        normalized = normalize_indicator(IOCType.SHA256, candidate)
        if normalized is not None:
            matches.append(normalized)
    return _unique_in_order(matches)

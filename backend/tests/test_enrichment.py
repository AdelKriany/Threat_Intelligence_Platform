from __future__ import annotations

from app.enrichment.extractor import (
    extract_cves,
    extract_emails,
    extract_ipv4,
    extract_sha256,
    extract_urls,
)

TEST_TEXT = (
    "Microsoft warns that CVE-2026-12345 is being actively exploited. "
    "Attackers connected to 45.12.88.17. Download: https://evil.example/payload.exe. "
    "Email: admin@example.com. SHA256: "
    "6f5902ac237024bdd0c176cb93063dc4f0c6f4f9f6d5c7d1b4bba8d3d4f7fabc"
)


def test_extract_cves_returns_expected_values() -> None:
    assert extract_cves(TEST_TEXT) == ["CVE-2026-12345"]


def test_extract_ipv4_returns_expected_values() -> None:
    assert extract_ipv4(TEST_TEXT) == ["45.12.88.17"]


def test_extract_urls_returns_expected_values() -> None:
    assert extract_urls(TEST_TEXT) == ["https://evil.example/payload.exe"]


def test_extract_emails_returns_expected_values() -> None:
    assert extract_emails(TEST_TEXT) == ["admin@example.com"]


def test_extract_sha256_returns_expected_values() -> None:
    assert extract_sha256(TEST_TEXT) == [
        "6f5902ac237024bdd0c176cb93063dc4f0c6f4f9f6d5c7d1b4bba8d3d4f7fabc"
    ]

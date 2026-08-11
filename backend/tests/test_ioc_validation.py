from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.database.base import Base
from app.ingestion.ioc.audit import audit_indicators, main
from app.ingestion.ioc.persistence import persist_indicators
from app.ingestion.ioc.types import ExtractedIndicator
from app.ingestion.ioc.validators import (
    ValidationReason,
    ValidationStatus,
    normalize_indicator,
    validate_indicator,
)
from app.ingestion.models import ArticleIndicator, Indicator, IOCType, RawArticle


@pytest.mark.parametrize(
    "value",
    [
        "malwares.jpg",
        "mshta.exe",
        "fastjson.gif",
        "water-plant-attack.jpg",
        "chrome-headless.jpg",
        "notepad-malware-code.jpg",
        "24650-internet-exposed-bmcs-disclose.html",
        "zimbra-patches-critical-snmp-command.html",
    ],
)
def test_filename_like_domains_are_rejected(value: str) -> None:
    result = validate_indicator(IOCType.DOMAIN, value)
    assert result.status is ValidationStatus.INVALID
    assert result.reason is ValidationReason.DOMAIN_FILE_EXTENSION
    assert normalize_indicator(IOCType.DOMAIN, value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("security.microsoft.com", "security.microsoft.com"),
        ("EXAMPLE.COM", "example.com"),
        ("sub.deep.example.org.", "sub.deep.example.org"),
        ("münich.example", "xn--mnich-kva.example"),
    ],
)
def test_legitimate_domains_normalize(value: str, expected: str) -> None:
    result = validate_indicator(IOCType.DOMAIN, value)
    assert result.status is ValidationStatus.VALID
    assert result.normalized_value == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "user@example.com",
        "example.com/path",
        "example.com?x=1",
        "example.com#fragment",
        "example.com:443",
        "bad label.example",
        "-bad.example",
        "bad-.example",
        "a..example.com",
        "127.0.0.1",
    ],
)
def test_embedded_syntax_and_invalid_domain_labels_are_rejected(value: str) -> None:
    assert validate_indicator(IOCType.DOMAIN, value).status is ValidationStatus.INVALID


def test_cve_and_hash_validation_reasons_are_stable() -> None:
    assert normalize_indicator(IOCType.CVE, " (cve-2026-12345) ") == "CVE-2026-12345"
    assert validate_indicator(IOCType.CVE, "CVE-2026-12").reason is ValidationReason.CVE_MALFORMED

    valid_md5 = validate_indicator(IOCType.MD5, "D41D8CD98F00B204E9800998ECF8427E")
    assert valid_md5.normalized_value == "d41d8cd98f00b204e9800998ecf8427e"
    assert validate_indicator(IOCType.SHA1, "abc").reason is ValidationReason.HASH_LENGTH
    non_hex = "g" * 64
    assert validate_indicator(IOCType.SHA256, non_hex).reason is ValidationReason.HASH_NON_HEX


@pytest.mark.parametrize(
    ("indicator_type", "value", "status"),
    [
        (IOCType.IPV4, "8.8.8.8", ValidationStatus.VALID),
        (IOCType.IPV4, "10.0.0.1", ValidationStatus.SUSPICIOUS),
        (IOCType.IPV4, "127.0.0.1", ValidationStatus.SUSPICIOUS),
        (IOCType.IPV4, "0.0.0.0", ValidationStatus.SUSPICIOUS),
        (IOCType.IPV4, "224.0.0.1", ValidationStatus.SUSPICIOUS),
        (IOCType.IPV6, "2001:4860:4860::8888", ValidationStatus.VALID),
        (IOCType.IPV6, "::1", ValidationStatus.SUSPICIOUS),
    ],
)
def test_non_public_ip_policy_is_explicit(
    indicator_type: IOCType, value: str, status: ValidationStatus
) -> None:
    result = validate_indicator(indicator_type, value)
    assert result.status is status
    if status is ValidationStatus.SUSPICIOUS:
        assert result.reason is ValidationReason.IP_NON_PUBLIC
        assert normalize_indicator(indicator_type, value) is not None


def test_url_normalization_preserves_path_query_and_removes_fragment() -> None:
    result = validate_indicator(
        IOCType.URL,
        "HTTPS://EXAMPLE.COM:8443/A/Path?Token=AbC#ignored",
    )
    assert result.status is ValidationStatus.VALID
    assert result.normalized_value == "https://example.com:8443/A/Path?Token=AbC"


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com/file",
        "hxxp://example.com/file",
        "https://user:pass@example.com/file",
        "https://example.com:99999/file",
        "https://example.com/a b",
        "https:///missing-host",
    ],
)
def test_unsafe_or_malformed_urls_are_rejected(value: str) -> None:
    assert validate_indicator(IOCType.URL, value).status is ValidationStatus.INVALID


def test_email_normalizes_local_and_domain_without_treating_full_value_as_domain() -> None:
    assert normalize_indicator(IOCType.EMAIL, "User.Name@EXAMPLE.COM") == "user.name@example.com"
    assert normalize_indicator(IOCType.EMAIL, "not-an-email") is None


def _factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_persistence_revalidates_and_rejects_invalid_candidates() -> None:
    factory = _factory()
    with factory() as session:
        article = RawArticle(
            source_id="validation",
            title="validation",
            fetched_at=datetime.now(UTC),
            content_hash="validation",
        )
        session.add(article)
        session.flush()
        count = persist_indicators(
            session,
            article.id,
            [
                ExtractedIndicator(IOCType.DOMAIN, "malwares.jpg"),
                ExtractedIndicator(IOCType.DOMAIN, "EXAMPLE.COM"),
            ],
        )
        session.commit()

        assert count == 1
        assert session.scalar(select(Indicator.indicator_value)) == "example.com"
        assert session.scalar(select(func.count(ArticleIndicator.indicator_id))) == 1


def _audit_factory() -> sessionmaker[Session]:
    factory = _factory()
    with factory() as session:
        session.add_all(
            [
                Indicator(indicator_type=IOCType.DOMAIN, indicator_value="example.com"),
                Indicator(indicator_type=IOCType.DOMAIN, indicator_value="malwares.jpg"),
                Indicator(indicator_type=IOCType.DOMAIN, indicator_value="fastjson.gif"),
                Indicator(indicator_type=IOCType.IPV4, indicator_value="10.0.0.1"),
            ]
        )
        session.commit()
    return factory


def test_audit_groups_limits_samples_and_is_read_only() -> None:
    factory = _audit_factory()
    with factory() as session:
        before = list(session.execute(select(Indicator.id, Indicator.indicator_value)))
        report = audit_indicators(session, sample_limit=1, batch_size=2)
        after = list(session.execute(select(Indicator.id, Indicator.indicator_value)))

    assert report["counts"] == {"valid": 1, "invalid": 2, "suspicious": 1}
    assert report["read_only"] is True
    file_group = next(
        group for group in report["groups"] if group["reason"] == "domain_file_extension"
    )
    assert file_group["count"] == 2
    assert len(file_group["samples"]) == 1
    assert before == after


def test_audit_json_and_exit_codes() -> None:
    factory = _audit_factory()
    stdout = io.StringIO()
    stderr = io.StringIO()

    assert main(["--format", "json"], session_factory=factory, stdout=stdout, stderr=stderr) == 0
    payload = json.loads(stdout.getvalue())
    assert payload["counts"]["invalid"] == 2
    assert stderr.getvalue() == ""

    assert (
        main(
            ["--format", "summary", "--fail-on", "invalid"],
            session_factory=factory,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        == 1
    )

    assert (
        main(
            ["--sample-limit", "-1"],
            session_factory=factory,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        == 2
    )

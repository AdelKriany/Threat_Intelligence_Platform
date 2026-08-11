from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import SplitResult, urlsplit, urlunsplit

from app.ingestion.models import IOCType

_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
_WRAPPER_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">", "'": "'", '"': '"'}
_CONTROL_OR_SPACE = re.compile(r"[\s\x00-\x1f\x7f]")
_CVE = re.compile(r"CVE-(?:19|20)\d{2}-\d{4,7}")
_HEX_LENGTHS = {IOCType.MD5: 32, IOCType.SHA1: 40, IOCType.SHA256: 64}
_LOCAL_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")

# Conservative OSINT policy: these common content/file suffixes produce far more
# article-title and attachment false positives than useful bare-domain indicators.
DOMAIN_FILE_SUFFIXES = frozenset(
    {
        "7z",
        "apk",
        "asp",
        "aspx",
        "bat",
        "bin",
        "bmp",
        "bz2",
        "cab",
        "cmd",
        "css",
        "csv",
        "dll",
        "doc",
        "docm",
        "docx",
        "exe",
        "gif",
        "gz",
        "htm",
        "html",
        "ico",
        "iso",
        "jar",
        "jpeg",
        "jpg",
        "js",
        "json",
        "lnk",
        "msi",
        "pdf",
        "php",
        "png",
        "ppt",
        "pptx",
        "ps1",
        "rar",
        "rtf",
        "scr",
        "svg",
        "tar",
        "tif",
        "tiff",
        "tmp",
        "txt",
        "vbs",
        "webp",
        "xls",
        "xlsm",
        "xlsx",
        "xml",
        "zip",
    }
)


class ValidationStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    SUSPICIOUS = "suspicious"


class ValidationReason(StrEnum):
    VALID = "valid"
    EMPTY = "empty"
    CVE_MALFORMED = "cve_malformed"
    HASH_LENGTH = "hash_length"
    HASH_NON_HEX = "hash_non_hex"
    IP_MALFORMED = "ip_malformed"
    IP_VERSION_MISMATCH = "ip_version_mismatch"
    IP_NON_PUBLIC = "ip_non_public"
    URL_UNSUPPORTED_SCHEME = "url_unsupported_scheme"
    URL_MISSING_HOST = "url_missing_host"
    URL_CREDENTIALS = "url_credentials"
    URL_INVALID_PORT = "url_invalid_port"
    URL_WHITESPACE_OR_CONTROL = "url_whitespace_or_control"
    URL_INVALID_HOST = "url_invalid_host"
    DOMAIN_EMBEDDED_SYNTAX = "domain_embedded_syntax"
    DOMAIN_IP_LITERAL = "domain_ip_literal"
    DOMAIN_EMPTY_LABEL = "domain_empty_label"
    DOMAIN_LABEL_TOO_LONG = "domain_label_too_long"
    DOMAIN_TOO_LONG = "domain_too_long"
    DOMAIN_LABEL_HYPHEN = "domain_label_hyphen"
    DOMAIN_INVALID_CHARACTER = "domain_invalid_character"
    DOMAIN_IMPLAUSIBLE_SUFFIX = "domain_implausible_suffix"
    DOMAIN_FILE_EXTENSION = "domain_file_extension"
    EMAIL_MALFORMED = "email_malformed"
    UNSUPPORTED_TYPE = "unsupported_type"


@dataclass(frozen=True, slots=True)
class ValidationResult:
    original_value: str
    normalized_value: str | None
    indicator_type: IOCType
    status: ValidationStatus
    reason: ValidationReason
    detail: str | None = None


def _result(
    original: str,
    indicator_type: IOCType,
    status: ValidationStatus,
    reason: ValidationReason,
    normalized: str | None = None,
    detail: str | None = None,
) -> ValidationResult:
    return ValidationResult(original, normalized, indicator_type, status, reason, detail)


def _trim_candidate(raw_value: str) -> str:
    candidate = raw_value.strip()
    while len(candidate) >= 2 and _WRAPPER_PAIRS.get(candidate[0]) == candidate[-1]:
        candidate = candidate[1:-1].strip()
    return candidate.rstrip(_TRAILING_PUNCTUATION)


def _validate_domain(original: str, candidate: str, indicator_type: IOCType) -> ValidationResult:
    lowered = candidate.lower()
    if lowered.endswith("."):
        lowered = lowered[:-1]
    if any(token in lowered for token in ("://", "/", "?", "#", "@")):
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.DOMAIN_EMBEDDED_SYNTAX,
        )
    if _CONTROL_OR_SPACE.search(lowered):
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.DOMAIN_INVALID_CHARACTER,
        )
    try:
        ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        pass
    else:
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.DOMAIN_IP_LITERAL
        )

    unicode_labels = lowered.split(".")
    if any(not label for label in unicode_labels):
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.DOMAIN_EMPTY_LABEL
        )
    ascii_labels: list[str] = []
    for label in unicode_labels:
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.DOMAIN_INVALID_CHARACTER,
            )
        if len(ascii_label) > 63:
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.DOMAIN_LABEL_TOO_LONG,
            )
        if ascii_label.startswith("-") or ascii_label.endswith("-"):
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.DOMAIN_LABEL_HYPHEN,
            )
        if not re.fullmatch(r"[a-z0-9-]+", ascii_label):
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.DOMAIN_INVALID_CHARACTER,
            )
        ascii_labels.append(ascii_label)

    normalized = ".".join(ascii_labels)
    if len(normalized) > 253:
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.DOMAIN_TOO_LONG
        )
    if len(ascii_labels) < 2:
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.DOMAIN_IMPLAUSIBLE_SUFFIX,
        )
    suffix = ascii_labels[-1]
    if suffix in DOMAIN_FILE_SUFFIXES:
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.DOMAIN_FILE_EXTENSION,
        )
    if not (re.fullmatch(r"[a-z]{2,63}", suffix) or suffix.startswith("xn--")):
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.DOMAIN_IMPLAUSIBLE_SUFFIX,
        )
    return _result(
        original, indicator_type, ValidationStatus.VALID, ValidationReason.VALID, normalized
    )


def _validate_url(original: str, candidate: str, indicator_type: IOCType) -> ValidationResult:
    if _CONTROL_OR_SPACE.search(candidate):
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.URL_WHITESPACE_OR_CONTROL,
        )
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.URL_MISSING_HOST
        )
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return _result(
            original,
            indicator_type,
            ValidationStatus.INVALID,
            ValidationReason.URL_UNSUPPORTED_SCHEME,
        )
    if parsed.username is not None or parsed.password is not None:
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.URL_CREDENTIALS
        )
    hostname = parsed.hostname
    if not hostname:
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.URL_MISSING_HOST
        )
    try:
        port = parsed.port
    except ValueError:
        return _result(
            original, indicator_type, ValidationStatus.INVALID, ValidationReason.URL_INVALID_PORT
        )

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        host_result = _validate_domain(hostname, hostname, IOCType.DOMAIN)
        if host_result.status is ValidationStatus.INVALID:
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.URL_INVALID_HOST,
                detail=host_result.reason.value,
            )
        normalized_host = host_result.normalized_value or hostname.lower()
    else:
        normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed

    netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    normalized_parts = SplitResult(scheme, netloc, parsed.path, parsed.query, "")
    return _result(
        original,
        indicator_type,
        ValidationStatus.VALID,
        ValidationReason.VALID,
        urlunsplit(normalized_parts),
    )


def validate_indicator(indicator_type: IOCType, raw_value: str) -> ValidationResult:
    """Validate one IOC with deterministic, network-free normalization and reasons."""

    original = raw_value
    candidate = _trim_candidate(unicodedata.normalize("NFC", raw_value))
    if not candidate:
        return _result(original, indicator_type, ValidationStatus.INVALID, ValidationReason.EMPTY)

    if indicator_type is IOCType.CVE:
        normalized = candidate.upper()
        if not _CVE.fullmatch(normalized):
            return _result(
                original, indicator_type, ValidationStatus.INVALID, ValidationReason.CVE_MALFORMED
            )
        return _result(
            original, indicator_type, ValidationStatus.VALID, ValidationReason.VALID, normalized
        )

    if indicator_type in _HEX_LENGTHS:
        normalized = candidate.lower()
        if len(normalized) != _HEX_LENGTHS[indicator_type]:
            return _result(
                original, indicator_type, ValidationStatus.INVALID, ValidationReason.HASH_LENGTH
            )
        if not re.fullmatch(r"[a-f0-9]+", normalized):
            return _result(
                original, indicator_type, ValidationStatus.INVALID, ValidationReason.HASH_NON_HEX
            )
        return _result(
            original, indicator_type, ValidationStatus.VALID, ValidationReason.VALID, normalized
        )

    if indicator_type in {IOCType.IPV4, IOCType.IPV6}:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return _result(
                original, indicator_type, ValidationStatus.INVALID, ValidationReason.IP_MALFORMED
            )
        expected_version = 4 if indicator_type is IOCType.IPV4 else 6
        if address.version != expected_version:
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.IP_VERSION_MISMATCH,
            )
        is_public = address.is_global and not any(
            (
                address.is_private,
                address.is_reserved,
                address.is_loopback,
                address.is_link_local,
                address.is_multicast,
                address.is_unspecified,
            )
        )
        status = ValidationStatus.VALID if is_public else ValidationStatus.SUSPICIOUS
        reason = ValidationReason.VALID if is_public else ValidationReason.IP_NON_PUBLIC
        return _result(original, indicator_type, status, reason, address.compressed.lower())

    if indicator_type is IOCType.URL:
        return _validate_url(original, candidate, indicator_type)

    if indicator_type is IOCType.DOMAIN:
        return _validate_domain(original, candidate, indicator_type)

    if indicator_type is IOCType.EMAIL:
        if candidate.count("@") != 1:
            return _result(
                original, indicator_type, ValidationStatus.INVALID, ValidationReason.EMAIL_MALFORMED
            )
        local, domain = candidate.rsplit("@", 1)
        if not _LOCAL_EMAIL.fullmatch(local):
            return _result(
                original, indicator_type, ValidationStatus.INVALID, ValidationReason.EMAIL_MALFORMED
            )
        domain_result = _validate_domain(domain, domain, IOCType.DOMAIN)
        if domain_result.status is ValidationStatus.INVALID:
            return _result(
                original,
                indicator_type,
                ValidationStatus.INVALID,
                ValidationReason.EMAIL_MALFORMED,
                detail=domain_result.reason.value,
            )
        return _result(
            original,
            indicator_type,
            ValidationStatus.VALID,
            ValidationReason.VALID,
            f"{local.lower()}@{domain_result.normalized_value}",
        )

    return _result(
        original, indicator_type, ValidationStatus.INVALID, ValidationReason.UNSUPPORTED_TYPE
    )


def normalize_indicator(indicator_type: IOCType, raw_value: str) -> str | None:
    """Compatibility API returning normalized valid or suspicious values."""

    result = validate_indicator(indicator_type, raw_value)
    return result.normalized_value if result.status is not ValidationStatus.INVALID else None

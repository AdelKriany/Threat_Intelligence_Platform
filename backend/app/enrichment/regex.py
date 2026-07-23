"""Regex patterns for IOC enrichment extraction."""

from __future__ import annotations

import re

CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

from __future__ import annotations

from app.ingestion.ioc.patterns import IOC_PATTERNS, IOCPattern
from app.ingestion.ioc.types import ExtractedIndicator
from app.ingestion.ioc.validators import normalize_indicator
from app.ingestion.models import RawArticle


class IOCExtractionService:
    """Extract and normalize IOCs from raw article content."""

    def __init__(self, patterns: tuple[IOCPattern, ...] | None = None) -> None:
        self.patterns = patterns or IOC_PATTERNS

    def extract(self, raw_article: RawArticle) -> list[ExtractedIndicator]:
        """Return distinct normalized indicators found in a raw article."""

        content = self._build_content(raw_article)
        if not content:
            return []

        found: set[ExtractedIndicator] = set()
        for pattern in self.patterns:
            for match in pattern.expression.finditer(content):
                normalized = normalize_indicator(pattern.indicator_type, match.group(0))
                if normalized is None:
                    continue
                found.add(
                    ExtractedIndicator(
                        indicator_type=pattern.indicator_type,
                        indicator_value=normalized,
                    )
                )

        return sorted(
            found,
            key=lambda indicator: (indicator.indicator_type.value, indicator.indicator_value),
        )

    def _build_content(self, raw_article: RawArticle) -> str:
        parts = [
            raw_article.title,
            raw_article.description,
            raw_article.raw_content,
            raw_article.url,
        ]
        return "\n".join(part for part in parts if part)

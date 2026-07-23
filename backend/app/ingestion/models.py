from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IOCType(StrEnum):
    """Supported IOC types for Phase 3.1 extraction."""

    CVE = "cve"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


def _ioc_type_values(enum_type: type[IOCType]) -> list[str]:
    return [member.value for member in enum_type]


@dataclass(slots=True)
class NormalizedArticle:
    """A normalized in-memory representation of an ingested feed entry."""

    source_id: str
    title: str
    description: str | None = None
    url: str | None = None
    published_at: datetime | None = None
    author: str | None = None
    categories: list[str] = field(default_factory=list)
    source_name: str | None = None
    raw_content: str | None = None


class RawArticle(Base):
    """The first persistent model for raw ingested content."""

    __tablename__ = "raw_articles"
    __table_args__ = (UniqueConstraint("content_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    categories: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    indicators: Mapped[list[Indicator]] = relationship(
        "Indicator",
        back_populates="raw_article",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a dict representation for logging and tests."""

        return {
            "id": self.id,
            "source_id": self.source_id,
            "source_name": self.source_name,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "published_at": self.published_at,
            "fetched_at": self.fetched_at,
            "content_hash": self.content_hash,
            "author": self.author,
            "categories": self.categories,
        }


class Indicator(Base):
    """A model for storing extracted indicators of compromise (IOCs)."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint(
            "raw_article_id",
            "indicator_type",
            "indicator_value",
            name="uq_indicators_article_type_value",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    raw_article_id: Mapped[int] = mapped_column(
        ForeignKey("raw_articles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    indicator_type: Mapped[IOCType] = mapped_column(
        Enum(
            IOCType,
            name="ioc_type",
            values_callable=_ioc_type_values,
            validate_strings=True,
        ),
        nullable=False,
        index=True,
    )
    indicator_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

    raw_article: Mapped[RawArticle] = relationship("RawArticle", back_populates="indicators")
    enrichments: Mapped[list[IndicatorEnrichment]] = relationship(
        "IndicatorEnrichment",
        back_populates="indicator",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class IndicatorEnrichment(Base):
    """One provider's latest enrichment result for an indicator."""

    __tablename__ = "indicator_enrichments"
    __table_args__ = (
        UniqueConstraint(
            "indicator_id",
            "provider",
            name="uq_indicator_enrichments_indicator_provider",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_data: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=dict,
    )
    raw_response: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    indicator: Mapped[Indicator] = relationship("Indicator", back_populates="enrichments")

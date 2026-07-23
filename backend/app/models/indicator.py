"""IOC models for the enrichment phase."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class IOCType(StrEnum):
    """Supported IOC types for enrichment storage."""

    CVE = "CVE"
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "Domain"
    URL = "URL"
    EMAIL = "Email"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"


class Indicator(Base):
    """Canonical IOC value stored independently from articles."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_indicators_type_value"),
        Index("ix_indicators_type_value", "type", "value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[IOCType] = mapped_column(Enum(IOCType, name="ioc_type"), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)


class ArticleIndicator(Base):
    """Association table linking raw articles to indicators."""

    __tablename__ = "article_indicators"

    article_id: Mapped[int] = mapped_column(
        ForeignKey("raw_articles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"),
        primary_key=True,
    )

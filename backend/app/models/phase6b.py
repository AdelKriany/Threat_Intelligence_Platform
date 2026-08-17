from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.ingestion.models import Indicator, RawArticle


def _utc_now() -> datetime:
    return datetime.now(UTC)


_postgres_sha256_check = CheckConstraint(
    "evidence_hash ~ '^[0-9a-f]{64}$'",
    name="ck_score_history_evidence_hash_sha256",
).ddl_if(dialect="postgresql")
_sqlite_sha256_check = CheckConstraint(
    "length(evidence_hash) = 64 AND evidence_hash NOT GLOB '*[^0-9a-f]*'",
    name="ck_score_history_evidence_hash_sha256_sqlite",
).ddl_if(dialect="sqlite")


class CorrelatedEvent(Base):
    """A stable correlation target; correlation logic is intentionally external."""

    __tablename__ = "correlated_events"
    __table_args__ = (
        UniqueConstraint("event_key", name="uq_correlated_events_event_key"),
        Index("ix_correlated_events_updated_at", "updated_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_key: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    article_links: Mapped[list[EventArticle]] = relationship(
        "EventArticle",
        back_populates="event",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    indicator_links: Mapped[list[EventIndicator]] = relationship(
        "EventIndicator",
        back_populates="event",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    scores: Mapped[list[ScoreHistory]] = relationship(
        "ScoreHistory",
        back_populates="event",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )


class EventArticle(Base):
    """Owned event/article link; neither endpoint is owned by this row."""

    __tablename__ = "event_articles"
    __table_args__ = (Index("ix_event_articles_article_event", "article_id", "event_id"),)

    event_id: Mapped[int] = mapped_column(
        ForeignKey("correlated_events.id", ondelete="CASCADE"), primary_key=True
    )
    article_id: Mapped[int] = mapped_column(
        ForeignKey("raw_articles.id", ondelete="CASCADE"), primary_key=True
    )
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

    event: Mapped[CorrelatedEvent] = relationship(
        "CorrelatedEvent", back_populates="article_links", lazy="selectin"
    )
    article: Mapped[RawArticle] = relationship("RawArticle", lazy="selectin")


class EventIndicator(Base):
    """Owned event/indicator link; neither endpoint is owned by this row."""

    __tablename__ = "event_indicators"
    __table_args__ = (
        Index(
            "ix_event_indicators_indicator_rule_event",
            "indicator_id",
            "rule_name",
            "rule_version",
            "event_id",
        ),
    )

    event_id: Mapped[int] = mapped_column(
        ForeignKey("correlated_events.id", ondelete="CASCADE"), primary_key=True
    )
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )

    event: Mapped[CorrelatedEvent] = relationship(
        "CorrelatedEvent", back_populates="indicator_links", lazy="selectin"
    )
    indicator: Mapped[Indicator] = relationship("Indicator", lazy="selectin")


class ScoreHistory(Base):
    """Append-only indicator or event score snapshot."""

    __tablename__ = "score_history"
    __table_args__ = (
        CheckConstraint(
            "score >= 0.00 AND score <= 100.00",
            name="ck_score_history_score_range",
        ),
        CheckConstraint(
            "target_kind IN ('indicator', 'event')",
            name="ck_score_history_target_kind",
        ),
        CheckConstraint(
            "severity IN ('none', 'low', 'medium', 'high', 'critical')",
            name="ck_score_history_severity",
        ),
        CheckConstraint(
            "(target_kind = 'indicator' AND indicator_id IS NOT NULL AND event_id IS NULL) "
            "OR (target_kind = 'event' AND event_id IS NOT NULL AND indicator_id IS NULL)",
            name="ck_score_history_exactly_one_target",
        ),
        _postgres_sha256_check,
        _sqlite_sha256_check,
        Index(
            "uq_score_history_indicator_evidence",
            "indicator_id",
            "formula_version",
            "evidence_hash",
            unique=True,
            postgresql_where=text("target_kind = 'indicator'"),
            sqlite_where=text("target_kind = 'indicator'"),
        ),
        Index(
            "uq_score_history_event_evidence",
            "event_id",
            "formula_version",
            "evidence_hash",
            unique=True,
            postgresql_where=text("target_kind = 'event'"),
            sqlite_where=text("target_kind = 'event'"),
        ),
        Index(
            "ix_score_history_indicator_calculated_at",
            "indicator_id",
            "calculated_at",
            postgresql_where=text("target_kind = 'indicator'"),
            sqlite_where=text("target_kind = 'indicator'"),
        ),
        Index(
            "ix_score_history_event_calculated_at",
            "event_id",
            "calculated_at",
            postgresql_where=text("target_kind = 'event'"),
            sqlite_where=text("target_kind = 'event'"),
        ),
        # Provisional support for the documented ranking order. Revisit only when
        # concrete list-query shapes exist; no API query is introduced in this phase.
        Index("ix_score_history_ranked", "target_kind", "score", "calculated_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    indicator_id: Mapped[int | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), nullable=True
    )
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("correlated_events.id", ondelete="CASCADE"), nullable=True
    )
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    formula_version: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    indicator: Mapped[Indicator | None] = relationship("Indicator", lazy="selectin")
    event: Mapped[CorrelatedEvent | None] = relationship(
        "CorrelatedEvent", back_populates="scores", lazy="selectin"
    )
    components: Mapped[list[ScoreComponentRecord]] = relationship(
        "ScoreComponentRecord",
        back_populates="score_history",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )


class ScoreComponentRecord(Base):
    """One explainable component owned by a score snapshot."""

    __tablename__ = "score_components"
    __table_args__ = (
        CheckConstraint("weight >= 0", name="ck_score_components_weight_nonnegative"),
        CheckConstraint(
            "contribution >= 0",
            name="ck_score_components_contribution_nonnegative",
        ),
        CheckConstraint(
            "freshness_multiplier >= 0",
            name="ck_score_components_freshness_nonnegative",
        ),
    )

    score_history_id: Mapped[int] = mapped_column(
        ForeignKey("score_history.id", ondelete="CASCADE"), primary_key=True
    )
    component_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_input: Mapped[dict[str, Any] | list[Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    normalized_input: Mapped[Any] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    weight: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    contribution: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    freshness_multiplier: Mapped[Decimal] = mapped_column(Numeric(12, 6), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    score_history: Mapped[ScoreHistory] = relationship(
        "ScoreHistory", back_populates="components", lazy="selectin"
    )


__all__ = [
    "CorrelatedEvent",
    "EventArticle",
    "EventIndicator",
    "ScoreComponentRecord",
    "ScoreHistory",
]

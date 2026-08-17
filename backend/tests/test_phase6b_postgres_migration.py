from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError

PHASE6B_TABLES = {
    "correlated_events",
    "event_articles",
    "event_indicators",
    "score_history",
    "score_components",
}
PARENT_REVISION = "b74f3c9a21de"


def _postgres_url() -> str:
    url = os.getenv("PHASE6B_POSTGRES_URL", "")
    if not url:
        pytest.skip("PHASE6B_POSTGRES_URL is not configured")
    parsed = make_url(url)
    if parsed.get_backend_name() != "postgresql" or parsed.database != "threatlens_phase6b_test":
        pytest.fail(
            "PHASE6B_POSTGRES_URL must target disposable threatlens_phase6b_test PostgreSQL"
        )
    return url


def _alembic_config(url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    return config


def _reject(engine: Engine, statement: str, parameters: dict[str, object]) -> None:
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(text(statement), parameters)


def test_postgres_migration_constraints_cascades_downgrade_and_reupgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = _postgres_url()
    monkeypatch.setenv("DATABASE_URL", url)
    config = _alembic_config(url)
    engine = create_engine(url)

    # The database name is safety-checked above. Resetting the disposable database's
    # migration chain makes this lifecycle test repeatable after an interrupted run.
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    inspector = inspect(engine)
    assert PHASE6B_TABLES.issubset(inspector.get_table_names())
    assert {column["name"] for column in inspector.get_columns("score_history")} == {
        "id",
        "target_kind",
        "indicator_id",
        "event_id",
        "score",
        "severity",
        "formula_version",
        "evidence_hash",
        "canonical_evidence",
        "calculated_at",
    }
    assert {column["name"] for column in inspector.get_columns("score_components")} == {
        "score_history_id",
        "component_name",
        "raw_input",
        "normalized_input",
        "weight",
        "contribution",
        "freshness_multiplier",
        "explanation",
        "provider",
        "evidence_at",
    }
    foreign_keys = {
        (foreign_key["constrained_columns"][0], foreign_key["referred_table"]): foreign_key
        for table_name in (
            "event_articles",
            "event_indicators",
            "score_history",
            "score_components",
        )
        for foreign_key in inspector.get_foreign_keys(table_name)
    }
    assert {
        ("event_id", "correlated_events"),
        ("article_id", "raw_articles"),
        ("indicator_id", "indicators"),
        ("score_history_id", "score_history"),
    }.issubset(foreign_keys)
    assert all(value["options"].get("ondelete") == "CASCADE" for value in foreign_keys.values())
    assert {check["name"] for check in inspector.get_check_constraints("score_history")} == {
        "ck_score_history_evidence_hash_sha256",
        "ck_score_history_exactly_one_target",
        "ck_score_history_score_range",
        "ck_score_history_severity",
        "ck_score_history_target_kind",
    }
    score_indexes = {index["name"]: index for index in inspector.get_indexes("score_history")}
    assert score_indexes["uq_score_history_indicator_evidence"]["unique"] is True
    assert score_indexes["uq_score_history_event_evidence"]["unique"] is True
    assert "indicator" in str(
        score_indexes["uq_score_history_indicator_evidence"]["dialect_options"]
    )
    assert "event" in str(score_indexes["uq_score_history_event_evidence"]["dialect_options"])

    now = datetime.now(UTC)
    with engine.begin() as connection:
        article_id = connection.scalar(
            text(
                """
                INSERT INTO raw_articles
                    (source_id, title, fetched_at, content_hash, created_at)
                VALUES ('phase6b-test', 'Phase 6B', :now, 'phase6b-postgres', :now)
                RETURNING id
                """
            ),
            {"now": now},
        )
        indicator_id = connection.scalar(
            text(
                """
                INSERT INTO indicators (indicator_type, indicator_value, created_at)
                VALUES ('cve', 'CVE-2026-60001', :now)
                RETURNING id
                """
            ),
            {"now": now},
        )
        event_id = connection.scalar(
            text(
                """
                INSERT INTO correlated_events
                    (event_key, title, rule_name, rule_version, created_at, updated_at)
                VALUES
                    ('cve:CVE-2026-60001', 'CVE event', 'shared-cve', 'v1', :now, :now)
                RETURNING id
                """
            ),
            {"now": now},
        )
        connection.execute(
            text(
                """
                INSERT INTO event_articles
                    (event_id, article_id, reason, rule_name, rule_version, created_at)
                VALUES (:event_id, :article_id, 'shared_canonical_cve', 'shared-cve', 'v1', :now)
                """
            ),
            {"event_id": event_id, "article_id": article_id, "now": now},
        )
        connection.execute(
            text(
                """
                INSERT INTO event_indicators
                    (event_id, indicator_id, reason, rule_name, rule_version, created_at)
                VALUES (:event_id, :indicator_id, 'shared_canonical_cve', 'shared-cve', 'v1', :now)
                """
            ),
            {"event_id": event_id, "indicator_id": indicator_id, "now": now},
        )

    score_sql = """
        INSERT INTO score_history
            (target_kind, indicator_id, event_id, score, severity, formula_version,
             evidence_hash, canonical_evidence, calculated_at)
        VALUES
            (:target_kind, :indicator_id, :event_id, :score, :severity, :formula_version,
             :evidence_hash, CAST(:evidence AS jsonb), :now)
        RETURNING id
    """
    common: dict[str, object] = {
        "indicator_id": indicator_id,
        "event_id": None,
        "target_kind": "indicator",
        "score": Decimal("42.25"),
        "severity": "medium",
        "formula_version": "phase6b-v1",
        "evidence_hash": "a" * 64,
        "evidence": json.dumps({"provider": {"value": "0.125"}}),
        "now": now,
    }
    with engine.begin() as connection:
        indicator_score_id = connection.scalar(text(score_sql), common)
        connection.execute(
            text(score_sql),
            {**common, "indicator_id": None, "event_id": event_id, "target_kind": "event"},
        )
        connection.execute(
            text(score_sql),
            {**common, "formula_version": "phase6b-v2"},
        )
        connection.execute(
            text(
                """
                INSERT INTO score_components
                    (score_history_id, component_name, raw_input, normalized_input,
                     weight, contribution, freshness_multiplier, explanation, provider,
                     evidence_at)
                VALUES
                    (:score_id, 'epss_probability', CAST(:raw AS jsonb), CAST(:normalized AS jsonb),
                     :weight, :contribution, :freshness, 'EPSS contribution', 'epss', :now)
                """
            ),
            {
                "score_id": indicator_score_id,
                "raw": json.dumps({"probability": "0.1234567"}),
                "normalized": json.dumps("0.1234567"),
                "weight": Decimal("15.000000"),
                "contribution": Decimal("1.851850"),
                "freshness": Decimal("1.000000"),
                "now": now,
            },
        )

    _reject(engine, score_sql, common)
    _reject(engine, score_sql, {**common, "score": Decimal("100.01"), "evidence_hash": "b" * 64})
    _reject(
        engine,
        score_sql,
        {**common, "target_kind": "unknown", "evidence_hash": "c" * 64},
    )
    _reject(
        engine,
        score_sql,
        {**common, "indicator_id": None, "evidence_hash": "d" * 64},
    )
    _reject(
        engine,
        score_sql,
        {**common, "event_id": event_id, "evidence_hash": "e" * 64},
    )
    _reject(engine, score_sql, {**common, "evidence_hash": "not-a-sha256"})
    _reject(
        engine,
        """
        INSERT INTO correlated_events
            (event_key, title, rule_name, rule_version, created_at, updated_at)
        VALUES ('cve:CVE-2026-60001', 'duplicate', 'shared-cve', 'v1', :now, :now)
        """,
        {"now": now},
    )
    _reject(
        engine,
        """
        INSERT INTO event_articles
            (event_id, article_id, reason, rule_name, rule_version, created_at)
        VALUES (:event_id, :article_id, 'duplicate', 'shared-cve', 'v1', :now)
        """,
        {"event_id": event_id, "article_id": article_id, "now": now},
    )
    _reject(
        engine,
        """
        INSERT INTO event_indicators
            (event_id, indicator_id, reason, rule_name, rule_version, created_at)
        VALUES (:event_id, :indicator_id, 'duplicate', 'shared-cve', 'v1', :now)
        """,
        {"event_id": event_id, "indicator_id": indicator_id, "now": now},
    )
    _reject(
        engine,
        """
        INSERT INTO score_components
            (score_history_id, component_name, raw_input, normalized_input,
             weight, contribution, freshness_multiplier, explanation)
        VALUES (:score_id, 'epss_probability', '{}'::jsonb, 'null'::jsonb, 0, 0, 0, 'duplicate')
        """,
        {"score_id": indicator_score_id},
    )

    with engine.connect() as connection:
        component = connection.execute(
            text(
                """
                SELECT weight, contribution, raw_input, normalized_input
                FROM score_components
                WHERE score_history_id = :score_id
                """
            ),
            {"score_id": indicator_score_id},
        ).one()
        assert component.weight == Decimal("15.000000")
        assert component.contribution == Decimal("1.851850")
        assert component.raw_input == {"probability": "0.1234567"}
        assert component.normalized_input == "0.1234567"
        timestamp = connection.scalar(
            text("SELECT calculated_at FROM score_history WHERE id = :score_id"),
            {"score_id": indicator_score_id},
        )
        assert timestamp.utcoffset().total_seconds() == 0

    with engine.begin() as connection:
        connection.execute(
            text(
                "DELETE FROM event_articles WHERE event_id = :event_id AND article_id = :article_id"
            ),
            {"event_id": event_id, "article_id": article_id},
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM raw_articles WHERE id = :id"), {"id": article_id}
            )
            == 1
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM correlated_events WHERE id = :id"), {"id": event_id}
            )
            == 1
        )
        connection.execute(text("DELETE FROM indicators WHERE id = :id"), {"id": indicator_id})
        assert (
            connection.scalar(
                text("SELECT count(*) FROM correlated_events WHERE id = :id"), {"id": event_id}
            )
            == 1
        )
        assert connection.scalar(text("SELECT count(*) FROM event_indicators")) == 0
        assert (
            connection.scalar(
                text("SELECT count(*) FROM score_history WHERE target_kind = 'indicator'")
            )
            == 0
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM score_history WHERE target_kind = 'event'")
            )
            == 1
        )
        connection.execute(text("DELETE FROM correlated_events WHERE id = :id"), {"id": event_id})
        assert connection.scalar(text("SELECT count(*) FROM score_history")) == 0
        assert connection.scalar(text("SELECT count(*) FROM score_components")) == 0
        assert (
            connection.scalar(
                text("SELECT count(*) FROM raw_articles WHERE id = :id"), {"id": article_id}
            )
            == 1
        )

    command.downgrade(config, PARENT_REVISION)
    downgraded_tables = set(inspect(engine).get_table_names())
    assert not PHASE6B_TABLES & downgraded_tables
    assert {"raw_articles", "indicators", "article_indicators"}.issubset(downgraded_tables)
    with engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT count(*) FROM raw_articles WHERE id = :id"), {"id": article_id}
            )
            == 1
        )

    command.upgrade(config, "head")
    assert PHASE6B_TABLES.issubset(inspect(engine).get_table_names())
    engine.dispose()

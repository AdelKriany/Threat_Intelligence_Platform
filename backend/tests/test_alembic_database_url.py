from __future__ import annotations

from alembic.config import Config

from app.database.alembic_runtime import (
    ALEMBIC_PLACEHOLDER_URL,
    apply_resolved_database_url,
    resolve_database_url,
    set_explicit_database_url,
)

DEVELOPMENT_URL = "postgresql+psycopg://dev:secret@postgres:5432/threatlens"
TEST_URL = "postgresql+psycopg://test:p%25ss%40word@postgres:5432/threatlens_phase6b_test"


def test_programmatic_config_url_wins_over_application_settings() -> None:
    config = Config()
    set_explicit_database_url(config, TEST_URL)

    assert resolve_database_url(config, application_url=DEVELOPMENT_URL) == TEST_URL


def test_direct_config_main_option_remains_resolved_url() -> None:
    config = Config()
    config.set_main_option("sqlalchemy.url", TEST_URL.replace("%", "%%"))

    assert resolve_database_url(config, application_url=DEVELOPMENT_URL) == TEST_URL


def test_cli_override_wins_when_no_programmatic_url_exists() -> None:
    config = Config()

    assert (
        resolve_database_url(
            config,
            application_url=DEVELOPMENT_URL,
            cli_options={"database_url": TEST_URL},
        )
        == TEST_URL
    )


def test_programmatic_url_wins_over_cli_override() -> None:
    config = Config()
    set_explicit_database_url(config, TEST_URL)

    assert (
        resolve_database_url(
            config,
            application_url=DEVELOPMENT_URL,
            cli_options={"database_url": DEVELOPMENT_URL},
        )
        == TEST_URL
    )


def test_application_settings_are_fallback_for_placeholder_config() -> None:
    config = Config()
    config.set_main_option("sqlalchemy.url", ALEMBIC_PLACEHOLDER_URL)

    assert resolve_database_url(config, application_url=DEVELOPMENT_URL) == DEVELOPMENT_URL


def test_special_character_url_round_trips_without_interpolation() -> None:
    config = Config()
    set_explicit_database_url(config, TEST_URL)

    assert config.get_main_option("sqlalchemy.url") == TEST_URL


def test_offline_and_online_consumers_receive_same_resolved_target() -> None:
    config = Config()
    set_explicit_database_url(config, TEST_URL)
    resolved = resolve_database_url(config, application_url=DEVELOPMENT_URL)
    apply_resolved_database_url(config, resolved)

    offline_url = resolved
    online_section = config.get_section(config.config_ini_section) or {}
    online_url = online_section["sqlalchemy.url"]
    assert offline_url == online_url == TEST_URL

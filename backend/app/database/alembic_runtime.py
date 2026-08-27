from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Connection, make_url

ALEMBIC_URL_OPTION = "sqlalchemy.url"
ALEMBIC_URL_ATTRIBUTE = "explicit_database_url"
ALEMBIC_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"
EXPECTED_DATABASE_ATTRIBUTE = "expected_database_name"


class DatabaseIdentityError(RuntimeError):
    """Raised before migration work when a connection reaches the wrong database."""


def set_explicit_database_url(config: Config, url: str) -> None:
    """Attach a programmatic URL without ConfigParser interpolation ambiguity."""

    if not url:
        raise ValueError("explicit Alembic database URL cannot be empty")
    config.attributes[ALEMBIC_URL_ATTRIBUTE] = url
    _set_rendered_database_url(config, url)


def resolve_database_url(
    config: Config,
    *,
    application_url: str,
    cli_options: Mapping[str, str] | None = None,
) -> str:
    """Resolve programmatic, CLI, configured, then application URL precedence."""

    explicit = config.attributes.get(ALEMBIC_URL_ATTRIBUTE)
    if isinstance(explicit, str) and explicit:
        return explicit

    cli_url = (cli_options or {}).get("database_url")
    if cli_url:
        return cli_url

    configured = config.get_main_option(ALEMBIC_URL_OPTION)
    if configured and configured != ALEMBIC_PLACEHOLDER_URL:
        return configured

    if not application_url:
        raise ValueError("Alembic database URL is not configured")
    return application_url


def apply_resolved_database_url(config: Config, url: str) -> None:
    """Set the URL consumed by offline and online Alembic execution."""

    _set_rendered_database_url(config, url)


def require_connection_database(connection: Connection, expected_database: str) -> None:
    """Fail before migration SQL when the server selected an unexpected database."""

    actual = connection.scalar(text("SELECT current_database()"))
    if actual != expected_database:
        raise DatabaseIdentityError(
            f"database identity check failed: expected {expected_database!r}, "
            f"connected to {actual!r}"
        )


def prepare_guarded_migration_connection(
    connection: Connection,
    expected_database: str,
) -> None:
    """Verify identity and end the read-only autobegin before Alembic starts DDL."""

    require_connection_database(connection, expected_database)
    connection.rollback()


def require_url_database(url: str, expected_database: str) -> None:
    """Fail before engine creation when a guarded migration URL is unsafe."""

    try:
        parsed = make_url(url)
    except Exception as exc:
        raise DatabaseIdentityError("guarded migration database URL is malformed") from exc
    if parsed.get_backend_name() != "postgresql" or parsed.database != expected_database:
        raise DatabaseIdentityError(
            f"guarded migration URL must target PostgreSQL database {expected_database!r}"
        )


def expected_database_name(config: Config) -> str | None:
    value: Any = config.attributes.get(EXPECTED_DATABASE_ATTRIBUTE)
    return value if isinstance(value, str) and value else None


def _set_rendered_database_url(config: Config, url: str) -> None:
    # Alembic Config uses ConfigParser interpolation. Doubling percent signs only for
    # storage preserves URL-encoded passwords when the option is read back.
    config.set_main_option(ALEMBIC_URL_OPTION, url.replace("%", "%%"))


__all__ = [
    "ALEMBIC_PLACEHOLDER_URL",
    "ALEMBIC_URL_ATTRIBUTE",
    "DatabaseIdentityError",
    "EXPECTED_DATABASE_ATTRIBUTE",
    "apply_resolved_database_url",
    "expected_database_name",
    "prepare_guarded_migration_connection",
    "require_connection_database",
    "require_url_database",
    "resolve_database_url",
    "set_explicit_database_url",
]

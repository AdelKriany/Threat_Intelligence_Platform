from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from alembic.config import Config
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL, Connection, Engine, make_url

from app.database.alembic_runtime import (
    EXPECTED_DATABASE_ATTRIBUTE,
    require_connection_database,
    set_explicit_database_url,
)

DISPOSABLE_DATABASE_NAME = "threatlens_phase6b_test"
ADMIN_DATABASE_NAME = "postgres"
OWNERSHIP_PREFIX = "threatlens-phase6b-test:"


class UnsafePostgresTestTarget(RuntimeError):
    """Raised before mutation when a PostgreSQL test target is not allowlisted."""


def validate_disposable_database_url(raw_url: str | None) -> URL:
    if not raw_url:
        raise UnsafePostgresTestTarget("Phase 6B PostgreSQL test URL is required")
    try:
        url = make_url(raw_url)
    except Exception as exc:
        raise UnsafePostgresTestTarget("Phase 6B PostgreSQL test URL is malformed") from exc
    if url.get_backend_name() != "postgresql":
        raise UnsafePostgresTestTarget("Phase 6B tests require a PostgreSQL URL")
    if url.database != DISPOSABLE_DATABASE_NAME:
        raise UnsafePostgresTestTarget(
            f"unsafe Phase 6B PostgreSQL target; only {DISPOSABLE_DATABASE_NAME!r} is allowed"
        )
    return url


def guarded_alembic_config(raw_url: str) -> Config:
    url = validate_disposable_database_url(raw_url)
    config = Config("alembic.ini")
    set_explicit_database_url(config, url.render_as_string(hide_password=False))
    config.attributes[EXPECTED_DATABASE_ATTRIBUTE] = DISPOSABLE_DATABASE_NAME
    return config


Revision = TypeVar("Revision", str, None)


def run_guarded_alembic_command(
    raw_url: str,
    operation: Callable[[Config, Revision], object],
    revision: Revision,
) -> None:
    """Preflight identity, then run Alembic with an in-env identity requirement."""

    url = validate_disposable_database_url(raw_url)
    engine = create_guarded_test_engine(url.render_as_string(hide_password=False))
    try:
        with engine.connect() as connection:
            require_connection_database(connection, DISPOSABLE_DATABASE_NAME)
    finally:
        engine.dispose()
    operation(guarded_alembic_config(raw_url), revision)


def create_guarded_test_engine(raw_url: str) -> Engine:
    url = validate_disposable_database_url(raw_url)
    engine = create_engine(url)

    @event.listens_for(engine, "checkout")
    def _verify_database(
        dbapi_connection: object,
        _connection_record: object,
        _connection_proxy: object,
    ) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SELECT current_database()")
            actual = cursor.fetchone()[0]
        finally:
            cursor.close()
            dbapi_connection.rollback()  # type: ignore[attr-defined]
        if actual != DISPOSABLE_DATABASE_NAME:
            raise UnsafePostgresTestTarget(
                "database identity check failed before test connection checkout: "
                f"expected {DISPOSABLE_DATABASE_NAME!r}, connected to {actual!r}"
            )

    return engine


def guarded_truncate_scoring_rows(engine: Engine) -> None:
    with engine.begin() as connection:
        require_connection_database(connection, DISPOSABLE_DATABASE_NAME)
        connection.execute(text("TRUNCATE TABLE raw_articles, indicators CASCADE"))


@dataclass(slots=True)
class OwnedDisposablePostgres:
    url: str
    admin_url: str
    ownership_marker: str
    created: bool = False

    @classmethod
    def create(cls, raw_url: str) -> OwnedDisposablePostgres:
        target_url = validate_disposable_database_url(raw_url)
        admin_url = target_url.set(database=ADMIN_DATABASE_NAME)
        marker = f"{OWNERSHIP_PREFIX}{uuid.uuid4()}"
        owned = cls(
            url=target_url.render_as_string(hide_password=False),
            admin_url=admin_url.render_as_string(hide_password=False),
            ownership_marker=marker,
        )
        owned._create()
        return owned

    def _create(self) -> None:
        admin_engine = create_engine(self.admin_url, isolation_level="AUTOCOMMIT")
        try:
            with admin_engine.connect() as connection:
                require_connection_database(connection, ADMIN_DATABASE_NAME)
                exists = connection.scalar(
                    text("SELECT 1 FROM pg_database WHERE datname = :name"),
                    {"name": DISPOSABLE_DATABASE_NAME},
                )
                if exists is not None:
                    raise UnsafePostgresTestTarget(
                        "disposable Phase 6B database already exists and is not owned by this run"
                    )
                connection.execute(text(f'CREATE DATABASE "{DISPOSABLE_DATABASE_NAME}"'))
                connection.execute(
                    text(
                        f'COMMENT ON DATABASE "{DISPOSABLE_DATABASE_NAME}" IS '
                        f"'{self.ownership_marker}'"
                    )
                )
                self.created = True
        finally:
            admin_engine.dispose()

        target_engine = create_guarded_test_engine(self.url)
        try:
            with target_engine.connect() as connection:
                self._require_marker(connection)
        except Exception:
            self.drop()
            raise
        finally:
            target_engine.dispose()

    def drop(self) -> None:
        if not self.created:
            return

        target_engine = create_guarded_test_engine(self.url)
        try:
            with target_engine.connect() as connection:
                self._require_marker(connection)
        finally:
            target_engine.dispose()

        admin_engine = create_engine(self.admin_url, isolation_level="AUTOCOMMIT")
        try:
            with admin_engine.connect() as connection:
                require_connection_database(connection, ADMIN_DATABASE_NAME)
                exists = connection.scalar(
                    text("SELECT 1 FROM pg_database WHERE datname = :name"),
                    {"name": DISPOSABLE_DATABASE_NAME},
                )
                if exists is None:
                    raise UnsafePostgresTestTarget(
                        "owned disposable Phase 6B database disappeared before cleanup"
                    )
                marker = connection.scalar(
                    text(
                        "SELECT pg_catalog.shobj_description(oid, 'pg_database') "
                        "FROM pg_database WHERE datname = :name"
                    ),
                    {"name": DISPOSABLE_DATABASE_NAME},
                )
                if marker != self.ownership_marker:
                    raise UnsafePostgresTestTarget(
                        "disposable Phase 6B database ownership marker does not match this run"
                    )
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :name AND pid <> pg_backend_pid()"
                    ),
                    {"name": DISPOSABLE_DATABASE_NAME},
                )
                connection.execute(text(f'DROP DATABASE "{DISPOSABLE_DATABASE_NAME}"'))
                self.created = False
        finally:
            admin_engine.dispose()

    def _require_marker(self, connection: Connection) -> None:
        require_connection_database(connection, DISPOSABLE_DATABASE_NAME)
        marker = connection.scalar(
            text(
                "SELECT pg_catalog.shobj_description(oid, 'pg_database') "
                "FROM pg_database WHERE datname = current_database()"
            )
        )
        if marker != self.ownership_marker:
            raise UnsafePostgresTestTarget(
                "disposable Phase 6B database ownership marker does not match this run"
            )


__all__ = [
    "ADMIN_DATABASE_NAME",
    "DISPOSABLE_DATABASE_NAME",
    "OwnedDisposablePostgres",
    "UnsafePostgresTestTarget",
    "create_guarded_test_engine",
    "guarded_alembic_config",
    "guarded_truncate_scoring_rows",
    "run_guarded_alembic_command",
    "validate_disposable_database_url",
]

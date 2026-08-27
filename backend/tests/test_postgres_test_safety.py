from __future__ import annotations

from contextlib import nullcontext
from unittest.mock import MagicMock

import pytest
from alembic import command

from app.database.alembic_runtime import (
    DatabaseIdentityError,
    prepare_guarded_migration_connection,
    require_connection_database,
)
from app.database.postgres_test_safety import (
    DISPOSABLE_DATABASE_NAME,
    OwnedDisposablePostgres,
    UnsafePostgresTestTarget,
    guarded_truncate_scoring_rows,
    run_guarded_alembic_command,
    validate_disposable_database_url,
)

SAFE_URL = "postgresql+psycopg://threatlens:secret@postgres:5432/threatlens_phase6b_test"


@pytest.mark.parametrize(
    "unsafe_url",
    [
        None,
        "",
        "not a url",
        "sqlite:///threatlens_phase6b_test.db",
        "postgresql+psycopg://user:secret@postgres/threatlens",
        "postgresql+psycopg://user:secret@postgres/postgres",
        "postgresql+psycopg://user:secret@postgres/template0",
        "postgresql+psycopg://user:secret@postgres/template1",
        "postgresql+psycopg://user:secret@postgres/unknown_test",
        "postgresql+psycopg://user:secret@postgres/",
    ],
)
def test_unsafe_targets_fail_closed(unsafe_url: str | None) -> None:
    with pytest.raises(UnsafePostgresTestTarget):
        validate_disposable_database_url(unsafe_url)


def test_development_target_is_rejected_before_any_destructive_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_engine = MagicMock()
    destructive_operation = MagicMock(spec=command.downgrade)
    monkeypatch.setattr(
        "app.database.postgres_test_safety.create_guarded_test_engine",
        create_engine,
    )

    with pytest.raises(UnsafePostgresTestTarget):
        run_guarded_alembic_command(
            "postgresql+psycopg://user:secret@postgres/threatlens",
            destructive_operation,
            "base",
        )

    create_engine.assert_not_called()
    destructive_operation.assert_not_called()


def test_connected_database_mismatch_aborts_before_alembic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MagicMock()
    connection.scalar.return_value = "threatlens"
    engine = MagicMock()
    engine.connect.return_value = nullcontext(connection)
    operation = MagicMock(spec=command.upgrade)
    monkeypatch.setattr(
        "app.database.postgres_test_safety.create_guarded_test_engine",
        lambda _url: engine,
    )

    with pytest.raises(DatabaseIdentityError, match="connected to 'threatlens'"):
        run_guarded_alembic_command(SAFE_URL, operation, "head")

    operation.assert_not_called()
    engine.dispose.assert_called_once_with()


def test_connected_database_mismatch_aborts_before_truncate() -> None:
    connection = MagicMock()
    connection.scalar.return_value = "threatlens"
    engine = MagicMock()
    engine.begin.return_value = nullcontext(connection)

    with pytest.raises(DatabaseIdentityError, match="connected to 'threatlens'"):
        guarded_truncate_scoring_rows(engine)

    connection.execute.assert_not_called()


def test_connection_identity_error_does_not_expose_url_password() -> None:
    connection = MagicMock()
    connection.scalar.return_value = "threatlens"

    with pytest.raises(DatabaseIdentityError) as raised:
        require_connection_database(connection, DISPOSABLE_DATABASE_NAME)

    assert "secret" not in str(raised.value)


def test_guarded_migration_identity_check_ends_read_only_autobegin() -> None:
    connection = MagicMock()
    connection.scalar.return_value = DISPOSABLE_DATABASE_NAME

    prepare_guarded_migration_connection(connection, DISPOSABLE_DATABASE_NAME)

    connection.rollback.assert_called_once_with()


def test_preexisting_disposable_database_is_not_claimed_or_mutated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MagicMock()
    connection.scalar.side_effect = ["postgres", 1]
    engine = MagicMock()
    engine.connect.return_value = nullcontext(connection)
    monkeypatch.setattr("app.database.postgres_test_safety.create_engine", lambda *a, **k: engine)

    with pytest.raises(UnsafePostgresTestTarget, match="already exists"):
        OwnedDisposablePostgres.create(SAFE_URL)

    assert all("CREATE DATABASE" not in str(call) for call in connection.execute.call_args_list)


def test_unowned_instance_cleanup_performs_no_connection_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_engine = MagicMock()
    monkeypatch.setattr("app.database.postgres_test_safety.create_engine", create_engine)
    owned = OwnedDisposablePostgres(
        url=SAFE_URL,
        admin_url="postgresql+psycopg://user:secret@postgres/postgres",
        ownership_marker="marker",
        created=False,
    )

    owned.drop()

    create_engine.assert_not_called()

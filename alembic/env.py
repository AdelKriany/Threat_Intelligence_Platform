from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"


def _load_runtime_settings() -> tuple[Any, Any]:
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))

    from app.core.config import settings
    from app.database.base import Base
    from app.ingestion import models as ingestion_models  # noqa: F401
    from app.models import phase6b as phase6b_models  # noqa: F401

    return settings, Base


settings, Base = _load_runtime_settings()

from app.database.alembic_runtime import (  # noqa: E402
    apply_resolved_database_url,
    expected_database_name,
    prepare_guarded_migration_connection,
    require_url_database,
    resolve_database_url,
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

resolved_database_url = resolve_database_url(
    config,
    application_url=settings.database_url,
    cli_options=context.get_x_argument(as_dictionary=True),
)
apply_resolved_database_url(config, resolved_database_url)
guarded_database_name = expected_database_name(config)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""

    if guarded_database_name is not None:
        require_url_database(resolved_database_url, guarded_database_name)
    context.configure(
        url=resolved_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        if guarded_database_name is not None:
            prepare_guarded_migration_connection(connection, guarded_database_name)
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

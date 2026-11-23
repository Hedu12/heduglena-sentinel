"""
Alembic async migration environment.

Configured for async SQLAlchemy (aiosqlite / asyncpg).
The database URL is read from core.config.settings so it respects
the same .env file and environment variables as the application.
No os.getenv() calls here — settings is the single source (P-02).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

# Ensure the backend package root is importable when Alembic is invoked
# from the backend/ directory via `python -m alembic ...`.
_HERE = Path(__file__).resolve().parent.parent  # backend/
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Import the declarative base so Alembic can diff ORM metadata.
from database.base import Base  # noqa: E402
# Import all models so their tables are registered on Base.metadata.
import database.models  # noqa: E402, F401

from core.config import settings  # noqa: E402

# Alembic config object — provides access to alembic.ini values.
config = context.config

# Override the sqlalchemy.url from alembic.ini with the validated settings value.
config.set_main_option("sqlalchemy.url", settings.database_url)

# Target metadata for autogenerate ("--autogenerate" flag on `alembic revision`).
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode (no database connection required).

    Emits SQL to stdout/file without connecting. Useful for reviewing
    what a migration will do before applying it.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Render timezone-aware datetime columns correctly.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: object) -> None:
    """Configure and run migrations using an existing sync connection."""
    context.configure(
        connection=connection,  # type: ignore[arg-type]
        target_metadata=target_metadata,
        # Required for SQLite ALTER TABLE emulation (rename, add column, etc.).
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode using an async engine.

    Creates a temporary engine scoped to the migration run so that the
    application engine (created by database.engine) is not affected.
    """
    connectable = create_async_engine(
        settings.database_url,
        # SQLite requires this for cross-thread use inside Alembic.
        connect_args={"check_same_thread": False}
        if settings.database_url.startswith("sqlite")
        else {},
    )

    async with connectable.connect() as connection:
        # run_sync executes the synchronous do_run_migrations inside the
        # async connection, as required by SQLAlchemy's async migration guide.
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())

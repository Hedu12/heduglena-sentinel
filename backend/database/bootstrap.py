"""
Fresh-install schema initialization.

At startup the application checks the database it is about to use:

    no tables at all        -> create the schema by running the Alembic migrations
                               (the same migrations the CLI runs; never create_all)
    at the migration head   -> nothing to do
    anything else           -> refuse to start, with instructions

Only an empty database is ever changed. A database that is behind, ahead of, or
outside Alembic's control is never migrated, altered or dropped automatically:
the operator backs it up and runs `python -m alembic upgrade head` deliberately.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, inspect
from sqlalchemy.ext.asyncio import AsyncEngine

from alembic import command
from core.exceptions import SentinelError

logger = logging.getLogger(__name__)

_MIGRATIONS = Path(__file__).resolve().parent.parent / "alembic"
_VERSION_TABLE = "alembic_version"


class SchemaStatus(StrEnum):
    CREATED = "created"
    CURRENT = "current"


class SchemaMismatchError(SentinelError):
    """The database exists but is not at the expected migration head."""


def _alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS))
    return config


def head_revision() -> str:
    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
    if head is None:
        raise SchemaMismatchError("no Alembic migrations found")
    return head


def _inspect(connection: Connection) -> tuple[list[str], str | None]:
    tables = [t for t in inspect(connection).get_table_names() if t != _VERSION_TABLE]
    revision = MigrationContext.configure(connection).get_current_revision()
    return tables, revision


def _upgrade(connection: Connection) -> None:
    config = _alembic_config()
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


async def ensure_schema(engine: AsyncEngine) -> SchemaStatus:
    """Create the schema on an empty database; verify it otherwise. Never destructive."""
    head = head_revision()
    async with engine.connect() as connection:
        tables, revision = await connection.run_sync(_inspect)
    if revision == head:
        logger.info("Database: schema is at migration head %s", head)
        return SchemaStatus.CURRENT
    if revision is None and not tables:
        logger.info("Database: empty database, creating schema with migrations to %s", head)
        async with engine.begin() as connection:
            await connection.run_sync(_upgrade)
        return SchemaStatus.CREATED
    found = revision or "none (tables exist without Alembic version)"
    raise SchemaMismatchError(
        f"database schema revision is {found}, expected {head}. Back up the database, then "
        "run `python -m alembic upgrade head` from backend/ before starting Sentinel."
    )

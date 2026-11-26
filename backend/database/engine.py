"""
Async SQLAlchemy engine and session factory.

The engine is created once at application startup via get_engine().
Route handlers and services receive a session via the get_session()
dependency — they never construct sessions directly.

Configuration comes exclusively from core.config.settings (P-02).
No os.getenv() calls here.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database.base import Base

logger = logging.getLogger(__name__)

# Module-level singletons, initialised by create_db_engine().
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def create_db_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
    """
    Create and cache the async engine.

    Call once at application startup, passing in settings.database_url.
    Subsequent calls return the cached engine.

    Args:
        database_url: SQLAlchemy async connection string.
        echo: If True, log all SQL statements (use only for debugging).
    """
    global _engine, _session_factory

    if _engine is not None:
        return _engine

    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        # Required for SQLite: allow the same connection across threads.
        connect_args["check_same_thread"] = False

    _engine = create_async_engine(
        database_url,
        echo=echo,
        connect_args=connect_args,
        # Pool configuration tuned for a single-process local deployment.
        pool_pre_ping=True,
    )

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    logger.info("Database engine created", extra={"database_url": _mask_url(database_url)})
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the session factory. Raises if the engine has not been initialised."""
    if _session_factory is None:
        raise RuntimeError(
            "Database engine not initialised. Call create_db_engine() before requesting sessions."
        )
    return _session_factory


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields one AsyncSession per request.

    Usage::

        @router.get("/example")
        async def example(session: AsyncSession = Depends(get_session)):
            ...
    """
    factory = get_session_factory()
    async with factory() as session:
        yield session


async def create_all_tables(engine: AsyncEngine) -> None:
    """
    Create all tables from the ORM metadata.

    Used in tests and for fresh installations before Alembic takes over.
    In production, Alembic migrations create the schema.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("All database tables created")


async def drop_all_tables(engine: AsyncEngine) -> None:
    """
    Drop all tables. Used only in tests to reset state between test runs.
    Never called from production code.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.info("All database tables dropped")


def dispose_engine() -> None:
    """
    Dispose the engine and reset module-level singletons.

    Called on application shutdown and between tests.
    """
    global _engine, _session_factory
    if _engine is not None:
        # Synchronous dispose is intentional here — this runs at shutdown.
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_engine.dispose())
            else:
                loop.run_until_complete(_engine.dispose())
        except RuntimeError:
            pass  # No event loop available; engine will be GC'd.
    _engine = None
    _session_factory = None


async def close_db_engine() -> None:
    """
    Dispose the engine and wait for its connections to close (application shutdown).

    Unlike dispose_engine(), this awaits the disposal instead of scheduling it, so
    no task is left behind when the event loop stops.
    """
    global _engine, _session_factory
    engine, _engine, _session_factory = _engine, None, None
    if engine is not None:
        await engine.dispose()


def _mask_url(url: str) -> str:
    """Remove password from a database URL for safe logging."""
    # Simple mask: replace everything between :// and @ with [masked].
    if "@" in url:
        scheme_end = url.index("://") + 3
        at_pos = url.rindex("@")
        return url[:scheme_end] + "[masked]" + url[at_pos:]
    return url

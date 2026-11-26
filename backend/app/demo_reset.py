"""
Demo reset: start a clean demo session without touching any security decision.

What a reset does (and nothing else):

    1. refuse unless DEMO_MODE=true and the database is a local SQLite file;
    2. stop the running session: live clients are told to reconnect, the demo scenario,
       monitoring loop and explanation worker are cancelled and awaited, and the
       database engine is disposed;
    3. archive the session's database file, intact, by renaming it into
       `<name>-demo-sessions/session-<UTC time>/`. Nothing is deleted or rewritten:
       every detection, score, transition, response and explanation stays readable;
    4. start a new session on an empty database exactly as application startup does:
       the schema is created by the Alembic migrations, and the defense state is
       restored by ThreatAssessmentService.restore_state(), which finds no history.

What a reset never does: it sets no defense state and no threat score, writes no
state transition or response record, and calls nothing in the state machine,
ResponsePlanner, ResponseGuard or the simulator. The new session's state is
whatever the authoritative pipeline establishes from an empty history. It takes no
input, so a client cannot choose a state, a score or an incident.

Real host telemetry keeps flowing: the new session collects fresh real samples.
"""

from __future__ import annotations

import asyncio
import gc
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy.engine import make_url

from app.lifecycle import start_session, stop_session
from core.config import settings
from core.exceptions import SentinelError
from models.enums import DefenseState

logger = logging.getLogger(__name__)

# SQLite side files that belong to the database file and move with it.
_SIDE_FILES = ("-journal", "-wal", "-shm")
_MOVE_ATTEMPTS = 8  # 0.05 s, 0.10 s, ... about 1.8 s in total


class DemoResetUnavailable(SentinelError):
    """A reset is not possible in this configuration."""


class DemoResetBusy(SentinelError):
    """A reset is already in progress."""


@dataclass(frozen=True, slots=True)
class ResetResult:
    archived_session: str  # a label only; no filesystem path is ever returned (SR-06)
    defense_state: DefenseState  # as established by the new session's runtime


def demo_database_file(database_url: str) -> Path | None:
    """The SQLite database file behind `database_url`, or None if it is not a local file."""
    url = make_url(database_url)
    database = url.database
    if not url.drivername.startswith("sqlite") or not database:
        return None
    if database == ":memory:" or database.startswith("file:"):
        return None
    return Path(database).resolve()


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def _move(source: Path, target: Path) -> None:
    # On Windows a file cannot be renamed while any handle is open. Retry briefly in
    # case another process (for example a virus scanner) holds it for a moment.
    for attempt in range(_MOVE_ATTEMPTS):
        try:
            source.replace(target)
            return
        except PermissionError:
            if attempt == _MOVE_ATTEMPTS - 1:
                raise
            gc.collect()
            await asyncio.sleep(0.05 * (attempt + 1))


async def _archive(database: Path, session: str) -> None:
    """Move the database file (and its side files) into the session archive, intact."""
    # The engine is disposed, but a closed session's SQLite connection can survive in
    # a reference cycle, keeping the file open (and unrenamable on Windows) until the
    # garbage collector finalizes it. Collect once, deliberately, before moving.
    gc.collect()
    target = database.parent / f"{database.stem}-demo-sessions" / session
    target.mkdir(parents=True, exist_ok=False)
    # Side files first: if one cannot move, the database file itself is still in place.
    for suffix in _SIDE_FILES:
        side = database.with_name(database.name + suffix)
        if side.exists():
            await _move(side, target / side.name)
    if database.exists():
        await _move(database, target / database.name)


def _lock(app: FastAPI) -> asyncio.Lock:
    lock: asyncio.Lock | None = getattr(app.state, "demo_reset_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        app.state.demo_reset_lock = lock
    return lock


async def reset_demo_session(
    app: FastAPI, *, clock: Callable[[], datetime] = _utc_now
) -> ResetResult:
    if not settings.demo_mode:
        raise DemoResetUnavailable("demo mode is disabled")
    database = demo_database_file(settings.database_url)
    if database is None:
        raise DemoResetUnavailable("a demo reset needs a local SQLite database file")
    lock = _lock(app)
    if lock.locked():
        raise DemoResetBusy("a demo reset is already in progress")
    async with lock:
        previous = getattr(app.state, "runtime", None)
        limiter = previous.demo.limiter if previous is not None else None
        session = f"session-{clock().strftime('%Y%m%dT%H%M%S%fZ')}"
        logger.warning("Demo: reset requested; archiving the current session as %s", session)
        await stop_session(app)
        try:
            await _archive(database, session)
        except OSError:
            logger.error("Demo: could not archive the session; resuming it", exc_info=True)
            await start_session(app)
            raise DemoResetUnavailable(
                "the demo session could not be archived; the previous session was resumed"
            ) from None
        runtime = await start_session(app)
        if limiter is not None:
            # The demo rate limit survives a reset, so a reset cannot be used to evade it.
            runtime.demo.limiter = limiter
        logger.warning("Demo: new session started (%s)", runtime.defense_state.value)
        return ResetResult(archived_session=session, defense_state=runtime.defense_state)

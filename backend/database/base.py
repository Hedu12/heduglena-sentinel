"""
SQLAlchemy declarative base and shared column helpers.

Uses MappedAsDataclass so that mapped_column(default=...) populates the
Python __init__, not just the SQL INSERT. This means model objects have
correct default values before they are flushed to the database.

No imports from the rest of the application — safe to import in alembic/env.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass


class Base(MappedAsDataclass, DeclarativeBase):
    """
    Project-wide declarative base.

    Inherits MappedAsDataclass so every subclass gets a generated __init__
    whose keyword arguments match the mapped columns, with correct defaults.
    """


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)

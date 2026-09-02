"""Lazy database engine, session factory, and FastAPI dependency."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Generator, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


DATABASE_URL_ENV = "DATABASE_URL"


class DatabaseConfigurationError(RuntimeError):
    """Raised when persistence is requested without database configuration."""


def get_database_url() -> str:
    """Return the configured database URL without embedding credentials."""
    database_url = os.getenv(DATABASE_URL_ENV, "").strip()
    if not database_url:
        raise DatabaseConfigurationError(
            f"{DATABASE_URL_ENV} must be configured before using persistence"
        )
    return database_url


def create_database_engine(
    database_url: Optional[str] = None,
    **engine_options: object,
) -> Engine:
    """Build an SQLAlchemy 2.x engine for the supplied or configured URL."""
    url = database_url or get_database_url()
    options = {"pool_pre_ping": True, **engine_options}
    return create_engine(url, **options)


@lru_cache
def get_engine() -> Engine:
    """Return the process-wide application engine lazily."""
    return create_database_engine()


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide session factory lazily."""
    return sessionmaker(
        bind=get_engine(),
        autoflush=False,
        expire_on_commit=False,
    )


def get_db() -> Generator[Session, None, None]:
    """Yield one SQLAlchemy session for a FastAPI request."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()

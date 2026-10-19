"""SQLAlchemy async engine and session-factory helpers."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine as _create


def create_async_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
    """Create an async engine, including SQLite's required connection option."""

    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return _create(database_url, echo=echo, connect_args=connect_args)


def create_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Create an explicit session factory for dependency injection and tests."""

    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


__all__ = ["create_async_engine", "create_session_factory"]

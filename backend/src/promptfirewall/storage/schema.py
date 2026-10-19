"""Schema initialization for local and test databases."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from promptfirewall.storage.models import Base


async def initialize_schema(engine: AsyncEngine) -> None:
    """Create all tables if they do not exist."""

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def close_schema_engine(engine: AsyncEngine) -> None:
    """Dispose pooled connections during application shutdown."""

    await engine.dispose()


__all__ = ["close_schema_engine", "initialize_schema"]

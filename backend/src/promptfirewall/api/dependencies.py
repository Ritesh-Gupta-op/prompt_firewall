"""FastAPI dependency seams for application services and database sessions."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import cast

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from promptfirewall.api.job_manager import ExperimentJobManager
from promptfirewall.config import Settings
from promptfirewall.storage.repository import StorageRepository
from promptfirewall.victim_app.service import VictimService


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.session_factory() as session:
        yield session


async def get_repository(request: Request) -> AsyncIterator[StorageRepository]:
    async with request.app.state.session_factory() as session:
        session.info["settings"] = request.app.state.settings
        session.info["session_factory"] = request.app.state.session_factory
        yield StorageRepository(session)


def get_victim_service(request: Request) -> VictimService:
    return cast(VictimService, request.app.state.victim_service)


def get_job_manager(request: Request) -> ExperimentJobManager:
    return cast(ExperimentJobManager, request.app.state.job_manager)


def get_settings_dependency(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


__all__ = ["get_job_manager", "get_repository", "get_session", "get_victim_service"]

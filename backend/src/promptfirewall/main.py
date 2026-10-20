"""Optional FastAPI application factory and process integration."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError

from promptfirewall.adapters.bridge import create_sync_model
from promptfirewall.api.errors import (
    ApiError,
    api_error_handler,
    duplicate_run_handler,
    http_error_handler,
    validation_error_handler,
)
from promptfirewall.api.job_manager import ExperimentJobManager, InProcessJobManager
from promptfirewall.api.routes import router
from promptfirewall.api.schemas import HealthResponse
from promptfirewall.api.security import ApiKeyMiddleware
from promptfirewall.config import Settings, get_settings
from promptfirewall.storage.database import create_async_engine, create_session_factory
from promptfirewall.storage.repository import DuplicateRunError, StorageRepository
from promptfirewall.storage.schema import close_schema_engine, initialize_schema
from promptfirewall.victim_app.service import VictimService


def create_app(
    settings: Settings | None = None,
    *,
    job_manager: ExperimentJobManager | None = None,
    victim_service: VictimService | None = None,
) -> FastAPI:
    """Build an isolated application for production or an integration test."""

    resolved_settings = settings or get_settings()
    engine = create_async_engine(resolved_settings.database_url)
    session_factory = create_session_factory(engine)
    manager = job_manager or InProcessJobManager(session_factory, resolved_settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await initialize_schema(engine)
        try:
            async with session_factory() as session:
                await StorageRepository(session).mark_interrupted()
            start = getattr(manager, "start", None)
            if start is not None:
                await start()
            yield
        finally:
            try:
                close = getattr(manager, "close", None)
                if close is not None:
                    await close()
            finally:
                await close_schema_engine(engine)

    app = FastAPI(
        title="PromptFirewall API",
        version="0.1.0",
        description="Optional typed HTTP API for synthetic prompt-injection security experiments.",
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.job_manager = manager
    app.state.victim_service = victim_service or VictimService(
        model=create_sync_model(resolved_settings),
    )
    app.add_middleware(ApiKeyMiddleware, settings=resolved_settings)

    app.add_exception_handler(ApiError, api_error_handler)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(DuplicateRunError, duplicate_run_handler)
    app.include_router(router, prefix="/api")

    @app.get("/health", response_model=HealthResponse, tags=["promptfirewall"])
    async def health() -> HealthResponse:
        return HealthResponse(status="ok", service="promptfirewall", database="configured")

    return app


app = create_app()

__all__ = ["app", "create_app"]

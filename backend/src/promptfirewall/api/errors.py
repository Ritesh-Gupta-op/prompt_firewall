"""Structured API errors and exception handlers."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from promptfirewall.storage.repository import DuplicateRunError


class ApiError(Exception):
    """An expected failure represented consistently in the HTTP API."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def error_body(code: str, message: str, *, details: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {"error": error}


async def api_error_handler(_: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, ApiError)
    return JSONResponse(
        status_code=error.status_code,
        content=jsonable_encoder(error_body(error.code, error.message, details=error.details)),
    )


async def validation_error_handler(_: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, RequestValidationError)
    return JSONResponse(
        status_code=422,
        content=error_body(
            "validation_error", "Request validation failed",
            details=jsonable_encoder(error.errors(), custom_encoder={ValueError: str}),
        ),
    )


async def http_error_handler(_: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, HTTPException)
    detail = error.detail
    content = detail if isinstance(detail, dict) and "error" in detail else error_body(
        "http_error", str(detail)
    )
    return JSONResponse(status_code=error.status_code, content=content, headers=error.headers)


async def duplicate_run_handler(_: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, DuplicateRunError)
    return JSONResponse(
        status_code=409,
        content=error_body("duplicate_run_id", f"Run ID already exists: {error}"),
    )


__all__ = [
    "ApiError",
    "api_error_handler",
    "error_body",
    "http_error_handler",
    "validation_error_handler",
]

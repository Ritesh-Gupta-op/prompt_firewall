"""Structured API errors and exception handlers."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


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


async def api_error_handler(_: Request, error: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content=error_body(error.code, error.message, details=error.details),
    )


async def validation_error_handler(_: Request, error: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_body("validation_error", "Request validation failed", details=error.errors()),
    )


async def http_error_handler(_: Request, error: HTTPException) -> JSONResponse:
    detail = error.detail
    content = detail if isinstance(detail, dict) and "error" in detail else error_body(
        "http_error", str(detail)
    )
    return JSONResponse(status_code=error.status_code, content=content, headers=error.headers)


__all__ = [
    "ApiError",
    "api_error_handler",
    "error_body",
    "http_error_handler",
    "validation_error_handler",
]

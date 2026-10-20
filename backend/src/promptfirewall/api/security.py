"""Service-to-service access control; test identity is not authentication."""

from __future__ import annotations

from secrets import compare_digest

from starlette.types import ASGIApp, Receive, Scope, Send

from promptfirewall.api.errors import error_body
from promptfirewall.config import Settings


class ApiKeyMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.key = settings.api_key.get_secret_value().encode() if settings.api_key else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Liveness is intentionally public; catalogs, evidence, docs and writes are not.
        if self.key is not None and scope["type"] == "http" and scope["path"] != "/health":
            headers = dict(scope.get("headers", []))
            supplied = headers.get(b"x-api-key", b"")
            if not compare_digest(supplied, self.key):
                from starlette.responses import JSONResponse

                response = JSONResponse(
                    error_body("unauthorized", "A valid X-API-Key is required"), status_code=401,
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)

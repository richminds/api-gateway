"""Domain exception → HTTP status mapping.

The core raises domain exceptions; this is the only place that decides what
each one means over HTTP. Keeping the mapping here lets ``features/`` stay
framework-free and importable without FastAPI.

    AuthenticationError  → 401  no credential, or an invalid/expired/revoked one
    AuthorizationError   → 403  authenticated, but not allowed to do this
    RateLimitExceeded    → 429  over the user, account or IP request budget
    RouteNotFound        → 404  no service is registered for this path
    UpstreamError        → 504  a downstream service timed out
                         → 502  a downstream service could not be reached
    ConfigurationError   → 500  the deployment is misconfigured

Every body has the same shape — ``{"error": {"code", "message", "request_id",
...}}`` — matching llm-gateway and knowledge-service, so a client parses one
error format for the whole platform. ``request_id`` is on every error
deliberately: it is what turns "it failed" in a bug report into the exact log
line for that call.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from features.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    RouteNotFound,
    UpstreamError,
)
from features.rate_limiter import RateLimitExceeded

logger = logging.getLogger(__name__)


def problem(
    request: Request,
    status: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    body = {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", ""),
            **extra,
        }
    }
    return JSONResponse(status_code=status, content=body, headers=headers)


def unauthorized(request: Request, message: str, reason: str = "invalid_token") -> JSONResponse:
    """401 with the WWW-Authenticate header RFC 7235 requires on a 401.

    Shared with the auth middleware, which rejects before any exception handler
    would run — a middleware returns a response rather than raising into the
    routing layer, so it needs this directly.
    """
    return problem(
        request,
        401,
        "unauthorized",
        message,
        headers={"WWW-Authenticate": "Bearer"},
        reason=reason,
    )


def rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """429 with an honest Retry-After.

    ``Retry-After`` is the real window expiry, not a fixed guess, so a
    well-behaved client backs off exactly as long as it needs to. ``scope``
    tells the client *which* budget it hit — see RateLimitExceeded for why
    that distinction has to reach them.
    """
    retry_after = max(1, int(exc.retry_after_seconds + 0.999))
    return problem(
        request,
        429,
        "rate_limit_exceeded",
        str(exc),
        headers={
            "Retry-After": str(retry_after),
            "X-RateLimit-Limit": str(exc.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Scope": exc.scope,
        },
        scope=exc.scope,
        limit=exc.limit,
        current=exc.current,
        retry_after_seconds=round(exc.retry_after_seconds, 1),
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthenticationError)
    async def _unauthenticated(request: Request, exc: AuthenticationError) -> JSONResponse:
        return unauthorized(request, str(exc), exc.reason)

    @app.exception_handler(AuthorizationError)
    async def _forbidden(request: Request, exc: AuthorizationError) -> JSONResponse:
        return problem(request, 403, "forbidden", str(exc))

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return rate_limited(request, exc)

    @app.exception_handler(RouteNotFound)
    async def _no_route(request: Request, exc: RouteNotFound) -> JSONResponse:
        return problem(request, 404, "route_not_found", str(exc), path=exc.path)

    @app.exception_handler(UpstreamError)
    async def _upstream(request: Request, exc: UpstreamError) -> JSONResponse:
        # Logged at error level: an unreachable upstream is an operational
        # event that should page someone, not a routine client mistake.
        logger.error("Upstream failure: %s", exc, extra={"service": exc.service})
        if exc.timeout:
            return problem(
                request,
                504,
                "upstream_timeout",
                f"The '{exc.service}' service did not respond in time.",
                service=exc.service,
            )
        return problem(
            request,
            502,
            "upstream_unavailable",
            f"The '{exc.service}' service is unavailable.",
            headers={"Retry-After": "5"},
            service=exc.service,
        )

    @app.exception_handler(ConfigurationError)
    async def _misconfigured(request: Request, exc: ConfigurationError) -> JSONResponse:
        # Not the caller's fault — surface it loudly so it shows up in alerts.
        logger.error("Gateway misconfigured: %s", exc)
        return problem(request, 500, "gateway_misconfigured", str(exc))

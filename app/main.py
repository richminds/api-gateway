"""API Gateway — the single ingress for the platform.

A **router**. It implements no business capability of its own: every request
is forwarded to the service that owns it, auth-service included. What it adds
is the cross-cutting work that would otherwise be reimplemented in each
service, inconsistently:

  * **authenticates** every request by asking auth-service to validate the
    token, except the paths configured as public (``GATEWAY_PUBLIC_PATHS`` —
    sign-in and sign-up, which cannot carry a token yet). The gateway holds no
    signing key and understands nothing about token format;
  * **logs** every request in one place, in one format, with a verified user
    and account on it;
  * **meters** requests per user and per account (features/usage.py) and
    **budgets** them per user, per account and — for unauthenticated traffic —
    per IP (features/rate_limiter.py);
  * **routes** what survives all of that to the owning service, with the
    caller's identity attached as headers those services can trust.

Being the sole ingress is also what keeps auth-service private: every call to
it in the platform is a request this gateway routed.

Run it::

    uvicorn app.main:app --reload --port 8000
    # or: python run.py
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from features import __version__
from features.access_policy import build_access_policy
from features.config import gateway_settings
from features.identity_cache import init_identity_cache
from features.introspection import TokenIntrospector
from features.mongo_connection import close_connection
from features.proxy import ProxyClient
from features.rate_limiter import RateLimiter
from features.registry import build_registry
from features.usage import close_usage_tracker, init_usage_tracker

from .config import service_settings
from .controllers import admin_controller, health_controller, proxy_controller
from .errors import register_exception_handlers
from .logging_config import configure_logging
from .middleware.auth import AuthMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.request_context import RequestContextMiddleware

logger = logging.getLogger(__name__)


def _warn_on_insecure_config() -> None:
    """Refuse to let an unsafe configuration go unnoticed on a real deployment.

    These are fine on localhost and in CI, and severe in production. Logged at
    ERROR in production so they surface in alerting rather than scrolling past
    in a startup log nobody reads.
    """
    complain = logger.error if service_settings.is_production else logger.warning

    if not gateway_settings.introspection_configured:
        complain(
            "GATEWAY_INTROSPECTION_URL is empty — the gateway has no way to "
            "validate a token, so EVERY authenticated request will fail with "
            "502. Point it at auth-service's GET /auth/me."
        )

    if not gateway_settings.auth_enabled:
        complain(
            "GATEWAY_AUTH_ENABLED is false — EVERY endpoint is public and no "
            "token is checked. This is a local-development setting only."
        )

    if service_settings.is_production and service_settings.docs_enabled:
        logger.warning(
            "APIGW_DOCS_ENABLED is true in production — /docs publishes this "
            "gateway's API surface. Set it false if the gateway is internet-facing."
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging(service_settings.log_level, service_settings.log_format)
    _warn_on_insecure_config()

    # Built once and shared: each holds a connection pool, and building them
    # per request would open a new pool per call and defeat keepalive entirely.
    app.state.registry = build_registry()
    app.state.access_policy = build_access_policy()
    app.state.proxy_client = ProxyClient()
    # Built before the introspector, which takes it as its second tier: one
    # constructed without it would silently run process-local only, and the
    # symptom (auth-service seeing N times the expected traffic) shows up in
    # someone else's dashboard rather than here.
    app.state.identity_cache = await init_identity_cache()
    app.state.introspector = TokenIntrospector(shared=app.state.identity_cache)
    await app.state.proxy_client.start()
    await app.state.introspector.start()

    await init_usage_tracker()

    logger.info(
        "API Gateway ready — auth=%s via %s (cache %.0fs, grace %.0fs, shared=%s) "
        "upstreams=%d public=%d storage=%s",
        "enforced" if gateway_settings.auth_enabled else "DISABLED",
        gateway_settings.introspection_url or "NOTHING CONFIGURED",
        gateway_settings.introspection_cache_ttl_seconds,
        gateway_settings.introspection_stale_grace_seconds,
        "yes" if app.state.identity_cache.enabled else "no",
        len(app.state.registry),
        len(app.state.access_policy),
        "mongodb" if gateway_settings.mongo_uri else "in-memory",
    )

    yield

    # Usage first: its final flush needs the Mongo connection that the last
    # line closes. Reversing these two silently loses the last interval of
    # counters on every single deploy.
    await close_usage_tracker()
    await app.state.introspector.close()
    await app.state.proxy_client.close()
    if gateway_settings.mongo_uri:
        await close_connection()
    logger.info("API Gateway shut down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="API Gateway",
        version=__version__,
        description=(
            "Single ingress for the platform. Routes every request to the "
            "service that owns it, having auth-service validate the caller's "
            "token first (except on the paths configured as public), metering "
            "requests per user and per account, and enforcing per-user and "
            "per-account budgets. It implements no endpoints of its own beyond "
            "health and its own observability."
        ),
        lifespan=lifespan,
        root_path=service_settings.root_path,
        docs_url="/docs" if service_settings.docs_enabled else None,
        redoc_url="/redoc" if service_settings.docs_enabled else None,
        openapi_url="/openapi.json" if service_settings.docs_enabled else None,
    )

    # ── Middleware ──────────────────────────────────────────────────────────
    # Starlette runs middleware in REVERSE registration order: the LAST one
    # added is the OUTERMOST. So this block reads inside-out, and the intended
    # nesting, from the outside in, is:
    #
    #   CORS            → must wrap everything, or a 401 reaches a browser
    #                     without CORS headers and the client sees an opaque
    #                     network error instead of the actual status.
    #   RequestContext  → mints the correlation ID and writes the access log,
    #                     so it must see rejected requests too.
    #   Auth            → establishes the identity...
    #   RateLimit       → ...which this one budgets against, so it must run
    #                     INSIDE auth and is therefore registered FIRST.
    #
    # Registering these two the other way round is a silent failure, not a
    # loud one: the rate limiter still runs, sees no identity yet, and quietly
    # budgets every authenticated caller by IP — so a whole office shares one
    # user's ceiling and the per-user and per-account limits never apply at all.
    rate_limiter = RateLimiter()
    # Held on app.state so GET /v1/rate-limits can read the live windows —
    # the middleware instance itself is not otherwise reachable.
    app.state.rate_limiter = rate_limiter
    app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)

    app.add_middleware(AuthMiddleware)
    app.add_middleware(RequestContextMiddleware)

    origins = service_settings.parsed_cors_origins()
    origin_regex = service_settings.cors_origin_regex.strip()
    if origins or origin_regex:
        if "*" in origins:
            # Browsers reject a wildcard origin on a credentialed request, and
            # every call here carries an Authorization header — so "*" doesn't
            # loosen anything, it just silently blocks everything.
            logger.warning(
                "APIGW_CORS_ORIGINS contains '*', which browsers refuse on "
                "credentialed requests — list real origins, or use "
                "APIGW_CORS_ORIGIN_REGEX."
            )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_origin_regex=origin_regex or None,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            # So a browser client can read the correlation ID off a failed
            # response and quote it in a bug report. Response headers are not
            # visible to JS unless they are exposed explicitly.
            expose_headers=[
                service_settings.request_id_header,
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "Retry-After",
            ],
        )

    register_exception_handlers(app)

    @app.get("/", tags=["health"], summary="Service banner")
    async def root() -> dict:
        return {
            "service": "api-gateway",
            "version": __version__,
            "docs": "/docs" if service_settings.docs_enabled else None,
            "health": "/health",
        }

    app.include_router(health_controller.router)
    app.include_router(admin_controller.me_router)
    app.include_router(admin_controller.router)

    # LAST, always. It matches every path, and FastAPI resolves routes in
    # registration order — registered any earlier it would swallow /health and
    # the admin routes and try to proxy them upstream.
    app.include_router(proxy_controller.router)

    return app


app = create_app()

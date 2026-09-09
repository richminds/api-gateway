"""API Gateway — the single ingress for the platform.

Every client request enters here and nowhere else. The gateway:

  * **authenticates** every request against a JWT minted by auth-service —
    except sign-in and sign-up, which cannot have a token yet;
  * **is the only service that talks to auth-service**, which stays on the
    private network (see features/auth_client.py);
  * **logs** every request in one place, in one format, with a verified user
    and account on it;
  * **meters** requests per user and per account (features/usage.py) and
    **budgets** them per user, per account and — for sign-in traffic — per IP
    (features/rate_limiter.py);
  * **proxies** what survives all of that to llm-gateway or knowledge-service,
    with the caller's identity attached as headers those services can trust.

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
from features.auth_client import AuthServiceClient
from features.config import gateway_settings
from features.mongo_connection import close_connection
from features.proxy import ProxyClient
from features.rate_limiter import RateLimiter
from features.registry import build_registry
from features.revocation import init_revocation_store
from features.usage import close_usage_tracker, init_usage_tracker

from .config import service_settings
from .controllers import (
    admin_controller,
    auth_controller,
    health_controller,
    proxy_controller,
)
from .errors import register_exception_handlers
from .logging_config import configure_logging
from .middleware.auth import AuthMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.request_context import RequestContextMiddleware

logger = logging.getLogger(__name__)


def _warn_on_insecure_config() -> None:
    """Refuse to let an unsafe configuration go unnoticed on a real deployment.

    Both of these are fine on localhost and in CI, and both are severe in
    production — a default secret means anyone who has read this source can
    forge a token for any user, and disabled auth means the front door is
    simply open. Logged at ERROR in production so they surface in alerting
    rather than scrolling past in a startup log nobody reads.
    """
    complain = logger.error if service_settings.is_production else logger.warning

    if gateway_settings.jwt_secret_is_default:
        complain(
            "GATEWAY_JWT_SECRET is unset — using the built-in development "
            "default. Anyone who has read this source can forge a valid token "
            "for any user. Set it to the same value as AUTH_JWT_SECRET before "
            "exposing this gateway."
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
    app.state.auth_client = AuthServiceClient()
    app.state.proxy_client = ProxyClient()
    await app.state.auth_client.start()
    await app.state.proxy_client.start()

    await init_revocation_store()
    await init_usage_tracker()

    logger.info(
        "API Gateway ready — auth=%s upstreams=%d storage=%s",
        "enforced" if gateway_settings.auth_enabled else "DISABLED",
        len(app.state.registry),
        "mongodb" if gateway_settings.mongo_uri else "in-memory",
    )

    yield

    # Usage first: its final flush needs the Mongo connection that the last
    # line closes. Reversing these two silently loses the last interval of
    # counters on every single deploy.
    await close_usage_tracker()
    await app.state.proxy_client.close()
    await app.state.auth_client.close()
    if gateway_settings.mongo_uri:
        await close_connection()
    logger.info("API Gateway shut down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="API Gateway",
        version=__version__,
        description=(
            "Single ingress for the platform. Authenticates every request "
            "against auth-service-issued JWTs (except sign-in and sign-up), "
            "meters requests per user and per account, and reverse-proxies to "
            "the services behind it. The only service that communicates with "
            "auth-service."
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
            "login": "/auth/login",
        }

    app.include_router(health_controller.router)
    app.include_router(auth_controller.router)
    app.include_router(admin_controller.me_router)
    app.include_router(admin_controller.router)

    # LAST, always. It matches every path, and FastAPI resolves routes in
    # registration order — registered any earlier it would swallow /auth/login,
    # /health and the admin routes and try to proxy them upstream.
    app.include_router(proxy_controller.router)

    return app


app = create_app()

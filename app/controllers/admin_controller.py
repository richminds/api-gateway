"""Operational endpoints — usage, live rate-limit windows, resolved config.

Platform-staff only (``require_admin`` on the whole router). These expose
every tenant's traffic volumes and the gateway's own configuration, which is
not something one customer should be able to read about another.

    GET /v1/usage         request counts per user / account / service
    GET /v1/usage/me      the caller's own counts — NOT staff-gated
    GET /v1/rate-limits   live sliding windows
    GET /v1/config        resolved, non-secret configuration
    GET /v1/routes        the route table

The counts come from ``features/usage.py`` and reflect what THIS process has
seen since it started. With several replicas behind a load balancer, each has
its own view — the durable, merged totals are the Mongo documents the tracker
flushes into, which a reporting job should read directly rather than by
fanning out across replicas.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request

from features import __version__
from features.config import gateway_settings
from features.registry import ServiceRegistry
from features.identity import CallerIdentity
from features.usage import get_usage_tracker

from ..config import service_settings
from ..dependencies import get_identity, get_registry, require_admin
from ..models.health_model import (
    ConfigResponse,
    RateLimitResponse,
    RateLimitRow,
    RouteRow,
    UsageResponse,
    UsageRow,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["admin"], dependencies=[Depends(require_admin)])

# Separate router: /v1/usage/me is the caller's own data, so it needs a token
# but not staff rights. Mounting it on the gated router above and trying to
# exempt one path would mean the gate is applied "except sometimes", which is
# how an exemption ends up covering more than intended.
me_router = APIRouter(prefix="/v1", tags=["usage"])


def _rows(records) -> list[UsageRow]:
    return [UsageRow(**r.as_dict()) for r in records]


@router.get("/usage", response_model=UsageResponse, summary="Request counts")
async def usage(
    user_id: str = Query("", description="Filter to one user"),
    account_id: str = Query("", description="Filter to one account"),
    service: str = Query("", description="Filter to one upstream service"),
) -> UsageResponse:
    """Per-user and per-account request counts, with rollups.

    ``rows`` is the per-(user, account, service, day) breakdown; the three
    rollups are that same data grouped, because "requests per account" is the
    question people actually ask and deriving it client-side from the raw rows
    is busywork the server can do once.

    The rollups are always computed over everything this process has seen, not
    over the filtered rows — a filtered rollup would be a single row restating
    the filter, which is not useful.
    """
    tracker = get_usage_tracker()
    return UsageResponse(
        rows=_rows(tracker.snapshot(user_id=user_id, account_id=account_id, service=service)),
        by_user=tracker.aggregate("user"),
        by_account=tracker.aggregate("account"),
        by_service=tracker.aggregate("service"),
    )


@me_router.get("/usage/me", response_model=UsageResponse, summary="Your own usage")
async def my_usage(
    identity: CallerIdentity = Depends(get_identity),
) -> UsageResponse:
    """The calling user's own request counts.

    Not staff-gated: reading your own usage is not privileged, and a client
    that wants to show "you have made N requests today" should not need a
    platform administrator. Scoped to the token's user_id, which the caller
    cannot influence — there is no parameter to widen it.
    """
    tracker = get_usage_tracker()
    return UsageResponse(rows=_rows(tracker.snapshot(user_id=identity.user_id)))


@router.get(
    "/rate-limits", response_model=RateLimitResponse, summary="Live rate-limit windows"
)
async def rate_limits(request: Request) -> RateLimitResponse:
    """Every currently-populated sliding window.

    Shows who is close to a ceiling right now — the thing to look at when
    someone reports intermittent 429s. Empty windows are not listed: a key
    only appears once it has made a request in the last 60 seconds.
    """
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return RateLimitResponse()
    return RateLimitResponse(
        windows=[
            RateLimitRow(
                key=u.key,
                scope=u.scope,
                requests_this_minute=u.requests_this_minute,
                limit=u.limit,
                remaining=u.remaining,
            )
            for u in limiter.get_all_usage()
        ]
    )


@router.get("/routes", response_model=list[RouteRow], summary="The route table")
async def routes(registry: ServiceRegistry = Depends(get_registry)) -> list[RouteRow]:
    """Which path prefix goes to which service, in match order (longest first)."""
    return [
        RouteRow(name=r.name, prefix=r.prefix, base_url=r.base_url) for r in registry
    ]


def _identity_cache(request: Request):
    """The shared cache, or a disabled stand-in when the lifespan never ran."""
    from features.identity_cache import IdentityCache

    return getattr(request.app.state, "identity_cache", None) or IdentityCache()


@router.get("/config", response_model=ConfigResponse, summary="Resolved configuration")
async def config(request: Request, registry: ServiceRegistry = Depends(get_registry)) -> ConfigResponse:
    """What this instance actually resolved from its environment.

    Secrets are never included — not the JWT secret, not the Mongo URI.
    There is no signing key here to leak — the gateway holds none.
    ``mongo_configured`` reports the only thing anyone needs to know about the
    Mongo URI, which is whether it was set at all.
    Turn the endpoint off entirely with ``APIGW_EXPOSE_CONFIG_ENDPOINT=false``.
    """
    s = gateway_settings
    return ConfigResponse(
        version=__version__,
        environment=service_settings.environment,
        auth_enabled=s.auth_enabled,
        public_paths=request.app.state.access_policy.describe(),
        introspection_url=s.introspection_url,
        introspection_cache_ttl_seconds=s.introspection_cache_ttl_seconds,
        introspection_stale_grace_seconds=s.introspection_stale_grace_seconds,
        introspection_cache_entries=request.app.state.introspector.cache_size(),
        identity_cache_enabled=_identity_cache(request).enabled,
        identity_cache_entries=await _identity_cache(request).size(),
        rate_limit_enabled=s.rate_limit_enabled,
        user_rpm=s.user_rpm,
        account_rpm=s.account_rpm,
        anonymous_rpm=s.anonymous_rpm,
        usage_tracking_enabled=s.usage_tracking_enabled,
        mongo_configured=bool(s.mongo_uri),
        routes=[
            RouteRow(name=r.name, prefix=r.prefix, base_url=r.base_url)
            for r in registry
        ],
    )

"""Health endpoints — always public, no credential required.

    GET /health            readiness (alias of /health/ready)
    GET /health/live       liveness — the process is up, no I/O
    GET /health/ready      readiness — auth-service reachable, storage healthy
    GET /health/upstreams  live probe of every registered service

Liveness must never touch a dependency: a Mongo blip or a restarting
auth-service should not get this container killed. Readiness may, because that
is exactly the signal a load balancer needs.

The distinction that matters here, and it is specific to a gateway: **a down
upstream is not an unready gateway.** If llm-gateway is unreachable, this
service should stay in the load balancer, keep serving knowledge-service
traffic, and return an honest 502 for the rest — all of which requires it to
keep receiving requests. Reporting itself unready would take the whole
platform down because one service behind it was.

auth-service is treated differently: without it nobody can sign in at all, so
it is a real readiness dependency. Even then it is reported as "degraded"
rather than fatal, since traffic holding a valid token is served entirely from
local verification and does not touch auth-service at all.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx
from fastapi import APIRouter, Depends, Request, Response

from features import __version__
from features.auth_client import AuthServiceClient
from features.config import gateway_settings
from features.registry import ServiceRegistry

from ..dependencies import get_auth_client, get_proxy_client, get_registry
from ..models.health_model import (
    DependencyStatus,
    LivenessResponse,
    ReadinessResponse,
    UpstreamStatus,
    UpstreamsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LivenessResponse, summary="Liveness probe")
async def live() -> LivenessResponse:
    return LivenessResponse(version=__version__)


async def _readiness(
    auth: AuthServiceClient, registry: ServiceRegistry
) -> ReadinessResponse:
    deps: list[DependencyStatus] = []

    # ── auth-service ────────────────────────────────────────────────────────
    started = time.perf_counter()
    auth_ok = await auth.ping()
    auth_latency = (time.perf_counter() - started) * 1000
    deps.append(
        DependencyStatus(
            name="auth-service",
            status="ok" if auth_ok else "degraded",
            detail=(
                f"reachable at {auth.base_url}"
                if auth_ok
                else f"unreachable at {auth.base_url} — sign-in and sign-up will "
                "fail, but requests with a valid token are unaffected "
                "(tokens are verified locally)"
            ),
            latency_ms=round(auth_latency, 1),
        )
    )

    # ── route table ─────────────────────────────────────────────────────────
    # Configuration, not connectivity — whether the upstreams are actually up
    # is /health/upstreams, deliberately not part of readiness (see the module
    # docstring).
    deps.append(
        DependencyStatus(
            name="route_table",
            status="ok" if len(registry) else "degraded",
            detail=(
                ", ".join(f"{r.prefix} -> {r.name}" for r in registry)
                if len(registry)
                else "No services registered — set GATEWAY_ROUTES."
            ),
        )
    )

    # ── storage ─────────────────────────────────────────────────────────────
    if gateway_settings.mongo_uri:
        from features.mongo_connection import get_connection

        try:
            conn = await get_connection()
            healthy = await conn.ping()
            deps.append(
                DependencyStatus(
                    name="mongodb",
                    status="ok" if healthy else "degraded",
                    detail=(
                        f"db={conn.db_name}"
                        if healthy
                        else "ping failed — usage counters and shared revocation "
                        "are degraded to in-process only"
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001 — readiness reports, never raises
            deps.append(
                DependencyStatus(name="mongodb", status="degraded", detail=str(exc))
            )
    else:
        deps.append(
            DependencyStatus(
                name="mongodb",
                status="ok",
                detail="not configured — usage counters and revocations are "
                "in-process (fine for a single replica)",
            )
        )

    # "degraded" never makes the gateway unready: every degraded state above
    # still leaves it able to serve authenticated traffic, which is the bulk of
    # what it does. Only an outright "unavailable" would, and nothing here
    # currently produces one.
    overall = "unavailable" if any(d.status == "unavailable" for d in deps) else "ok"
    return ReadinessResponse(status=overall, version=__version__, dependencies=deps)


@router.get("", response_model=ReadinessResponse, summary="Readiness probe")
async def health(
    response: Response,
    auth: AuthServiceClient = Depends(get_auth_client),
    registry: ServiceRegistry = Depends(get_registry),
) -> ReadinessResponse:
    result = await _readiness(auth, registry)
    if result.status != "ok":
        response.status_code = 503
    return result


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe")
async def ready(
    response: Response,
    auth: AuthServiceClient = Depends(get_auth_client),
    registry: ServiceRegistry = Depends(get_registry),
) -> ReadinessResponse:
    result = await _readiness(auth, registry)
    if result.status != "ok":
        response.status_code = 503
    return result


@router.get(
    "/upstreams", response_model=UpstreamsResponse, summary="Probe every service"
)
async def upstreams(
    request: Request,
    registry: ServiceRegistry = Depends(get_registry),
) -> UpstreamsResponse:
    """Live health of every registered service, probed concurrently.

    An operator's view, not a probe target — it makes one request per upstream,
    so pointing an orchestrator at it would multiply health traffic across the
    whole platform. Use /health/ready for that.

    Each service is asked for its own /health/live, which every service in this
    platform serves without a credential.
    """
    proxy_client = get_proxy_client(request)

    async def probe(route) -> UpstreamStatus:
        started = time.perf_counter()
        try:
            response = await proxy_client.client.get(
                f"{route.base_url}/health/live", timeout=5.0
            )
            latency = (time.perf_counter() - started) * 1000
            return UpstreamStatus(
                name=route.name,
                prefix=route.prefix,
                base_url=route.base_url,
                status="ok" if response.status_code == 200 else "degraded",
                latency_ms=round(latency, 1),
                detail=f"HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            return UpstreamStatus(
                name=route.name,
                prefix=route.prefix,
                base_url=route.base_url,
                status="unavailable",
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                detail=str(exc) or exc.__class__.__name__,
            )

    # Concurrently: probing serially would make this endpoint as slow as the
    # sum of every timeout, and the slowest case is exactly when someone is
    # using it to find out what is broken.
    results = await asyncio.gather(*(probe(r) for r in registry))
    return UpstreamsResponse(upstreams=list(results))

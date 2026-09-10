"""Health and observability response models.

Same shape as the sibling services' health models, so one monitoring
configuration reads all four services.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    """The process is up. Touches no dependency, by design — a Mongo blip or a
    down auth-service must not get the container killed and restarted."""

    status: str = "alive"
    service: str = "api-gateway"
    version: str = ""


class DependencyStatus(BaseModel):
    name: str
    status: str        # "ok" | "degraded" | "unavailable"
    detail: str = ""
    latency_ms: float | None = None


class ReadinessResponse(BaseModel):
    """Whether this instance should receive traffic.

    ``status`` is "ok" only when everything the gateway *needs* is working.
    auth-service is such a dependency (without it nobody can sign in) but the
    upstream application services are not: a gateway whose llm-gateway is down
    should still serve knowledge-service traffic and still return an honest 502
    for the rest, which it can only do if it stays in the load balancer.
    """

    status: str = "ok"
    service: str = "api-gateway"
    version: str = ""
    dependencies: list[DependencyStatus] = Field(default_factory=list)


class UpstreamStatus(BaseModel):
    name: str
    prefix: str
    base_url: str
    status: str = "unknown"
    latency_ms: float | None = None
    detail: str = ""


class UpstreamsResponse(BaseModel):
    """Live probe of every registered service. Operational, not a probe target —
    it makes one request per upstream, so an orchestrator should keep polling
    /health/ready instead."""

    upstreams: list[UpstreamStatus] = Field(default_factory=list)


class UsageRow(BaseModel):
    user_id: str = ""
    account_id: str = ""
    service: str = ""
    day: str = ""
    requests: int = 0
    errors: int = 0
    avg_duration_ms: float = 0.0
    status_2xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0


class UsageResponse(BaseModel):
    """Per-user / per-account request counts.

    ``rows`` is the raw per-key breakdown; ``by_user``, ``by_account`` and
    ``by_service`` are the same data rolled up, because that is the shape a
    dashboard actually asks for.
    """

    rows: list[UsageRow] = Field(default_factory=list)
    by_user: list[dict] = Field(default_factory=list)
    by_account: list[dict] = Field(default_factory=list)
    by_service: list[dict] = Field(default_factory=list)


class RateLimitRow(BaseModel):
    key: str
    scope: str
    requests_this_minute: int
    limit: int
    remaining: int


class RateLimitResponse(BaseModel):
    """Live rate-limit windows. Reflects THIS process only — with several
    replicas each holds its own windows (see features/rate_limiter.py)."""

    windows: list[RateLimitRow] = Field(default_factory=list)


class RouteRow(BaseModel):
    name: str
    prefix: str
    base_url: str


class ConfigResponse(BaseModel):
    """Resolved, non-secret configuration. Never includes the JWT secret or the
    Mongo URI — ``mongo_configured`` reports whether one is set, which is the
    only part of it anyone needs to see."""

    service: str = "api-gateway"
    version: str = ""
    environment: str = ""
    auth_enabled: bool = True
    public_paths: list[str] = Field(default_factory=list)
    """The paths reachable without a token, as configured. Worth having on the
    same page as everything else: "why is this endpoint 401ing" and "why is
    this endpoint NOT 401ing" are both answered here."""
    introspection_url: str = ""
    """Where tokens are validated. The gateway holds no signing key — it asks
    auth-service."""
    introspection_cache_ttl_seconds: float = 0.0
    """How long a validation is trusted. This IS the revocation lag: a
    logged-out token keeps working for at most this long."""
    introspection_stale_grace_seconds: float = 0.0
    introspection_cache_entries: int = 0
    identity_cache_enabled: bool = False
    """Whether the cross-replica identity cache (features/identity_cache.py)
    is backed by MongoDB. False means each replica caches alone, which is
    correct but multiplies auth-service's traffic by the replica count."""
    identity_cache_entries: int = 0
    """Estimated documents in the shared cache; -1 when it cannot be read."""
    rate_limit_enabled: bool = True
    user_rpm: int = 0
    account_rpm: int = 0
    anonymous_rpm: int = 0
    usage_tracking_enabled: bool = True
    mongo_configured: bool = False
    routes: list[RouteRow] = Field(default_factory=list)

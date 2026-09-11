"""Gateway domain configuration — upstreams, validation, budgets, storage.

Env vars are prefixed ``GATEWAY_``. This module — and only this module — owns
*what the gateway fronts and what it trusts*; ``app/config.py`` (prefix
``APIGW_``) owns *how the gateway itself is exposed* (host/port/CORS/docs).
That is the same split the sibling services use: llm-gateway has
``features/config.py`` (``LLM_``) vs ``app/config.py`` (``GATEWAY_``),
knowledge-service ``rag/config.py`` (``RAG_``) vs ``app/config.py``
(``KNOWLEDGE_``), auth-service ``features/config.py`` (``AUTH_``) vs
``app/config.py`` (``AUTHSVC_``).

The gateway holds no signing key and knows nothing about token format. It
validates by asking auth-service (``features/introspection.py``), which owns
the secret, the algorithm, the expiry rules and the revocation list. The only
thing configured here is where to ask and how long to trust the answer.
"""
from __future__ import annotations

import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_file=str(_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ─────────────────────────────────────────────────────────── token validation
    # Where to ask "who is this token?". auth-service's GET /auth/me already
    # answers exactly that — signature, expiry AND its own revocation list —
    # so no extra endpoint is needed there.
    #
    # This must point at auth-service DIRECTLY, not back through this gateway's
    # own /auth route: routing it through the gateway would make validating a
    # request require validating a request.
    introspection_url: str = "http://localhost:8100/auth/me"

    introspection_cache_ttl_seconds: float = 60.0
    """How long one answer is trusted before asking again.

    This is the revocation lag: a logged-out token keeps working for at most
    this long. It is also the load control — asking per request would put a
    round trip in front of all platform traffic. Halve it to make logout bite
    faster, and double auth-service's call volume."""

    introspection_stale_grace_seconds: float = 300.0
    """How long a cached answer may still be used when auth-service is
    UNREACHABLE (never when it is merely stale). Keeps a brief auth-service
    outage from taking the whole platform down. 0 fails closed immediately."""

    introspection_timeout_seconds: float = 10.0
    """Kept modest: this sits in front of a request the caller is waiting on,
    so a wedged auth-service should surface as a fast 504 rather than holding
    the connection open for minutes."""

    auth_enabled: bool = True
    """The master switch on the gate. Off means every route is public and every
    caller anonymous — for a local smoke test with no auth-service running,
    catastrophic anywhere else, so main.py logs an error when it is off in
    production."""

    # ──────────────────────────────────────────────────────────────── upstreams
    # The route table: which path prefix belongs to which service.
    #
    #   GATEWAY_ROUTES=llm:/api/llm:http://localhost:8080,knowledge:/api/knowledge:http://localhost:8090
    #
    # Each entry is name:prefix:base_url — see registry.py::parse_routes for the
    # parsing rules (the URL's own "http://" colons are not separators).
    #
    # auth-service is in here as an ordinary upstream, exactly like the others.
    # The gateway does not implement sign-in; it routes to the service that
    # does. It remains the only caller of auth-service either way — being the
    # sole ingress is what makes that true, not having hand-written endpoints.
    #
    # Note the auth entry's base_url carries a PATH (".../auth"). auth-service
    # serves its routes under /auth, and the gateway strips the matched prefix
    # before forwarding, so public "/auth/login" becomes "/login" and the base
    # URL's path puts it back: http://localhost:8100/auth/login. That keeps the
    # public path identical to what the UIs already call, so pointing them at
    # the gateway is a base-URL change and nothing else.
    routes: str = (
        "auth:/auth:http://localhost:8100/auth,"
        "llm:/api/llm:http://localhost:8080,"
        "knowledge:/api/knowledge:http://localhost:8090"
    )

    # Services that receive the bearer token and NOTHING else — no X-User-ID,
    # X-Account-ID or any other decomposed claim. auth-service is the identity
    # authority: it derives the caller from a token it signed itself, so
    # telling it who the caller is adds nothing and hands it a second, weaker
    # source of truth that could disagree with the first. Every other upstream
    # gets the full set, so a service added to GATEWAY_ROUTES is served
    # identity headers by default rather than silently going without them.
    #
    # Names must match the GATEWAY_ROUTES entry names, not the path prefixes.
    identity_exempt_services: str = "auth"

    # ────────────────────────────────────────────────────────── secured or not
    # Which routed paths may be reached WITHOUT a token. Everything else needs
    # a valid token — see features/access_policy.py for the entry syntax and for
    # why "private by default" is the only safe direction for this list.
    #
    # The default opens exactly the endpoints that cannot possibly carry a
    # token yet: signing in, signing up, and creating an organization (which
    # has no members who could hold one). Everything else auth-service exposes
    # — /auth/me, /auth/logout, /auth/accounts, the staff routes — is routed
    # like any other traffic and requires a token, with auth-service still
    # enforcing its own rules on top.
    public_paths: str = (
        "POST:/auth/login,"
        "POST:/auth/register,"
        "POST:/auth/organizations/register"
    )

    # ──────────────────────────────────────────────────────── upstream timeouts
    upstream_timeout_seconds: float = 120.0
    """Generous by design: an LLM completion or a document ingest legitimately
    runs for minutes, and a gateway that gives up before the service it fronts
    would turn a slow success into a failed request."""

    upstream_connect_timeout_seconds: float = 5.0
    """Kept short and separate from the read timeout above: failing to *reach* a
    service is a fast, unambiguous failure (it is down, or DNS is wrong), and
    waiting two minutes to discover that helps nobody."""

    upstream_max_connections: int = 200
    upstream_max_keepalive_connections: int = 50
    """The proxy holds one pooled connection per in-flight upstream request.
    These bound how much concurrency the gateway will push at the services
    behind it — the point of a shared front door is that it can protect them,
    which it cannot do with an unbounded pool."""

    # ─────────────────────────────────────────────────────────── rate limiting
    rate_limit_enabled: bool = True

    user_rpm: int = 120
    """Requests per minute per authenticated user. 0 disables the user
    dimension. Two independent budgets are enforced (see rate_limiter.py):
    this one stops a single runaway client, the account one below stops a
    single tenant from consuming the whole deployment."""

    account_rpm: int = 1200
    """Requests per minute per account (tenant). 0 disables the account
    dimension. Deliberately an order of magnitude above the per-user budget:
    an account is expected to have many users."""

    anonymous_rpm: int = 30
    """Requests per minute per client IP for the unauthenticated endpoints —
    sign-in and sign-up. This is the only budget that *can* apply there, since
    by definition there is no user yet, and it is the one that makes password
    guessing expensive. Kept low for that reason."""

    anonymous_rpm_overrides: str = ""
    """Per-PATH anonymous ceilings, comma-separated ``path=rpm``::

        GATEWAY_ANONYMOUS_RPM_OVERRIDES=/api/makemerich/*=600

    The escape hatch for an upstream routed as public because it validates its
    own tokens rather than because its traffic is unauthenticated. All of that
    traffic counts against the anonymous (per-IP) budget, and ``anonymous_rpm``
    is sized to make password guessing expensive — far too low for an
    application's normal load.

    Raising ``anonymous_rpm`` instead would be the wrong fix: auth-service has
    no lockout of its own, so that budget is the ONLY barrier in front of
    POST /auth/login. This keeps sign-in tight while one subtree is generous.
    A trailing ``*`` makes an entry cover a subtree; longest path wins. See
    features/rate_limiter.py::parse_anonymous_rpm_overrides."""

    rate_limit_overrides: str = ""
    """Per-principal exceptions, comma-separated ``key=rpm``, where key is a
    user_id or an account_id::

        GATEWAY_RATE_LIMIT_OVERRIDES=acme-corp=6000,svc-batch-loader=600

    A key is matched against whichever dimension is being checked, so an
    account ID here raises that account's ceiling and a user ID raises that
    user's."""

    # ──────────────────────────────────────────────────────────────── usage log
    usage_tracking_enabled: bool = True
    """Per-user and per-account request counters (features/usage.py), exposed
    on GET /v1/usage. Independent of rate limiting: the limiter enforces a
    rolling 60-second window and forgets, this keeps cumulative totals."""

    usage_flush_seconds: float = 10.0
    """How often buffered usage rows are written to Mongo. Batched rather than
    written per request because a metering write on the hot path would add a
    round trip to every proxied call — and losing at most this many seconds of
    counters to a hard crash is an acceptable price for that."""

    # ────────────────────────────────────────────────────────────────── storage
    # Optional, and only used for usage counters now that revocation belongs to
    # auth-service. With no URI they are kept in-process: correct for a single
    # replica, and they reset on restart. Set it for anything with more than
    # one replica, otherwise each replica reports only its own traffic.
    mongo_uri: str = ""
    mongo_db_name: str = "app"
    usage_collection: str = "gateway_usage"

    # ── shared identity cache (features/identity_cache.py) ──────────────────
    # Second tier in front of auth-service, shared by every replica. The
    # in-process cache is per-replica, so with N of them auth-service sees N
    # times the traffic the TTL was meant to buy; this collapses that back to
    # one call per token per TTL for the whole deployment.
    #
    # No TTL of its own: it reuses GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS and
    # GATEWAY_INTROSPECTION_STALE_GRACE_SECONDS, because a second, disagreeing
    # expiry for the same answer is a bug waiting to be written. Documents are
    # expired by a MongoDB TTL index at TTL + grace — the outer horizon, since
    # an entry past its TTL is exactly what the grace window serves.
    #
    # Inactive with no GATEWAY_MONGO_URI; the in-process tier still works.
    identity_cache_enabled: bool = True
    identity_cache_collection: str = "gateway_identity_cache"

    # ─────────────────────────────────────────────────────────────────── derived

    @property
    def introspection_configured(self) -> bool:
        return bool(self.introspection_url.strip())

    def parsed_identity_exempt_services(self) -> frozenset[str]:
        """Service names that get the bearer token but no identity headers."""
        return frozenset(
            name.strip()
            for name in self.identity_exempt_services.split(",")
            if name.strip()
        )

    def parsed_anonymous_rpm_overrides(self):
        """The per-path anonymous ceilings, longest path first."""
        from .rate_limiter import AnonymousBudgets, parse_anonymous_rpm_overrides

        return AnonymousBudgets(
            parse_anonymous_rpm_overrides(self.anonymous_rpm_overrides)
        )

    def parsed_rate_limit_overrides(self) -> dict[str, int]:
        """``{principal: rpm}``. Malformed entries are logged and skipped
        rather than raising — a typo in one override should not stop the
        gateway from booting and serving everyone else."""
        out: dict[str, int] = {}
        for raw in (p.strip() for p in self.rate_limit_overrides.split(",")):
            if not raw:
                continue
            key, sep, value = raw.partition("=")
            if not sep:
                logger.warning(
                    "Ignoring malformed GATEWAY_RATE_LIMIT_OVERRIDES entry %r", raw
                )
                continue
            try:
                out[key.strip()] = int(value.strip())
            except ValueError:
                logger.warning("Ignoring non-numeric rate-limit override %r", raw)
        return out


gateway_settings = GatewaySettings()

"""Gateway domain configuration — upstreams, JWT, budgets, storage.

Env vars are prefixed ``GATEWAY_``. This module — and only this module — owns
*what the gateway fronts and what it trusts*; ``app/config.py`` (prefix
``APIGW_``) owns *how the gateway itself is exposed* (host/port/CORS/docs).
That is the same split the sibling services use: llm-gateway has
``features/config.py`` (``LLM_``) vs ``app/config.py`` (``GATEWAY_``),
knowledge-service ``rag/config.py`` (``RAG_``) vs ``app/config.py``
(``KNOWLEDGE_``), auth-service ``features/config.py`` (``AUTH_``) vs
``app/config.py`` (``AUTHSVC_``).

The JWT settings here are not this service's own — they are auth-service's,
mirrored. auth-service is the trust root for identity: it signs, the gateway
verifies. HS256 is symmetric, so ``GATEWAY_JWT_SECRET`` must equal
``AUTH_JWT_SECRET``, ``GATEWAY_JWT_ISSUER`` must equal ``AUTH_JWT_ISSUER``,
and ``GATEWAY_JWT_AUDIENCE`` must be one of the audiences auth-service mints
into ``aud``. Get any of those wrong and every request 401s with a signature
or claim error — see the README's "token lifecycle" section.
"""
from __future__ import annotations

import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent

DEFAULT_JWT_SECRET = "dev-secret-change-me"
"""Matches auth-service's own development default, so a laptop that has
neither service configured still produces tokens the gateway accepts. It is
worthless as a secret — anyone who has read either source can forge a token
for any user — which is why ``jwt_secret_is_default`` exists and main.py
refuses to start quietly on it in production."""


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_file=str(_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ────────────────────────────────────────────────────────────────────── JWT
    # Mirrors of auth-service's signing settings — see the module docstring.
    jwt_secret: str = DEFAULT_JWT_SECRET
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "auth-service"

    jwt_audience: str = "llm-gateway"
    """One audience, not a list: the gateway verifies that a token was minted
    for the platform it fronts. auth-service puts several services in ``aud``
    (llm-gateway, knowledge-service, ...) and PyJWT accepts a token when the
    configured audience appears anywhere in that list, so naming any one of
    them is enough."""

    verify_audience: bool = True
    """Off only for a deployment whose auth-service predates the ``aud`` claim.
    Leaving it off in normal operation means a token minted for some other
    system that happens to share the secret would be accepted here."""

    auth_enabled: bool = True
    """The master switch on the JWT gate. Off means every route is public and
    every caller is anonymous — useful for a local smoke test against a
    gateway with no auth-service running, catastrophic anywhere else, so
    main.py logs an error at startup when it is off in production."""

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

    # ────────────────────────────────────────────────────────── secured or not
    # Which routed paths may be reached WITHOUT a token. Everything else needs
    # a valid JWT — see features/access_policy.py for the entry syntax and for
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

    # Paths that END a session. When a request to one of these succeeds, the
    # gateway records the token's ID as revoked so it stops being accepted
    # here immediately — see features/revocation.py for why local verification
    # makes this necessary, and app/controllers/proxy_controller.py for how it
    # stays a pure passthrough while doing it. Empty disables the behaviour.
    logout_paths: str = "/auth/logout"

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
    # Optional. With no URI the gateway keeps usage counters and the revoked
    # token set in-process: correct for a single replica, and the counters
    # simply reset on restart. Set it for anything with more than one replica —
    # otherwise each replica meters only its own traffic and honours only the
    # logouts it personally handled.
    mongo_uri: str = ""
    mongo_db_name: str = "portless"
    usage_collection: str = "gateway_usage"

    revoked_tokens_collection: str = "revoked_tokens"
    """Deliberately the SAME collection name auth-service uses. Pointed at the
    same database, the gateway's revocation checks and auth-service's own
    blacklist become one store, so a token revoked by either is dead to both.
    Pointed at a different database they stay independent and the gateway still
    honours every logout it handled itself — which, since it is the only
    ingress, is all of them."""

    # ─────────────────────────────────────────────────────────────────── derived

    @property
    def jwt_secret_is_default(self) -> bool:
        return self.jwt_secret == DEFAULT_JWT_SECRET

    def parsed_logout_paths(self) -> frozenset[str]:
        """Normalised set of session-ending paths (no trailing slashes)."""
        return frozenset(
            p.strip().rstrip("/")
            for p in self.logout_paths.split(",")
            if p.strip()
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

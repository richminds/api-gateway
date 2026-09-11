"""Per-user / per-account request budgets, enforced at the edge.

Runs *after* ``AuthMiddleware`` has established who the caller is, so it can
count against a verified user and account rather than anything the caller
asserted. (Starlette runs middleware in reverse registration order, so
``main.py`` adds this one before the auth middleware to get that ordering —
see the note there.)

Health and docs are exempt: an orchestrator probing liveness every few seconds
is not traffic anyone means to budget, and a gateway that 429s its own health
check will be restarted in a loop by the very system that was checking it.

Unauthenticated sign-in and sign-up traffic is limited by client IP, which is
the only key that exists before a user does. Whether the IP is believed from a
header or taken from the socket is a deployment question with a real security
consequence — see ``APIGW_TRUST_FORWARDED_FOR`` in app/config.py.

That per-IP ceiling can be raised for specific paths via
``GATEWAY_ANONYMOUS_RPM_OVERRIDES`` — resolved here, per request, because it is
keyed on the path and this is the only layer that sees both the path and the
budget. See features/rate_limiter.py for why it exists.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from features.config import gateway_settings
from features.rate_limiter import RateLimiter, RateLimitExceeded
from features.identity import ANONYMOUS

from ..config import service_settings
from ..errors import rate_limited

logger = logging.getLogger(__name__)

# Never budgeted — see the module docstring.
EXEMPT_PREFIXES: tuple[str, ...] = ("/health", "/docs", "/redoc", "/openapi.json")


def client_ip(request: Request) -> str:
    """The caller's IP, honouring X-Forwarded-For only when configured to.

    Takes the *first* entry of the header: X-Forwarded-For accumulates
    left-to-right as "client, proxy1, proxy2", so the original client is the
    leftmost. Falls back to the socket address, which is what a direct
    connection gives and what a proxy's own address looks like.
    """
    if service_settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        # Built once and held: the sliding windows ARE the limiter's state, so
        # rebuilding it per request would reset every window and enforce
        # nothing at all.
        self._limiter = limiter or RateLimiter()
        # Parsed once at startup, like the limiter itself — this runs in front
        # of every request and re-parsing an env var per call would be pure
        # waste.
        self._anonymous_budgets = gateway_settings.parsed_anonymous_rpm_overrides()

    @property
    def limiter(self) -> RateLimiter:
        return self._limiter

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not gateway_settings.rate_limit_enabled or request.url.path.startswith(
            EXEMPT_PREFIXES
        ):
            return await call_next(request)

        identity = getattr(request.state, "identity", ANONYMOUS)
        user_id, account_id = identity.rate_limit_keys()

        try:
            self._limiter.check(
                user_id=user_id,
                account_id=account_id,
                ip=client_ip(request),
                # Only consulted for the IP dimension, which is only reached
                # when the caller is anonymous — an authenticated request is
                # budgeted on its user and account instead.
                anonymous_rpm=self._anonymous_budgets.rpm_for(request.url.path),
            )
        except RateLimitExceeded as exc:
            # Warning rather than error: being over budget is the system
            # working as designed, and at error level a single misbehaving
            # client would flood the log and drown real incidents.
            logger.warning(
                "Rate limit hit: %s", exc, extra={"scope": exc.scope, "limit": exc.limit}
            )
            return rate_limited(request, exc)

        response = await call_next(request)

        # Let a well-behaved client pace itself instead of discovering the
        # ceiling by hitting it. Reported on the dimension the caller can
        # actually control — their own — and only when there is one.
        if user_id:
            usage = self._limiter.get_usage("user", user_id)
            if usage.limit > 0:
                response.headers["X-RateLimit-Limit"] = str(usage.limit)
                response.headers["X-RateLimit-Remaining"] = str(usage.remaining)

        return response

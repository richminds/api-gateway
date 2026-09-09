"""The JWT gate — every request needs a token except sign-in and sign-up.

This is the rule the whole gateway exists to enforce, stated once, in one
place: **a request reaches a downstream service only if it carried a valid,
unrevoked token minted by auth-service.** The exceptions are the two endpoints
that cannot possibly have one yet (register, login), plus health and docs so
an orchestrator can probe the service before any credential exists.

The exception list is an explicit allowlist of exact paths, never a pattern.
That is a deliberate constraint: a prefix rule like "/auth/* is public" is one
new endpoint away from accidentally exposing ``/auth/users`` to the world, and
the failure is silent — nothing errors, the endpoint just stops being
protected. Adding a public path here should require someone to type it.

Order of checks, and why:

1. **Public path?** Pass straight through, no token needed.
2. **Auth disabled?** (``GATEWAY_AUTH_ENABLED=false``) Everything is anonymous.
   For a local smoke test with no auth-service running; main.py refuses to let
   this go unnoticed in production.
3. **Verify the token locally** — signature, expiry, issuer, audience. No
   network call: see features/tokens.py for why introspecting auth-service on
   every request would make it a hard dependency of all platform traffic.
4. **Check revocation** — the one piece local verification cannot know. See
   features/revocation.py.

The verified identity lands on ``request.state.identity`` and is bound to the
ambient log context, so everything downstream of here — the rate limiter, the
usage tracker, the access log, the proxy's injected headers — reads the same
verified identity and none of them re-parses the token.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from features.config import gateway_settings
from features.errors import AuthenticationError
from features.log_context import bind_account_id, bind_user_id, reset_account_id, reset_user_id
from features.revocation import is_token_revoked
from features.tokens import ANONYMOUS, TokenVerifier, extract_bearer

from ..errors import unauthorized

logger = logging.getLogger(__name__)

# Exact paths that need no token. See the module docstring for why this is an
# exact-match allowlist rather than a set of prefixes.
PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/auth/register",   # sign up — there is no token yet, that is the point
        "/auth/login",      # sign in — likewise
        "/auth/organizations/register",  # self-serve org creation, pre-signup
        "/health",
        "/health/live",
        "/health/ready",
        "/health/upstreams",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/docs/oauth2-redirect",
    }
)


def is_public(path: str) -> bool:
    """True when this exact path needs no credential.

    A trailing slash is normalised away first: FastAPI treats "/auth/login/"
    as a redirect to "/auth/login", and a caller who sends the former should
    not get a 401 that the latter would not produce.
    """
    normalised = path.rstrip("/") or "/"
    return normalised in PUBLIC_PATHS or path in PUBLIC_PATHS


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, verifier: TokenVerifier | None = None) -> None:
        super().__init__(app)
        self._verifier = verifier or TokenVerifier()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request.state.identity = ANONYMOUS
        request.state.token = ""

        if is_public(request.url.path) or not gateway_settings.auth_enabled:
            return await call_next(request)

        token = extract_bearer(request.headers.get("authorization", ""))
        if not token:
            return unauthorized(
                request,
                "This endpoint requires authentication. Send "
                "'Authorization: Bearer <token>' — obtain a token from "
                "POST /auth/login.",
                reason="missing_token",
            )

        try:
            identity = self._verifier.verify(token)
        except AuthenticationError as exc:
            # Logged at warning, not error: a expired token is an ordinary
            # event in the life of a healthy system, not an incident.
            logger.warning(
                "Rejected %s %s: %s", request.method, request.url.path, exc
            )
            return unauthorized(request, str(exc), exc.reason)

        if await is_token_revoked(identity.jti):
            return unauthorized(
                request,
                "This session has been logged out — please log in again.",
                reason="token_revoked",
            )

        request.state.identity = identity
        request.state.token = token

        # Bound here rather than in RequestContextMiddleware because this is
        # the first moment either value is *known* — they come out of the
        # token, and nothing before this point has opened it.
        user_token = bind_user_id(identity.user_id)
        account_token = bind_account_id(identity.account_id)
        try:
            return await call_next(request)
        finally:
            reset_account_id(account_token)
            reset_user_id(user_token)

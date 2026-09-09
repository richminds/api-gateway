"""The JWT gate — the one rule this gateway enforces on every request.

**A request is routed to a service only if it carried a valid, unrevoked token
minted by auth-service — unless its path is configured as public.**

Which paths are public is deployment configuration, not something hardcoded
here (``GATEWAY_PUBLIC_PATHS``, parsed by ``features/access_policy.py``). It
has to be: the gateway routes rather than implements, so it cannot know from a
path alone whether it is a sign-in endpoint. Anything not listed is private,
which means a new endpoint on any upstream is protected the moment it exists
and opening it up takes a deliberate edit.

Order of checks, and why:

1. **Public path?** Route it, no token needed.
2. **Auth disabled?** (``GATEWAY_AUTH_ENABLED=false``) Everything is anonymous.
   For a local smoke test; main.py refuses to let it pass unnoticed elsewhere.
3. **Verify the token locally** — signature, expiry, issuer, audience. No
   network call: see features/tokens.py for why asking auth-service about every
   request would make it a hard dependency of all platform traffic.
4. **Check revocation** — the one thing local verification cannot know on its
   own. See features/revocation.py.

The verified identity lands on ``request.state.identity`` and is bound to the
ambient log context, so everything downstream — the rate limiter, the usage
tracker, the access log, the identity headers the proxy injects — reads the
same verified identity and none of them re-parses the token.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from features.access_policy import AccessPolicy
from features.config import gateway_settings
from features.errors import AuthenticationError
from features.log_context import bind_account_id, bind_user_id, reset_account_id, reset_user_id
from features.revocation import is_token_revoked
from features.tokens import ANONYMOUS, TokenVerifier, extract_bearer

from ..errors import unauthorized

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        policy: AccessPolicy | None = None,
        verifier: TokenVerifier | None = None,
    ) -> None:
        super().__init__(app)
        self._policy = policy
        self._verifier = verifier or TokenVerifier()

    def _access_policy(self, request: Request) -> AccessPolicy:
        # Falls back to the one the lifespan built, so the policy is parsed
        # once at startup rather than per request, while still being
        # injectable for tests.
        return self._policy or request.app.state.access_policy

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request.state.identity = ANONYMOUS
        request.state.token = ""

        is_public = self._access_policy(request).is_public(
            request.method, request.url.path
        )
        request.state.is_public_path = is_public

        if is_public or not gateway_settings.auth_enabled:
            return await call_next(request)

        token = extract_bearer(request.headers.get("authorization", ""))
        if not token:
            return unauthorized(
                request,
                "This endpoint requires authentication. Send "
                "'Authorization: Bearer <token>' — obtain a token by signing in "
                "through the auth service behind this gateway.",
                reason="missing_token",
            )

        try:
            identity = self._verifier.verify(token)
        except AuthenticationError as exc:
            # Warning, not error: an expired token is an ordinary event in the
            # life of a healthy system, not an incident.
            logger.warning("Rejected %s %s: %s", request.method, request.url.path, exc)
            return unauthorized(request, str(exc), exc.reason)

        if await is_token_revoked(identity.jti):
            return unauthorized(
                request,
                "This session has been logged out — please sign in again.",
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

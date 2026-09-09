"""The gate — every request needs a token auth-service accepts.

**A request is routed only if auth-service confirms the token.** The gateway
does not decode, verify or understand tokens; it hands the opaque string to
auth-service and acts on the answer (``features/introspection.py``). One
service owns identity — the signing key, the algorithm, the expiry rules and
the revocation list — and it is the only place that has to be right about them.

The exceptions are the paths configured public (``GATEWAY_PUBLIC_PATHS``),
which is deployment configuration rather than anything hardcoded here: the
gateway routes rather than implements, so it cannot know from a path alone
whether it is a sign-in endpoint. Anything not listed is private, so a new
endpoint on any upstream is protected the moment it exists.

Because validation is a network call, answers are cached briefly — see
``features/introspection.py`` for the TTL, the revocation lag it implies, and
what happens when auth-service is unreachable.

The confirmed identity lands on ``request.state.identity`` and is bound to the
ambient log context, so everything downstream — the rate limiter, the usage
tracker, the access log, the headers the proxy injects — reads the same
verified identity and none of them asks again.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from features.access_policy import AccessPolicy
from features.config import gateway_settings
from features.errors import AuthenticationError, UpstreamError
from features.identity import ANONYMOUS, extract_bearer
from features.log_context import bind_account_id, bind_user_id, reset_account_id, reset_user_id

from ..errors import problem, unauthorized

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, policy: AccessPolicy | None = None, introspector=None) -> None:
        super().__init__(app)
        self._policy = policy
        self._introspector = introspector

    def _access_policy(self, request: Request) -> AccessPolicy:
        # Falls back to the one the lifespan built, so the policy is parsed
        # once at startup rather than per request, while still being
        # injectable for tests.
        return self._policy or request.app.state.access_policy

    def _token_introspector(self, request: Request):
        return self._introspector or request.app.state.introspector

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
            # Answered without asking auth-service: there is nothing to ask
            # about, and a missing header is not something it could rule on.
            return unauthorized(
                request,
                "This endpoint requires authentication. Send "
                "'Authorization: Bearer <token>' — obtain a token by signing in "
                "through the auth service behind this gateway.",
                reason="missing_token",
            )

        try:
            identity = await self._token_introspector(request).validate(token)
        except AuthenticationError as exc:
            # auth-service's own wording, passed through: "expired", "revoked"
            # and "invalid" call for different reactions from a client, and
            # only auth-service knows which it was.
            logger.warning("Rejected %s %s: %s", request.method, request.url.path, exc)
            return unauthorized(request, str(exc), exc.reason)
        except UpstreamError as exc:
            # Validation could not happen. Fail closed — admitting the request
            # would mean routing traffic nobody has authenticated. Reported as
            # a gateway-side failure (502/504), not a 401, because the caller's
            # credentials were never the problem and retrying is the right move.
            logger.error("Could not validate a token: %s", exc)
            status, code = (504, "auth_service_timeout") if exc.timeout else (
                502,
                "auth_service_unavailable",
            )
            return problem(
                request,
                status,
                code,
                "Could not verify your session because the authentication "
                "service is unavailable. Please retry.",
                headers={"Retry-After": "5"},
                service=exc.service,
            )

        request.state.identity = identity
        request.state.token = token

        # Bound here rather than in RequestContextMiddleware because this is
        # the first moment either value is *known* — they come from
        # auth-service's answer, which nothing before this point has.
        user_token = bind_user_id(identity.user_id)
        account_token = bind_account_id(identity.account_id)
        try:
            return await call_next(request)
        finally:
            reset_account_id(account_token)
            reset_user_id(user_token)

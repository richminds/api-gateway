"""Correlation IDs, access logging, and usage metering.

The outermost middleware, so it sees every request and every response —
including the ones the auth and rate-limit middlewares reject. That placement
is the point: a 401 or a 429 is exactly the kind of event someone will later
need to find in the logs, and a middleware that only saw successful traffic
would be missing the interesting half.

Three things happen here.

**A correlation ID** is echoed from the caller's header when present and
minted otherwise, attached to ``request.state``, bound to the ambient log
context, returned on the response, and forwarded upstream by the proxy. One ID
therefore ties the gateway's access log, auth-service's log and the upstream
service's log together for a single call — which is what makes a failure
report traceable across a platform of four services instead of three separate
guesses.

**One access log line per request**, carrying the verified user and account
(bound by ``AuthMiddleware``, picked up ambiently by the formatter — no
threading needed). This is the "logging" half of what a gateway is for: every
request the platform serves is logged in one place, in one format, with a real
identity on it.

**Usage metering.** The same response path records the request against its
user, account and target service (``features/usage.py``). Done here rather
than in the proxy so that requests rejected before reaching an upstream are
still counted — a client generating nothing but 401s is using the platform,
and the numbers should say so.
"""
from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from features.config import gateway_settings
from features.log_context import (
    account_id_scope,
    bind_request_id,
    new_request_id,
    reset_request_id,
    user_id_scope,
)
from features.tokens import ANONYMOUS
from features.usage import get_usage_tracker

from ..config import service_settings

logger = logging.getLogger("gateway.access")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        header = service_settings.request_id_header
        request_id = request.headers.get(header) or new_request_id()
        request.state.request_id = request_id

        token = bind_request_id(request_id)
        started = time.perf_counter()
        status_code = 500  # what gets recorded if call_next raises

        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers[header] = request_id
            return response
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000

            # Read after call_next: the identity is established by
            # AuthMiddleware, which runs inside this one.
            identity = getattr(request.state, "identity", ANONYMOUS)
            service = getattr(request.state, "upstream_service", "") or "gateway"

            if gateway_settings.usage_tracking_enabled:
                # Never allowed to break a request that has otherwise succeeded:
                # metering is a reporting concern, and a broken counter is not
                # worth a 500 the caller can do nothing about.
                try:
                    get_usage_tracker().record(
                        user_id=identity.user_id,
                        account_id=identity.account_id,
                        service=service,
                        status_code=status_code,
                        duration_ms=elapsed_ms,
                    )
                except Exception as exc:  # noqa: BLE001 — see above
                    logger.warning("Usage metering failed: %s", exc)

            # Health probes fire constantly — keep them out of the access log.
            # Logged INSIDE the finally block but BEFORE the contextvar reset
            # below, because the whole point of binding request_id is for this
            # exact line to carry it.
            #
            # The user/account contextvars are re-bound here rather than relied
            # upon from AuthMiddleware, and that is not redundant: Starlette's
            # BaseHTTPMiddleware runs each call_next in its own task, so a
            # contextvar bound by an INNER middleware is invisible out here —
            # the binding propagates down into what it awaits, never back up.
            # Without this the platform's central access log would name no user
            # on any line, which is most of the point of having it.
            # request.state is not affected: it is backed by the ASGI scope,
            # which every middleware shares.
            identity_user = identity.user_id
            identity_account = identity.account_id

            if not request.url.path.startswith("/health"):
                with user_id_scope(identity_user), account_id_scope(identity_account):
                    logger.info(
                        "%s %s → %d (%.0fms)",
                        request.method,
                        request.url.path,
                        status_code,
                        elapsed_ms,
                        extra={
                            "method": request.method,
                            "path": request.url.path,
                            "status": status_code,
                            "latency_ms": round(elapsed_ms, 1),
                            "service": service,
                            # user_id and account_id are deliberately NOT passed
                            # here: the JSON formatter already stamps them (and
                            # request_id) on every line from the ambient
                            # contextvars, and a duplicate key in `extra` would
                            # be dropped as a shadow of it.
                        },
                    )

            reset_request_id(token)

"""The catch-all route — every request the gateway fronts.

One route handles all of them, matching any method on any path, because a
gateway must not need a code change when a service behind it adds an endpoint.
Which upstream a request belongs to is decided by the registry
(``features/registry.py``) from ``GATEWAY_ROUTES``. This includes auth-service:
it is an ordinary upstream, and signing in is an ordinary routed request.

By the time a request arrives here it has been authenticated
(``app/middleware/auth.py`` — no token, no entry, unless the path is
configured public) and counted against its budgets
(``app/middleware/rate_limit.py``). This module resolves the route, forwards
the request with a verified identity attached, and streams the answer back.

Registered last in ``main.py``: FastAPI matches routes in registration order,
so a catch-all added before ``/health`` and the ``/v1`` admin routes would
swallow them and try to proxy them to a service that has never heard of them.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from features.config import gateway_settings
from features.errors import RouteNotFound
from features.proxy import (
    ProxyClient,
    build_upstream_headers,
    filter_response_headers,
    upstream_error_from,
)
from features.registry import ServiceRegistry
from features.revocation import revoke_token
from features.tokens import CallerIdentity

from ..dependencies import get_identity, get_proxy_client, get_registry, get_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["proxy"])

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _is_logout(path: str) -> bool:
    return (path.rstrip("/") or "/") in gateway_settings.parsed_logout_paths()


@router.api_route(
    "/{full_path:path}",
    methods=_METHODS,
    include_in_schema=False,
    summary="Route to the service that owns this path",
)
async def proxy(
    full_path: str,
    request: Request,
    identity: CallerIdentity = Depends(get_identity),
    token: str = Depends(get_token),
    registry: ServiceRegistry = Depends(get_registry),
    proxy_client: ProxyClient = Depends(get_proxy_client),
) -> StreamingResponse:
    """Forward one request to whichever service owns its path.

    Excluded from the OpenAPI schema: it matches every path, so including it
    would render the docs page as a single meaningless "ANY /{full_path}"
    entry. The services behind the gateway publish their own schemas.
    """
    path = request.url.path
    route = registry.resolve(path)
    if route is None:
        raise RouteNotFound(path)

    # Recorded for the access log and the usage counters, which run in the
    # outer middleware and would otherwise attribute this request to the
    # gateway itself rather than to the service it was for.
    request.state.upstream_service = route.name

    headers = build_upstream_headers(
        incoming=dict(request.headers),
        identity=identity,
        request_id=request.state.request_id,
        client_host=request.client.host if request.client else "",
        scheme=request.url.scheme,
        host=request.headers.get("host", ""),
        token=token,
    )

    # The request body is read in full rather than streamed through. A streamed
    # upload would be better for large files, but Starlette's request stream can
    # only be consumed once and any error path that needs to look at the body
    # would then find it empty. The response — which is where the size and the
    # latency actually are, and where streaming is load-bearing for
    # token-by-token LLM output — is streamed below.
    body = await request.body()

    try:
        response = await proxy_client.stream(
            route=route,
            method=request.method,
            path=path,
            query_string=request.url.query,
            headers=headers,
            body=body or None,
        )
    except Exception as exc:  # noqa: BLE001 — translated into the gateway's vocabulary
        raise upstream_error_from(exc, route.name) from exc

    # ── session end ─────────────────────────────────────────────────────────
    # The gateway does not implement logout — it routed the request to the
    # service that does. But it verifies tokens locally, so unless it notices,
    # a token auth-service just revoked would keep working here until it
    # expired. Recording the jti on the way past closes that window without
    # the gateway owning any part of the logout itself: it forwards the
    # request, forwards the response, and takes note.
    #
    # Only on success, and only for a token this gateway actually verified —
    # a failed logout revokes nothing, and there is nothing to revoke on an
    # anonymous request.
    if (
        _is_logout(path)
        and 200 <= response.status_code < 300
        and not identity.is_anonymous
    ):
        try:
            await revoke_token(identity.jti, identity.expires_at)
            logger.info("Session ended; token revoked at the gateway")
        except Exception as exc:  # noqa: BLE001
            # The upstream logout succeeded, so the caller is logged out as far
            # as auth-service is concerned; failing their request now would be
            # both wrong and unhelpful. Loud, because the token stays usable
            # here until it expires.
            logger.error(
                "Logout succeeded upstream but the gateway could not record the "
                "revocation — this token stays valid here until it expires: %s",
                exc,
            )

    async def body_iterator():
        """Stream the upstream response, then release its connection.

        ``aiter_bytes`` — decoded — rather than ``aiter_raw``, and the two are
        not interchangeable here: ``filter_response_headers`` drops
        ``Content-Encoding``, so forwarding still-compressed bytes would hand
        the client gzip labelled as plain text.

        ``aclose`` in a finally block is what returns the connection to the
        pool. Without it a client that disconnects mid-stream leaks a
        connection per request, and the pool is exhausted in minutes under any
        real traffic — a slow failure that looks like the upstream being down.
        """
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        finally:
            await response.aclose()

    return StreamingResponse(
        body_iterator(),
        status_code=response.status_code,
        headers=filter_response_headers(response.headers),
        # Taken from the upstream's own header rather than assumed: the gateway
        # forwards JSON, SSE streams and file downloads through this one path.
        media_type=response.headers.get("content-type"),
    )

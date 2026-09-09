"""The catch-all route — every request the gateway fronts.

One route handles all of them, matching any method on any path, because a
gateway must not need a code change when a service behind it adds an endpoint.
Which upstream a request belongs to is decided by the registry
(``features/registry.py``) from ``GATEWAY_ROUTES``. This includes auth-service:
it is an ordinary upstream, and signing in is an ordinary routed request.

By the time a request arrives here it has been authenticated by auth-service
(``app/middleware/auth.py`` — no valid token, no entry, unless the path is
configured public) and counted against its budgets
(``app/middleware/rate_limit.py``). This module resolves the route, forwards
the request with the verified identity attached, and streams the answer back.

Nothing here knows anything about tokens or sessions: logging out is just a
routed request to auth-service like any other, and it takes effect at the
gateway when the cached validation for that token expires.

Registered last in ``main.py``: FastAPI matches routes in registration order,
so a catch-all added before ``/health`` and the ``/v1`` admin routes would
swallow them and try to proxy them to a service that has never heard of them.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from features.errors import RouteNotFound
from features.proxy import (
    ProxyClient,
    build_upstream_headers,
    filter_response_headers,
    upstream_error_from,
)
from features.identity import CallerIdentity
from features.registry import ServiceRegistry

from ..dependencies import get_identity, get_proxy_client, get_registry, get_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["proxy"])

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


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

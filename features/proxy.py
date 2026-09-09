"""The reverse proxy — forwarding a verified request to its upstream service.

Two jobs, and the second is the security-critical one.

**1. Forward faithfully.** Method, path, query string, headers and body go
through unchanged, and the response streams back. Streaming matters here more
than it usually does: llm-gateway serves token-by-token completions, and
buffering a whole response before returning it would turn a streaming endpoint
into a slow non-streaming one — the client would sit silent for the full
generation and then receive everything at once.

**2. Replace the caller's identity claims with verified ones.** Every header
in ``STRIPPED_REQUEST_HEADERS`` is deleted from the incoming request and then
re-set from the token the gateway verified. This is what makes the whole
architecture sound: downstream services trust ``X-User-ID`` and ``X-Org-ID``,
so if a caller could send those headers themselves they would be able to read
any tenant's data by typing a different value. Stripping is unconditional —
not "if absent, add", but "remove whatever was there, then set ours".

Hop-by-hop headers (RFC 7230 §6.1) are dropped in both directions. Forwarding
``Connection``, ``Keep-Alive`` or ``Transfer-Encoding`` from one connection
onto a different one is how proxies produce corrupted framing, and forwarding
``Content-Length`` alongside a re-chunked body is how they produce truncated
responses.
"""
from __future__ import annotations

import logging
from typing import AsyncIterator

import httpx

from .config import gateway_settings
from .errors import UpstreamError
from .registry import Route
from .identity import CallerIdentity

logger = logging.getLogger(__name__)

# Headers that manage a single connection and must never cross to another one.
# Lowercase — every comparison here normalises before matching.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# Identity headers the gateway asserts. Deleted from the incoming request
# unconditionally, then re-set from the verified token — see the module
# docstring. A caller sending these is either confused or attacking; either
# way what they sent is discarded.
STRIPPED_REQUEST_HEADERS = frozenset(
    {
        "x-user-id",
        "x-user-email",
        "x-user-name",
        "x-account-id",
        "x-org-id",
        "x-is-portless",
        "x-authenticated-via",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
    }
)

# Content-Length is recomputed by httpx from the body it actually sends;
# passing the original through can contradict it and truncate the request.
_DROPPED_REQUEST_HEADERS = HOP_BY_HOP_HEADERS | STRIPPED_REQUEST_HEADERS | {
    "content-length",
    "host",  # must name the upstream, not the gateway — httpx sets it
}

# Same reasoning on the way back: the response is re-framed onto the client's
# connection, so its length and encoding are Starlette's to decide.
_DROPPED_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | {"content-length", "content-encoding"}


def build_upstream_headers(
    incoming: dict[str, str],
    identity: CallerIdentity,
    request_id: str,
    client_host: str = "",
    scheme: str = "http",
    host: str = "",
    token: str = "",
) -> dict[str, str]:
    """The header set to send upstream: caller's headers, sanitised, plus ours.

    The bearer token is forwarded as well as the decomposed claims. That looks
    redundant, and it is deliberate: llm-gateway and knowledge-service already
    validate JWTs themselves and can keep doing so unchanged, which is what
    lets them stay independently runnable and independently testable. The
    injected headers are the convenience layer on top, not a replacement for
    the token.

    Every key is lowercased, and that is load-bearing rather than cosmetic. A
    Python dict is case-sensitive but HTTP header names are not, so mixing
    ``authorization`` (as Starlette yields it) with ``Authorization`` (as one
    might naturally write it) puts BOTH in the dict and sends the header twice —
    which arrives upstream as one comma-joined value that parses as neither.
    Lowercase throughout means setting a header always overwrites the incoming
    one. It is also what HTTP/2 requires on the wire.
    """
    headers = {
        k.lower(): v
        for k, v in incoming.items()
        if k.lower() not in _DROPPED_REQUEST_HEADERS
    }

    headers["x-request-id"] = request_id

    if not identity.is_anonymous:
        headers["x-user-id"] = identity.user_id
        headers["x-authenticated-via"] = "api-gateway"
        if identity.email:
            headers["x-user-email"] = identity.email
        if identity.name:
            headers["x-user-name"] = identity.name
        if identity.account_id:
            headers["x-account-id"] = identity.account_id
        if identity.org_id:
            headers["x-org-id"] = identity.org_id
        if identity.is_portless:
            # Only ever sent when true. An "X-Is-Portless: false" header invites
            # a downstream service to parse the string, and "false" is truthy in
            # more languages than not.
            headers["x-is-portless"] = "true"
        if token:
            headers["authorization"] = f"Bearer {token}"

    # Standard proxy provenance, so the upstream can log the real client rather
    # than the gateway's own address. Set (not appended) because the gateway is
    # the trust boundary: any X-Forwarded-For the caller sent was stripped
    # above, precisely so it cannot forge its own origin.
    if client_host:
        headers["x-forwarded-for"] = client_host
    headers["x-forwarded-proto"] = scheme
    if host:
        headers["x-forwarded-host"] = host

    return headers


def filter_response_headers(headers: httpx.Headers) -> dict[str, str]:
    """Upstream response headers, minus the ones that belong to its connection."""
    return {
        k: v for k, v in headers.items() if k.lower() not in _DROPPED_RESPONSE_HEADERS
    }


class ProxyClient:
    """Holds the connection pool used for every proxied request.

    One pool for all upstreams. httpx keys its keepalive connections by origin,
    so a single client already maintains separate connection sets per service —
    a client per upstream would only fragment the limits without isolating
    anything.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None

    async def start(self) -> None:
        if self._client is None:
            s = gateway_settings
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    s.upstream_timeout_seconds,
                    connect=s.upstream_connect_timeout_seconds,
                ),
                limits=httpx.Limits(
                    max_connections=s.upstream_max_connections,
                    max_keepalive_connections=s.upstream_max_keepalive_connections,
                ),
                # The gateway forwards a 301/302 to the client rather than
                # chasing it. Following redirects here would hide the upstream's
                # own routing from the caller and can silently re-issue a
                # request (with its Authorization header) to another host.
                follow_redirects=False,
            )

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("ProxyClient.start() was never called")
        return self._client

    async def stream(
        self,
        route: Route,
        method: str,
        path: str,
        query_string: str,
        headers: dict[str, str],
        body: bytes | AsyncIterator[bytes] | None,
    ) -> httpx.Response:
        """Send the request and return as soon as the response headers arrive.

        The body is left unread (``stream=True``), so the caller decides when
        it is consumed — that is what keeps a streamed completion streaming all
        the way to the client instead of being buffered here.

        The caller therefore owns the response: it MUST call ``aclose()`` when
        finished, or the connection is never returned to the pool. See
        ``app/controllers/proxy_controller.py``.
        """
        url = route.target_url(path)
        if query_string:
            url = f"{url}?{query_string}"

        request = self.client.build_request(
            method, url, headers=headers, content=body
        )
        return await self.client.send(request, stream=True)


def upstream_error_from(exc: Exception, service: str) -> UpstreamError:
    """Translate an httpx failure into the gateway's own vocabulary.

    Timeouts are separated from connection failures because they mean different
    things to a caller: a timeout may well succeed on retry, a refused
    connection means the service is down and retrying immediately is pointless.
    app/errors.py renders them as 504 and 502 respectively.
    """
    if isinstance(exc, httpx.TimeoutException):
        return UpstreamError(service, "timed out waiting for a response", timeout=True)
    if isinstance(exc, httpx.ConnectError):
        return UpstreamError(service, "could not connect")
    if isinstance(exc, httpx.HTTPError):
        return UpstreamError(service, str(exc) or exc.__class__.__name__)
    return UpstreamError(service, f"unexpected error: {exc}")

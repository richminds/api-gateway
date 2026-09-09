"""The one and only client for auth-service.

**This module is the architectural boundary.** auth-service is not on the
public network and no other service in the platform holds its URL; every call
to it in the entire system goes through the functions below. If a second
caller ever appears, that is the thing to push back on in review, because the
property this design buys — one place that knows how identity is established,
one place to audit, one place to rate limit sign-in attempts — is only true
while this file is the sole client.

What the gateway does with auth-service, and (as importantly) what it does not:

    register / login          proxied here, because minting a token requires
                              the password, which only auth-service can check
    logout                    proxied here AND recorded locally, so the token
                              stops working at this gateway immediately (see
                              revocation.py)
    select account, join org  proxied here — both re-issue a token
    everything else           NOT proxied. Verifying a token on a normal
                              request is a local signature check
                              (features/tokens.py); asking auth-service about
                              every request would put it in the critical path
                              of all platform traffic.

Failures are translated into ``UpstreamError`` so the HTTP layer can render a
502/504 with the service named, rather than leaking an httpx exception. The
one deliberate exception is a *response* from auth-service: a 401 on a bad
password is auth-service's answer, not a gateway failure, so those are passed
through with their status and body intact (see ``AuthServiceResponse``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from .config import gateway_settings
from .errors import UpstreamError

logger = logging.getLogger(__name__)

SERVICE_NAME = "auth-service"


@dataclass
class AuthServiceResponse:
    """What auth-service answered, passed through verbatim.

    The gateway does not reinterpret auth-service's own status codes: a 401
    from a wrong password, a 409 from a duplicate email and a 403 from a
    disabled account are all meaningful answers that the client should see as
    auth-service worded them. Rewriting them here would mean maintaining a
    second copy of auth-service's error vocabulary that drifts.
    """

    status_code: int
    body: Any
    headers: dict[str, str]

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class AuthServiceClient:
    """Async HTTP client for auth-service.

    Holds a long-lived connection pool: sign-in traffic is bursty and TLS
    handshakes on every login would dominate the latency of an endpoint that
    is already doing an intentionally-slow bcrypt verify.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        s = gateway_settings
        self._base_url = (base_url or s.auth_service_url).rstrip("/")
        self._timeout = timeout_seconds or s.auth_service_timeout_seconds
        # Injectable so tests can hand in an ASGI-transport client wired
        # straight to a fake auth-service, with no network and no ports.
        self._client = client
        self._owns_client = client is None

    # ------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout, connect=5.0),
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
            )

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    @property
    def base_url(self) -> str:
        return self._base_url

    # ---------------------------------------------------------------- calls

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        token: str = "",
        request_id: str = "",
    ) -> AuthServiceResponse:
        """One request to auth-service, with gateway-shaped error handling."""
        if self._client is None:
            await self.start()
        assert self._client is not None  # start() guarantees it

        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if request_id:
            # Same correlation ID the caller's request carries, so one ID ties
            # the gateway's access log to auth-service's own logs for the same
            # sign-in — the whole point of minting it at the edge.
            headers["X-Request-ID"] = request_id

        try:
            response = await self._client.request(
                method, path, json=json, headers=headers
            )
        except httpx.TimeoutException as exc:
            logger.error("auth-service timed out on %s %s: %s", method, path, exc)
            raise UpstreamError(SERVICE_NAME, "timed out", timeout=True) from exc
        except httpx.HTTPError as exc:
            logger.error("auth-service unreachable on %s %s: %s", method, path, exc)
            raise UpstreamError(SERVICE_NAME, "unreachable") from exc

        return AuthServiceResponse(
            status_code=response.status_code,
            body=_decode_body(response),
            headers=dict(response.headers),
        )

    async def register(self, payload: dict, request_id: str = "") -> AuthServiceResponse:
        """Sign up. Public — this is one of the two endpoints that needs no token."""
        return await self._request(
            "POST", "/auth/register", json=payload, request_id=request_id
        )

    async def login(self, payload: dict, request_id: str = "") -> AuthServiceResponse:
        """Sign in. Public — the other endpoint that needs no token."""
        return await self._request(
            "POST", "/auth/login", json=payload, request_id=request_id
        )

    async def register_organization(
        self, payload: dict, request_id: str = ""
    ) -> AuthServiceResponse:
        """Self-serve organization creation. Public at auth-service, and public
        here: a new organization needs an org_id before anyone can sign up
        under it, so requiring a token would make the first signup impossible.
        """
        return await self._request(
            "POST", "/auth/organizations/register", json=payload, request_id=request_id
        )

    async def logout(self, token: str, request_id: str = "") -> AuthServiceResponse:
        """Revoke a token at auth-service.

        The gateway also records the revocation locally — see
        ``app/controllers/auth_controller.py::logout`` for why both, and why
        the local record is written even if this call fails.
        """
        return await self._request(
            "POST", "/auth/logout", token=token, request_id=request_id
        )

    async def me(self, token: str, request_id: str = "") -> AuthServiceResponse:
        """The caller's profile, straight from auth-service.

        Not used to authenticate normal requests (that is a local signature
        check) — this is for a client that wants the *current* profile rather
        than the snapshot frozen into its token, e.g. after an admin changed
        its organization.
        """
        return await self._request("GET", "/auth/me", token=token, request_id=request_id)

    async def select_account(
        self, payload: dict, token: str, request_id: str = ""
    ) -> AuthServiceResponse:
        """Re-issue the caller's token scoped to one of their app accounts.

        Needs auth-service because the account is a signed claim — switching
        accounts means a new token, not a client-side flag.
        """
        return await self._request(
            "POST", "/auth/me/account", json=payload, token=token, request_id=request_id
        )

    async def join_organization(
        self, payload: dict, token: str, request_id: str = ""
    ) -> AuthServiceResponse:
        """Attach a guest user to an organization; re-issues the token."""
        return await self._request(
            "POST",
            "/auth/me/organization",
            json=payload,
            token=token,
            request_id=request_id,
        )

    async def ping(self) -> bool:
        """True when auth-service answers its health endpoint.

        Used by readiness only. Never on the request path: if this were checked
        per request, an auth-service blip would 503 traffic that needs nothing
        from it.
        """
        if self._client is None:
            await self.start()
        assert self._client is not None
        try:
            response = await self._client.get("/health/live", timeout=3.0)
            return response.status_code == 200
        except httpx.HTTPError:
            return False


def _decode_body(response: httpx.Response) -> Any:
    """JSON when the response is JSON, else the raw text.

    auth-service answers JSON everywhere except 204 No Content (logout), and a
    proxy or load balancer in between can produce an HTML error page. Neither
    should raise here — the caller gets whatever came back.
    """
    if response.status_code == 204 or not response.content:
        return None
    content_type = response.headers.get("content-type", "")
    if "json" in content_type:
        try:
            return response.json()
        except ValueError:
            logger.warning("auth-service sent malformed JSON with a JSON content-type")
    return response.text

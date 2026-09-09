"""HTTP client for the API Gateway.

Drop this into any application — a web UI's backend-for-frontend, a script, a
service acting on a user's behalf — that should reach the platform through its
front door rather than talking to the individual services.

The point of using it over raw httpx is that it holds the **session**: it signs
in once, keeps the token, attaches it to every subsequent call, and refreshes
it by signing in again when it expires. That is the part every caller would
otherwise reimplement, usually by storing the token somewhere and forgetting to
handle expiry until it fails in production at 3am.

Usage::

    from sdk import GatewayClient

    async with GatewayClient("https://api.example.com") as gw:
        await gw.login("user@example.com", "hunter22", account_id="acme")

        models = await gw.get("/api/llm/v1/models")
        answer = await gw.post("/api/knowledge/v1/query", json={"q": "..."})

        await gw.logout()

Or, when a token is already held (a browser passing one to its backend)::

    gw = GatewayClient("https://api.example.com", token=existing_token)

Nothing here talks to auth-service — only the gateway does. That is the whole
architecture, and it means an application integrating with this SDK needs
exactly one URL and one credential.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0


class GatewayError(Exception):
    """A non-2xx answer from the gateway.

    Carries the parsed error envelope the whole platform uses, so a caller can
    branch on ``code`` (``rate_limit_exceeded``, ``upstream_timeout``, ...)
    rather than pattern-matching prose, and quote ``request_id`` in a bug
    report to point straight at the log line.
    """

    def __init__(
        self,
        status_code: int,
        code: str = "",
        message: str = "",
        request_id: str = "",
        body: Any = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.request_id = request_id
        self.body = body
        super().__init__(
            f"Gateway returned {status_code}"
            + (f" ({code})" if code else "")
            + (f": {message}" if message else "")
            + (f" [request_id={request_id}]" if request_id else "")
        )

    @property
    def is_auth_error(self) -> bool:
        return self.status_code == 401

    @property
    def is_rate_limited(self) -> bool:
        return self.status_code == 429


@dataclass
class Session:
    """The signed-in session — a token plus who it belongs to."""

    access_token: str = ""
    user_id: str = ""
    email: str = ""
    account_id: str = ""
    org_id: str = ""
    accounts: list[dict] = field(default_factory=list)
    """Every app account this user may sign in through. More than one entry
    means the user should pick, then call ``select_account``."""

    @property
    def is_authenticated(self) -> bool:
        return bool(self.access_token)


class GatewayClient:
    """Async client for the API Gateway.

    Holds one connection pool and one session. Not safe to share across users —
    it carries a single token by design, so a server handling many users should
    build one per request or per user rather than one globally.
    """

    def __init__(
        self,
        base_url: str,
        token: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = Session(access_token=token)
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout
        )
        self._credentials: tuple[str, str, str | None] | None = None

    # ------------------------------------------------------------- lifecycle

    async def __aenter__(self) -> "GatewayClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ auth

    async def register(
        self,
        email: str,
        name: str,
        password: str,
        account_id: str | None = None,
        org_id: str | None = None,
    ) -> Session:
        """Sign up and start a session. Needs no existing token."""
        payload = {"email": email, "name": name, "password": password}
        if account_id:
            payload["account_id"] = account_id
        if org_id:
            payload["org_id"] = org_id
        body = await self._request("POST", "/auth/register", json=payload, auth=False)
        return self._adopt(body)

    async def login(
        self, email: str, password: str, account_id: str | None = None
    ) -> Session:
        """Sign in and start a session.

        The credentials are remembered in memory so ``ensure_session`` can sign
        in again when the token expires. Pass them per call instead if you
        would rather they were not retained.
        """
        payload: dict[str, Any] = {"email": email, "password": password}
        if account_id:
            payload["account_id"] = account_id
        self._credentials = (email, password, account_id)
        body = await self._request("POST", "/auth/login", json=payload, auth=False)
        return self._adopt(body)

    async def logout(self) -> None:
        """End the session. Clears the local token even if the call fails —
        the caller asked to be logged out, and keeping a token they believe is
        gone is the worse outcome."""
        try:
            await self._request("POST", "/auth/logout")
        finally:
            self.session = Session()
            self._credentials = None

    async def whoami(self) -> dict:
        """The claims the gateway reads from the current token. No round trip
        to auth-service, so it is cheap enough to call freely."""
        return await self._request("GET", "/auth/whoami")

    async def me(self) -> dict:
        """The stored profile, which may be newer than the token's claims."""
        return await self._request("GET", "/auth/me")

    async def select_account(self, account_id: str) -> Session:
        """Switch to another of this user's app accounts; re-issues the token."""
        body = await self._request(
            "POST", "/auth/me/account", json={"account_id": account_id}
        )
        return self._adopt(body)

    async def ensure_session(self) -> Session:
        """Sign in again if the token has gone. Called automatically on a 401.

        Only possible when ``login`` was used and the credentials were retained;
        a client constructed with a bare token has nothing to sign in with and
        the original 401 is raised for the caller to handle.
        """
        if self._credentials is None:
            raise GatewayError(401, "unauthorized", "No credentials to sign in with")
        email, password, account_id = self._credentials
        return await self.login(email, password, account_id)

    def _adopt(self, body: dict) -> Session:
        user = body.get("user") or {}
        self.session = Session(
            access_token=body.get("access_token", ""),
            user_id=user.get("user_id", ""),
            email=user.get("email", ""),
            account_id=body.get("account_id") or user.get("account_id") or "",
            org_id=user.get("org_id") or "",
            accounts=body.get("accounts") or [],
        )
        return self.session

    # -------------------------------------------------------- proxied calls

    async def get(self, path: str, **kwargs) -> Any:
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> Any:
        return await self._request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs) -> Any:
        return await self._request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs) -> Any:
        return await self._request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs) -> Any:
        return await self._request("DELETE", path, **kwargs)

    async def stream(self, method: str, path: str, **kwargs) -> AsyncIterator[bytes]:
        """Stream a response — for the endpoints that produce one, such as
        token-by-token LLM output. The gateway streams these end to end, so
        chunks arrive as the upstream produces them."""
        headers = {**kwargs.pop("headers", {}), **self._auth_headers()}
        async with self._client.stream(
            method, path, headers=headers, **kwargs
        ) as response:
            if response.status_code >= 400:
                await response.aread()
                raise self._error_from(response)
            async for chunk in response.aiter_bytes():
                yield chunk

    async def usage(self) -> dict:
        """This user's own request counts."""
        return await self._request("GET", "/v1/usage/me")

    async def health(self) -> dict:
        return await self._request("GET", "/health", auth=False)

    # -------------------------------------------------------------- internals

    def _auth_headers(self) -> dict[str, str]:
        if not self.session.access_token:
            return {}
        return {"Authorization": f"Bearer {self.session.access_token}"}

    async def _request(
        self, method: str, path: str, auth: bool = True, _retried: bool = False, **kwargs
    ) -> Any:
        headers = {**kwargs.pop("headers", {})}
        if auth:
            headers.update(self._auth_headers())

        response = await self._client.request(method, path, headers=headers, **kwargs)

        if response.status_code == 401 and auth and not _retried and self._credentials:
            # The token expired mid-session. Sign in again once and retry —
            # transparently, because every caller would otherwise write this
            # same block, and most would write it after the first outage.
            logger.info("Gateway session expired; signing in again")
            await self.ensure_session()
            return await self._request(method, path, auth=auth, _retried=True, **kwargs)

        if response.status_code >= 400:
            raise self._error_from(response)

        if response.status_code == 204 or not response.content:
            return None
        if "json" in response.headers.get("content-type", ""):
            return response.json()
        return response.text

    @staticmethod
    def _error_from(response: httpx.Response) -> GatewayError:
        code = message = request_id = ""
        body: Any = None
        try:
            body = response.json()
            error = body.get("error") if isinstance(body, dict) else None
            if isinstance(error, dict):
                code = error.get("code", "")
                message = error.get("message", "")
                request_id = error.get("request_id", "")
            elif isinstance(body, dict) and "detail" in body:
                # auth-service's own errors are passed through verbatim, and
                # FastAPI words those as {"detail": ...}.
                message = str(body["detail"])
        except ValueError:
            body = response.text
        return GatewayError(response.status_code, code, message, request_id, body)

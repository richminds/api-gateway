"""Token validation — delegated to auth-service.

The gateway holds no signing key and understands nothing about token format.
It asks auth-service "who is this?" and auth-service answers, having checked
the signature, the expiry **and its own revocation list**. One service owns
identity; everything else asks it.

The endpoint is auth-service's ``GET /auth/me``, which already does exactly
this — 200 with the user's profile, or 401. No new endpoint was needed there.

**Why this is cached.** Asking on every single request would put a network
round trip in front of all platform traffic and make auth-service a hard
dependency of every call, including the ones that have nothing to do with
identity. A short-lived cache keyed on the token collapses that to one call
per token per TTL, which is the difference between auth-service seeing the
platform's entire request volume and seeing a trickle.

The cost is revocation lag: a logged-out token keeps working until its cache
entry expires, at most ``GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS``. That is
the one knob to turn if you want logout to bite faster, and the trade is
linear — halve the TTL, double the calls.

**Failure policy.** When auth-service cannot be reached:

  * a cached identity is served while it is within the stale grace window
    (``GATEWAY_INTROSPECTION_STALE_GRACE_SECONDS``), so a brief auth-service
    outage does not take the platform down with it;
  * otherwise the request fails with 502/504 rather than being let through.

Failing *closed* is deliberate. The alternative — admitting unvalidated
requests when the validator is unreachable — turns an auth-service outage into
an open front door, which is a worse failure than downtime. Set the grace to 0
to fail closed immediately.

Negative answers are cached too. A 401 is monotonic — a token auth-service
rejects as invalid, expired or revoked never becomes valid again — so caching
it is safe, and it is what stops a client looping on a dead token from
hammering auth-service.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass

import httpx

from .config import gateway_settings
from .errors import AuthenticationError, UpstreamError
from .identity import CallerIdentity, identity_from_profile

logger = logging.getLogger(__name__)

SERVICE_NAME = "auth-service"


def _cache_key(token: str) -> str:
    """Hash the token rather than keying on it directly.

    The cache is a long-lived dict; a heap dump, a debugger, or an accidental
    repr of it would otherwise expose live credentials for every active
    session. The hash is as unique as the token and reveals nothing.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class _Entry:
    """One cached answer — either an identity or a rejection."""

    fetched_at: float
    identity: CallerIdentity | None = None
    rejection: str = ""
    """The reason auth-service gave for a 401. Non-empty means this entry is a
    cached rejection."""
    reason_code: str = "invalid_token"

    def age(self, now: float) -> float:
        return now - self.fetched_at


class TokenIntrospector:
    """Validates tokens by asking auth-service, with a short-lived cache."""

    _PRUNE_THRESHOLD = 2048

    def __init__(
        self,
        url: str | None = None,
        cache_ttl: float | None = None,
        stale_grace: float | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        s = gateway_settings
        # `url if url is None` rather than `url or ...`: an explicit "" means
        # "no validator configured", and `or` would silently swap it for the
        # configured one — hiding exactly the misconfiguration worth surfacing.
        self._url = (s.introspection_url if url is None else url).strip()
        self._cache_ttl = s.introspection_cache_ttl_seconds if cache_ttl is None else cache_ttl
        self._stale_grace = (
            s.introspection_stale_grace_seconds if stale_grace is None else stale_grace
        )
        self._timeout = timeout or s.introspection_timeout_seconds
        # Injectable so tests can wire a fake auth-service with no network.
        self._client = client
        self._owns_client = client is None
        self._cache: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout, connect=5.0),
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
            )

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    @property
    def url(self) -> str:
        return self._url

    def cache_size(self) -> int:
        return len(self._cache)

    # ------------------------------------------------------------ validation

    async def validate(self, token: str) -> CallerIdentity:
        """Return the caller, or raise.

        AuthenticationError when auth-service rejects the token; UpstreamError
        when auth-service cannot be asked and nothing usable is cached.
        """
        if not token:
            raise AuthenticationError("No bearer token supplied", reason="missing_token")

        key = _cache_key(token)
        now = time.monotonic()

        cached = self._cache.get(key)
        if cached is not None and cached.age(now) < self._cache_ttl:
            if cached.rejection:
                raise AuthenticationError(cached.rejection, reason=cached.reason_code)
            assert cached.identity is not None
            return cached.identity

        try:
            identity = await self._ask_auth_service(token)
        except AuthenticationError as exc:
            await self._store(key, _Entry(now, rejection=str(exc), reason_code=exc.reason))
            raise
        except UpstreamError:
            # auth-service is unreachable. Serve a stale-but-recent answer if we
            # have one; otherwise fail closed — see the module docstring.
            if (
                cached is not None
                and self._stale_grace > 0
                and cached.age(now) < self._cache_ttl + self._stale_grace
            ):
                logger.warning(
                    "auth-service unreachable — serving a cached identity "
                    "%.0fs old (grace %.0fs)",
                    cached.age(now),
                    self._stale_grace,
                )
                if cached.rejection:
                    raise AuthenticationError(
                        cached.rejection, reason=cached.reason_code
                    ) from None
                assert cached.identity is not None
                return cached.identity
            raise

        await self._store(key, _Entry(now, identity=identity))
        return identity

    async def _ask_auth_service(self, token: str) -> CallerIdentity:
        if self._client is None:
            await self.start()
        assert self._client is not None

        if not self._url:
            raise UpstreamError(
                SERVICE_NAME,
                "no introspection URL configured (set GATEWAY_INTROSPECTION_URL)",
            )

        try:
            response = await self._client.get(
                self._url, headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.TimeoutException as exc:
            logger.error("auth-service timed out validating a token: %s", exc)
            raise UpstreamError(SERVICE_NAME, "timed out", timeout=True) from exc
        except httpx.HTTPError as exc:
            logger.error("auth-service unreachable while validating a token: %s", exc)
            raise UpstreamError(SERVICE_NAME, "unreachable") from exc

        if response.status_code == 200:
            try:
                profile = response.json()
            except ValueError as exc:
                raise UpstreamError(
                    SERVICE_NAME, "returned a non-JSON body for a valid token"
                ) from exc
            identity = identity_from_profile(profile)
            if identity.is_anonymous:
                # 200 but no user_id: auth-service is answering something we do
                # not understand. Treating that as "authenticated" would admit
                # a request with no principal to rate limit or meter.
                raise UpstreamError(
                    SERVICE_NAME, "returned a profile with no user_id"
                )
            return identity

        if response.status_code in (401, 403):
            raise AuthenticationError(
                _rejection_message(response),
                reason="token_rejected",
            )

        # 5xx, 404 (wrong URL), a proxy error page — not a verdict on the
        # token, so it must not be cached as one.
        logger.error(
            "auth-service answered %d when validating a token", response.status_code
        )
        raise UpstreamError(
            SERVICE_NAME, f"unexpected status {response.status_code} from {self._url}"
        )

    async def _store(self, key: str, entry: _Entry) -> None:
        async with self._lock:
            self._cache[key] = entry
            if len(self._cache) > self._PRUNE_THRESHOLD:
                self._prune()

    def _prune(self) -> None:
        """Drop entries past any possible usefulness. Caller holds the lock."""
        now = time.monotonic()
        horizon = self._cache_ttl + self._stale_grace
        self._cache = {
            k: e for k, e in self._cache.items() if e.age(now) < horizon
        }

    def invalidate(self, token: str = "") -> None:
        """Forget one token's cached answer, or all of them."""
        if token:
            self._cache.pop(_cache_key(token), None)
        else:
            self._cache.clear()


def _rejection_message(response: httpx.Response) -> str:
    """auth-service's own wording for why it said no.

    Passed through rather than replaced so a client sees "Token has been
    revoked — please log in again" instead of a generic gateway message that
    hides which of several very different problems occurred.
    """
    try:
        body = response.json()
    except ValueError:
        return "Authentication failed"
    if isinstance(body, dict):
        detail = body.get("detail") or (body.get("error") or {}).get("message")
        if detail:
            return str(detail)
    return "Authentication failed"

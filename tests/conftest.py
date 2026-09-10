"""Shared fixtures.

The suite never touches a network or a MongoDB. Two fake services are injected
as httpx ``MockTransport`` handlers through the ``client=`` arguments that
``ProxyClient`` and ``TokenIntrospector`` already expose, so the real code
paths — header building, error translation, streaming, caching, connection
release — are the ones under test. Only the socket is fake.

**Tokens here are opaque strings**, because that is what they are to the
gateway now. It does not decode or verify anything; it asks auth-service, and
the fake below decides. That is why there is no JWT minting in this suite any
more — a test that needs an invalid token just uses a string the fake rejects.

Env defaults are set *before* any app import because settings objects are
module-level singletons built at import time; real environment variables
outrank .env in pydantic-settings, so this also keeps the suite hermetic on a
developer machine with a fully populated .env.
"""
from __future__ import annotations

import os

os.environ.setdefault("GATEWAY_INTROSPECTION_URL", "http://auth.test/auth/me")
os.environ.setdefault("GATEWAY_MONGO_URI", "")
os.environ.setdefault(
    "GATEWAY_ROUTES",
    "auth:/auth:http://auth.test/auth,"
    "llm:/api/llm:http://llm.test,"
    "knowledge:/api/knowledge:http://knowledge.test",
)
os.environ.setdefault(
    "GATEWAY_PUBLIC_PATHS",
    "POST:/auth/login,POST:/auth/register,POST:/auth/organizations/register",
)
# Off by default so a test's first call always reaches the fake auth-service;
# the caching tests turn it on explicitly for the behaviour they are pinning.
os.environ.setdefault("GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS", "0")
os.environ.setdefault("APIGW_ENVIRONMENT", "test")
os.environ.setdefault("APIGW_LOG_FORMAT", "text")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from features.config import gateway_settings  # noqa: E402
from features.introspection import TokenIntrospector  # noqa: E402
from features.proxy import ProxyClient  # noqa: E402
from features.usage import UsageTracker  # noqa: E402

# Opaque tokens. Their only meaning is what FakeAuthService below decides.
VALID_TOKEN = "opaque-token-for-user-1"
STAFF_TOKEN = "opaque-token-for-staff"
REVOKED_TOKEN = "opaque-token-that-was-revoked"
EXPIRED_TOKEN = "opaque-token-that-expired"

PROFILES: dict[str, dict] = {
    VALID_TOKEN: {
        "user_id": "user-1",
        "email": "user@example.com",
        "name": "Test User",
        "account_id": "acme",
        "account_ids": ["acme"],
        "is_admin": False,
    },
    STAFF_TOKEN: {
        "user_id": "staff-1",
        "email": "staff@example.com",
        "name": "Staff",
        "account_id": "acme",
        "account_ids": ["acme"],
        "is_admin": True,
    },
}

REJECTIONS: dict[str, str] = {
    REVOKED_TOKEN: "Token has been revoked — please log in again",
    EXPIRED_TOKEN: "Invalid or expired token",
}


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def register_token(
    fake_auth,
    token: str,
    *,
    user_id: str = "user-x",
    email: str = "",
    name: str = "",
    account_id: str = "",
    account_ids: list[str] | None = None,
    is_admin: bool = False,
) -> str:
    """Teach the fake auth-service about an opaque token; return the token.

    Replaces the JWT minting this suite used to do. The gateway never inspects
    a token, so a test only needs auth-service to agree that this string maps
    to this user.
    """
    fake_auth.profiles[token] = {
        "user_id": user_id,
        "email": email,
        "name": name,
        "account_id": account_id,
        "account_ids": account_ids if account_ids is not None else ([account_id] if account_id else []),
        "is_admin": is_admin,
    }
    return token


class FakeAuthService:
    """Stands in for auth-service's ``GET /auth/me`` — the validation endpoint.

    ``calls`` is the assertion surface for the caching tests: it counts how
    many times the gateway actually asked, which is the whole point of the
    cache.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail_with: Exception | None = None
        self.status_override: int | None = None
        self.profiles = dict(PROFILES)

    def handler(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "")[7:].strip()
        self.calls.append(token)

        if self.fail_with is not None:
            raise self.fail_with
        if self.status_override is not None:
            return httpx.Response(self.status_override, json={"detail": "upstream said no"})

        if token in self.profiles:
            return httpx.Response(200, json=self.profiles[token])
        return httpx.Response(
            401, json={"detail": REJECTIONS.get(token, "Invalid or expired token")}
        )

    def revoke(self, token: str) -> None:
        """What auth-service does on logout — the token now 401s."""
        self.profiles.pop(token, None)


class FakeUpstreams:
    """Every service behind the gateway, as one transport handler.

    Echoes back what it received so proxy tests can assert on exactly what was
    forwarded. ``requests`` is the record of what reached a service at all,
    which is how the gate is tested: a blocked request must leave it empty.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.fail_with: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            raise self.fail_with

        path = request.url.path
        if path == "/health/live":
            return httpx.Response(200, json={"status": "alive"})

        if request.url.host == "auth.test":
            if path == "/auth/login":
                return httpx.Response(
                    200,
                    json={
                        "access_token": VALID_TOKEN,
                        "token_type": "bearer",
                        "user": {"user_id": "user-1", "email": "user@example.com"},
                        "account_id": "acme",
                    },
                )
            if path == "/auth/register":
                return httpx.Response(201, json={"access_token": VALID_TOKEN})
            if path == "/auth/logout":
                return httpx.Response(204)

        return httpx.Response(
            self.status,
            json={
                "seen": {
                    "method": request.method,
                    "path": path,
                    "query": request.url.query.decode(),
                    "headers": {k.lower(): v for k, v in request.headers.items()},
                    "body": request.content.decode() if request.content else "",
                    "host": request.url.host,
                }
            },
        )

    def paths_seen(self) -> list[str]:
        return [r.url.path for r in self.requests]


@pytest.fixture
def fake_auth() -> FakeAuthService:
    return FakeAuthService()


@pytest.fixture
def upstreams() -> FakeUpstreams:
    return FakeUpstreams()


@pytest.fixture
def client(fake_auth: FakeAuthService, upstreams: FakeUpstreams):
    """TestClient with the whole platform faked and all shared state reset.

    The app object is module-level (built once at import), so its rate-limit
    windows, usage counters and validation cache would otherwise leak between
    tests and make them order-dependent.
    """
    with TestClient(app) as c:
        app.state.proxy_client = ProxyClient(
            client=httpx.AsyncClient(transport=httpx.MockTransport(upstreams.handler))
        )
        app.state.introspector = TokenIntrospector(
            client=httpx.AsyncClient(transport=httpx.MockTransport(fake_auth.handler))
        )
        import features.usage as usage_module

        usage_module._tracker = UsageTracker(collection=None)

        # Both the windows AND the ceilings are restored. The ceilings matter
        # because a test that lowers one is otherwise mutating the module-level
        # app for every test that follows it.
        app.state.rate_limiter.reset()
        app.state.rate_limiter._limits.update(
            {
                "user": gateway_settings.user_rpm,
                "account": gateway_settings.account_rpm,
                "ip": gateway_settings.anonymous_rpm,
            }
        )

        yield c

    app.state.rate_limiter.reset()


@pytest.fixture
def user_token() -> str:
    return VALID_TOKEN


@pytest.fixture
def staff_token() -> str:
    """An administrator — what the gateway's own /v1 admin routes require."""
    return STAFF_TOKEN

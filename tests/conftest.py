"""Shared fixtures.

The suite never touches a network, a MongoDB or a real auth-service. Two fake
upstreams are injected as httpx ``MockTransport`` handlers through the same
constructor argument the production classes already expose (``client=``), so
the real ``AuthServiceClient`` and ``ProxyClient`` code paths — header
building, error translation, streaming, connection release — are the ones
under test. Only the socket is fake.

Env defaults are set *before* any app import because settings objects are
module-level singletons built at import time; real environment variables
outrank .env in pydantic-settings, so this also keeps the suite hermetic on a
developer machine with a fully populated .env.
"""
from __future__ import annotations

import os

os.environ.setdefault("GATEWAY_JWT_SECRET", "test-secret-not-for-production-use-only")
os.environ.setdefault("GATEWAY_MONGO_URI", "")
os.environ.setdefault("GATEWAY_AUTH_SERVICE_URL", "http://auth-service.test")
os.environ.setdefault(
    "GATEWAY_ROUTES",
    "llm:/api/llm:http://llm.test,knowledge:/api/knowledge:http://knowledge.test",
)
os.environ.setdefault("APIGW_ENVIRONMENT", "test")
os.environ.setdefault("APIGW_LOG_FORMAT", "text")

from datetime import datetime, timedelta, timezone  # noqa: E402

import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from features.auth_client import AuthServiceClient  # noqa: E402
from features.config import gateway_settings  # noqa: E402
from features.proxy import ProxyClient  # noqa: E402
from features.revocation import reset_revocation_store  # noqa: E402
from features.usage import UsageTracker  # noqa: E402

TEST_SECRET = "test-secret-not-for-production-use-only"


# ---------------------------------------------------------------------------
# Token minting — stands in for auth-service's features/security.py
# ---------------------------------------------------------------------------

def make_token(
    user_id: str = "user-1",
    email: str = "user@example.com",
    name: str = "Test User",
    account_id: str = "acme",
    org_id: str = "org-1",
    is_portless: bool = False,
    jti: str = "jti-1",
    expires_in_minutes: int = 60,
    secret: str = TEST_SECRET,
    issuer: str = "auth-service",
    audience: str | list[str] = "llm-gateway,knowledge-service",
) -> str:
    """Mint a token shaped exactly like the ones auth-service issues.

    Defaults match a normal signed-in user. Every argument is overridable so a
    test can produce the specific bad token it wants to prove is rejected —
    wrong secret, wrong issuer, expired, and so on.
    """
    now = datetime.now(timezone.utc)
    aud = audience.split(",") if isinstance(audience, str) else audience
    payload = {
        "sub": user_id,
        "email": email,
        "name": name,
        "account_id": account_id,
        "org_id": org_id,
        "is_portless": is_portless,
        "iss": issuer,
        "aud": aud,
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=expires_in_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Fake upstreams
# ---------------------------------------------------------------------------

class FakeAuthService:
    """A stand-in for auth-service that records what it was asked.

    ``requests`` is the assertion surface for the tests that care about *how*
    the gateway called it — that logout was propagated, that the correlation ID
    was forwarded, that a bearer token was passed on.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.login_status = 200
        self.logout_status = 204
        self.fail_with: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            raise self.fail_with

        path = request.url.path

        if path == "/auth/login":
            if self.login_status != 200:
                return httpx.Response(
                    self.login_status,
                    json={"detail": "Invalid email or password"},
                )
            return httpx.Response(
                200,
                json={
                    "access_token": make_token(),
                    "token_type": "bearer",
                    "user": {
                        "user_id": "user-1",
                        "email": "user@example.com",
                        "name": "Test User",
                        "account_id": "acme",
                        "org_id": "org-1",
                    },
                    "account_id": "acme",
                    "accounts": [{"account_id": "acme", "name": "Acme"}],
                },
            )

        if path == "/auth/register":
            return httpx.Response(
                201,
                json={
                    "access_token": make_token(user_id="user-new"),
                    "token_type": "bearer",
                    "user": {
                        "user_id": "user-new",
                        "email": "new@example.com",
                        "name": "New User",
                    },
                },
            )

        if path == "/auth/logout":
            return httpx.Response(self.logout_status)

        if path == "/auth/me":
            return httpx.Response(
                200,
                json={
                    "user_id": "user-1",
                    "email": "user@example.com",
                    "name": "Test User",
                    "account_id": "acme",
                    "org_id": "org-1",
                },
            )

        if path == "/auth/organizations/register":
            return httpx.Response(
                201, json={"org_id": "org-new", "name": "New Org", "created_by": "self-serve"}
            )

        if path == "/health/live":
            return httpx.Response(200, json={"status": "alive"})

        return httpx.Response(404, json={"detail": "not found"})


class FakeUpstream:
    """A stand-in for llm-gateway / knowledge-service.

    Echoes back the path, method, query, headers and body it received, which is
    what lets the proxy tests assert on exactly what the gateway forwarded —
    including the identity headers it injected and the ones it stripped.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.fail_with: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            raise self.fail_with

        if request.url.path == "/health/live":
            return httpx.Response(200, json={"status": "alive"})

        return httpx.Response(
            self.status,
            json={
                "seen": {
                    "method": request.method,
                    "path": request.url.path,
                    "query": request.url.query.decode(),
                    "headers": {k.lower(): v for k, v in request.headers.items()},
                    "body": request.content.decode() if request.content else "",
                    "host": request.url.host,
                }
            },
        )


@pytest.fixture
def fake_auth() -> FakeAuthService:
    return FakeAuthService()


@pytest.fixture
def fake_upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def client(fake_auth: FakeAuthService, fake_upstream: FakeUpstream):
    """TestClient with both upstreams faked and all shared state reset.

    The app object is module-level (built once at import), so its rate-limit
    windows, usage counters and revocation set would otherwise leak between
    tests and make them order-dependent. Everything stateful is reset here.
    """
    reset_revocation_store()

    with TestClient(app) as c:
        # Swapped after startup so the lifespan's real construction still runs;
        # both classes take an injected client as a public constructor argument
        # precisely so this needs no monkeypatching.
        app.state.auth_client = AuthServiceClient(
            client=httpx.AsyncClient(
                transport=httpx.MockTransport(fake_auth.handler),
                base_url=gateway_settings.auth_service_url,
            )
        )
        app.state.proxy_client = ProxyClient(
            client=httpx.AsyncClient(transport=httpx.MockTransport(fake_upstream.handler))
        )
        # A fresh tracker per test, and detached from Mongo, so counts start at
        # zero and nothing schedules a flush.
        import features.usage as usage_module

        usage_module._tracker = UsageTracker(collection=None)

        # Both the windows AND the ceilings are restored. The ceilings matter
        # because a test that lowers one (to make going over budget cheap) is
        # otherwise mutating the module-level app for every test that follows
        # it — which shows up as unrelated tests in later files getting 429s
        # they never asked for.
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
    reset_revocation_store()


@pytest.fixture
def user_token() -> str:
    return make_token()


@pytest.fixture
def staff_token() -> str:
    """A platform-staff token — what the gateway's admin routes require."""
    return make_token(user_id="staff-1", email="staff@portless.io", is_portless=True)

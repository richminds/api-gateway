"""Shared fixtures.

The suite never touches a network or a MongoDB. Every upstream — auth-service
included, since it is now an ordinary upstream — is a single httpx
``MockTransport`` handler injected through the ``client=`` argument
``ProxyClient`` already exposes, so the real proxy code paths (header building,
error translation, streaming, connection release) are the ones under test.
Only the socket is fake.

Env defaults are set *before* any app import because settings objects are
module-level singletons built at import time; real environment variables
outrank .env in pydantic-settings, so this also keeps the suite hermetic on a
developer machine with a fully populated .env.
"""
from __future__ import annotations

import os

os.environ.setdefault("GATEWAY_JWT_SECRET", "test-secret-not-for-production-use-only")
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
os.environ.setdefault("GATEWAY_LOGOUT_PATHS", "/auth/logout")
os.environ.setdefault("APIGW_ENVIRONMENT", "test")
os.environ.setdefault("APIGW_LOG_FORMAT", "text")

from datetime import datetime, timedelta, timezone  # noqa: E402

import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
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
    test can produce the specific bad token it wants to prove is rejected.
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
# The fake platform behind the gateway
# ---------------------------------------------------------------------------

class FakeUpstreams:
    """Every service behind the gateway, as one transport handler.

    Echoes back what it received so proxy tests can assert on exactly what was
    forwarded — the injected identity headers, the translated path, the body.
    ``requests`` is the record of everything that reached a service at all,
    which is how the gate is tested: a blocked request must leave it empty.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.logout_status = 204
        self.fail_with: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            raise self.fail_with

        path = request.url.path

        if path == "/health/live":
            return httpx.Response(200, json={"status": "alive"})

        # ── auth-service ────────────────────────────────────────────────────
        if request.url.host == "auth.test":
            if path == "/auth/login":
                return httpx.Response(
                    200,
                    json={
                        "access_token": make_token(),
                        "token_type": "bearer",
                        "user": {"user_id": "user-1", "email": "user@example.com"},
                        "account_id": "acme",
                    },
                )
            if path == "/auth/register":
                return httpx.Response(
                    201,
                    json={
                        "access_token": make_token(user_id="user-new"),
                        "token_type": "bearer",
                        "user": {"user_id": "user-new", "email": "new@example.com"},
                    },
                )
            if path == "/auth/logout":
                return httpx.Response(self.logout_status)
            if path == "/auth/me":
                return httpx.Response(
                    200, json={"user_id": "user-1", "email": "user@example.com"}
                )

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
def upstreams() -> FakeUpstreams:
    return FakeUpstreams()


@pytest.fixture
def client(upstreams: FakeUpstreams):
    """TestClient with the whole platform faked and all shared state reset.

    The app object is module-level (built once at import), so its rate-limit
    windows, usage counters and revocation set would otherwise leak between
    tests and make them order-dependent.
    """
    reset_revocation_store()

    with TestClient(app) as c:
        app.state.proxy_client = ProxyClient(
            client=httpx.AsyncClient(transport=httpx.MockTransport(upstreams.handler))
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
    reset_revocation_store()


@pytest.fixture
def user_token() -> str:
    return make_token()


@pytest.fixture
def staff_token() -> str:
    """A platform-staff token — what the gateway's own admin routes require."""
    return make_token(user_id="staff-1", email="staff@portless.io", is_portless=True)

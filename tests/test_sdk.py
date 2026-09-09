"""The client SDK, exercised against a fake gateway.

The re-authentication test is the one that matters: holding the session across
token expiry is the behaviour callers would otherwise reimplement, usually
badly, and usually discovering the gap in production.
"""
from __future__ import annotations

import httpx
import pytest

from sdk import GatewayClient, GatewayError


def gateway(handler) -> GatewayClient:
    return GatewayClient(
        "http://gateway.test",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        ),
    )


def login_body(token: str = "token-1") -> dict:
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"user_id": "u1", "email": "u@example.com", "account_id": "acme"},
        "account_id": "acme",
        "accounts": [{"account_id": "acme", "name": "Acme"}],
    }


async def test_login_starts_a_session():
    async with gateway(lambda r: httpx.Response(200, json=login_body())) as gw:
        session = await gw.login("u@example.com", "hunter22")
        assert session.is_authenticated
        assert session.user_id == "u1"
        assert session.account_id == "acme"


async def test_the_token_is_attached_to_later_calls():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/auth/login":
            return httpx.Response(200, json=login_body())
        return httpx.Response(200, json={"ok": True})

    async with gateway(handler) as gw:
        await gw.login("u@example.com", "hunter22")
        await gw.get("/api/llm/v1/models")

    assert seen[-1].headers["authorization"] == "Bearer token-1"


async def test_login_itself_sends_no_token():
    async with gateway(lambda r: httpx.Response(200, json=login_body())) as gw:
        await gw.login("u@example.com", "hunter22")


async def test_an_expired_session_signs_in_again_and_retries():
    """The behaviour the SDK exists for."""
    calls: list[str] = []
    state = {"expired": True}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        if path == "/auth/login":
            return httpx.Response(200, json=login_body("token-2"))
        if state["expired"]:
            state["expired"] = False
            return httpx.Response(
                401, json={"error": {"code": "unauthorized", "reason": "token_expired"}}
            )
        return httpx.Response(200, json={"ok": True})

    async with gateway(handler) as gw:
        await gw.login("u@example.com", "hunter22")
        result = await gw.get("/api/llm/v1/models")

    assert result == {"ok": True}
    # login, the 401'd call, login again, the retry
    assert calls == [
        "/auth/login",
        "/api/llm/v1/models",
        "/auth/login",
        "/api/llm/v1/models",
    ]


async def test_a_401_without_credentials_is_raised_not_retried():
    """A client constructed with a bare token has nothing to sign in with."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(401, json={"error": {"code": "unauthorized"}})

    gw = GatewayClient(
        "http://gateway.test",
        token="stale",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://gateway.test"
        ),
    )
    with pytest.raises(GatewayError) as exc:
        await gw.get("/api/llm/v1/models")
    await gw.aclose()

    assert exc.value.is_auth_error
    assert len(calls) == 1  # not retried


async def test_the_error_envelope_is_parsed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "too fast",
                    "request_id": "rid-9",
                }
            },
        )

    async with gateway(handler) as gw:
        with pytest.raises(GatewayError) as exc:
            await gw.get("/api/llm/v1/models")

    error = exc.value
    assert error.is_rate_limited
    assert error.code == "rate_limit_exceeded"
    assert error.request_id == "rid-9"


async def test_auth_service_detail_errors_are_surfaced():
    """auth-service's own errors are passed through verbatim by the gateway,
    and FastAPI words those as {"detail": ...} rather than the envelope."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid email or password"})

    async with gateway(handler) as gw:
        with pytest.raises(GatewayError) as exc:
            await gw.login("u@example.com", "wrong")

    assert "Invalid email or password" in exc.value.message


async def test_logout_clears_the_session_even_when_the_call_fails():
    """The caller asked to be logged out; keeping a token they believe is gone
    is the worse outcome."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/login":
            return httpx.Response(200, json=login_body())
        return httpx.Response(500, json={"error": {"code": "boom"}})

    async with gateway(handler) as gw:
        await gw.login("u@example.com", "hunter22")
        with pytest.raises(GatewayError):
            await gw.logout()
        assert not gw.session.is_authenticated


async def test_a_204_returns_none():
    async with gateway(lambda r: httpx.Response(204)) as gw:
        assert await gw.get("/api/llm/v1/thing") is None

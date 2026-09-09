"""Auth traffic through the router, and the revocation that makes logout work.

The gateway implements none of this — it routes to auth-service. What it does
own is noticing a successful logout on the way past, because it verifies tokens
locally and would otherwise keep accepting a token auth-service has revoked.
"""
from __future__ import annotations

import httpx

from .conftest import auth_headers, make_token


# ---------------------------------------------------------------------------
# Auth traffic is routed, not reimplemented
# ---------------------------------------------------------------------------

def test_the_login_response_is_passed_through_untouched(client):
    """auth-service's answer is the answer — the gateway does not reshape it."""
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    body = response.json()
    assert set(body) == {"access_token", "token_type", "user", "account_id"}
    assert body["user"]["user_id"] == "user-1"


def test_the_login_request_body_reaches_auth_service_unchanged(client, upstreams):
    """No model in the gateway re-validates or strips fields, so a field
    auth-service adds tomorrow arrives without a gateway change."""
    client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "hunter22",
            "account_id": "acme",
            "some_future_field": "value",
        },
    )
    body = upstreams.requests[0].content.decode()
    assert "some_future_field" in body
    assert "acme" in body


def test_auth_service_status_codes_are_preserved(client, upstreams):
    """A 409 from auth-service reaches the client as a 409, not as something
    the gateway decided to call it."""
    upstreams.status = 409
    response = client.get("/auth/accounts", headers=auth_headers(make_token()))
    assert response.status_code == 409


def test_auth_service_being_down_is_a_502(client, upstreams):
    upstreams.fail_with = httpx.ConnectError("refused")
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    assert response.status_code == 502
    assert response.json()["error"]["service"] == "auth"


def test_authenticated_auth_routes_carry_the_token_upstream(client, user_token, upstreams):
    client.get("/auth/me", headers=auth_headers(user_token))
    assert upstreams.requests[0].headers["authorization"] == f"Bearer {user_token}"
    assert upstreams.requests[0].url.path == "/auth/me"


def test_the_correlation_id_reaches_auth_service(client, upstreams):
    client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "hunter22"},
        headers={"X-Request-ID": "sign-in-42"},
    )
    assert upstreams.requests[0].headers["x-request-id"] == "sign-in-42"


# ---------------------------------------------------------------------------
# Logout — routed, and noticed
# ---------------------------------------------------------------------------

def test_logout_is_routed_to_auth_service(client, user_token, upstreams):
    response = client.post("/auth/logout", headers=auth_headers(user_token))
    assert response.status_code == 204
    assert upstreams.paths_seen() == ["/auth/logout"]


def test_a_token_stops_working_the_moment_logout_succeeds(client, user_token, upstreams):
    """The reason the gateway watches logout go past.

    It verifies tokens locally, so without this the token would keep working
    here until it expired, no matter what auth-service recorded.
    """
    assert client.get("/api/llm/v1/models", headers=auth_headers(user_token)).status_code == 200

    client.post("/auth/logout", headers=auth_headers(user_token))

    after = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert after.status_code == 401
    assert after.json()["error"]["reason"] == "token_revoked"


def test_logout_blocks_the_routed_auth_endpoints_too(client, user_token):
    client.post("/auth/logout", headers=auth_headers(user_token))
    assert client.get("/auth/me", headers=auth_headers(user_token)).status_code == 401


def test_a_failed_logout_revokes_nothing(client, user_token, upstreams):
    """If auth-service refused, the session did not end — revoking here would
    log the user out of a session that is still live everywhere else."""
    upstreams.logout_status = 500

    client.post("/auth/logout", headers=auth_headers(user_token))

    still_valid = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert still_valid.status_code == 200


def test_logout_revokes_only_that_token(client, upstreams):
    """Per jti, not per user — logging out on your phone must not sign you out
    on your laptop."""
    phone = make_token(jti="jti-phone")
    laptop = make_token(jti="jti-laptop")

    client.post("/auth/logout", headers=auth_headers(phone))

    assert client.get("/api/llm/v1/models", headers=auth_headers(phone)).status_code == 401
    assert client.get("/api/llm/v1/models", headers=auth_headers(laptop)).status_code == 200


def test_a_second_logout_is_rejected_by_the_gate(client, user_token, upstreams):
    assert client.post("/auth/logout", headers=auth_headers(user_token)).status_code == 204
    # The token is already revoked, so it never reaches auth-service again.
    assert client.post("/auth/logout", headers=auth_headers(user_token)).status_code == 401
    assert upstreams.paths_seen() == ["/auth/logout"]


def test_logout_paths_are_configurable(client, user_token, upstreams, monkeypatch):
    """Nothing about "/auth/logout" is special-cased in code — it is a setting,
    because where logout lives is a fact about the service behind the gateway."""
    from features.config import gateway_settings

    monkeypatch.setattr(gateway_settings, "logout_paths", "")

    client.post("/auth/logout", headers=auth_headers(user_token))

    # Routed as before, but no longer treated as ending the session.
    assert upstreams.paths_seen() == ["/auth/logout"]
    assert client.get("/api/llm/v1/models", headers=auth_headers(user_token)).status_code == 200

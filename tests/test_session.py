"""Login, logout, and the revocation that makes logout mean something.

The logout tests are the ones worth reading. Because the gateway verifies
tokens locally, a logout recorded only at auth-service would leave the token
working for every proxied call until it expired — so the gateway records it
locally too, first, and these tests pin that behaviour down.
"""
from __future__ import annotations

import httpx

from .conftest import auth_headers, make_token


# ---------------------------------------------------------------------------
# Login / register pass-through
# ---------------------------------------------------------------------------

def test_login_failure_is_passed_through_verbatim(client, fake_auth):
    """auth-service's own status is the answer — the gateway does not
    reinterpret it."""
    fake_auth.login_status = 401
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_login_forwards_the_correlation_id_to_auth_service(client, fake_auth):
    """One ID ties the gateway's log to auth-service's log for one sign-in."""
    client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "hunter22"},
        headers={"X-Request-ID": "sign-in-42"},
    )
    assert fake_auth.requests[0].headers["x-request-id"] == "sign-in-42"


def test_auth_service_down_on_login_is_502(client, fake_auth):
    fake_auth.fail_with = httpx.ConnectError("refused")
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    assert response.status_code == 502
    assert response.json()["error"]["service"] == "auth-service"


def test_auth_service_timeout_on_login_is_504(client, fake_auth):
    fake_auth.fail_with = httpx.ReadTimeout("slow")
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    assert response.status_code == 504


def test_me_is_proxied_to_auth_service(client, user_token, fake_auth):
    response = client.get("/auth/me", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert [r.url.path for r in fake_auth.requests] == ["/auth/me"]
    # The caller's own token is what auth-service is asked with.
    assert fake_auth.requests[0].headers["authorization"] == f"Bearer {user_token}"


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def test_logout_succeeds(client, user_token):
    response = client.post("/auth/logout", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert response.json()["status"] == "logged_out"


def test_logout_is_propagated_to_auth_service(client, user_token, fake_auth):
    client.post("/auth/logout", headers=auth_headers(user_token))
    assert [r.url.path for r in fake_auth.requests] == ["/auth/logout"]


def test_token_stops_working_immediately_after_logout(client, user_token, fake_upstream):
    """The whole point of local revocation.

    Without it the token would keep working at the gateway until it expired,
    because the gateway does not ask auth-service about ordinary requests.
    """
    assert client.get("/api/llm/v1/models", headers=auth_headers(user_token)).status_code == 200

    client.post("/auth/logout", headers=auth_headers(user_token))

    after = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert after.status_code == 401
    assert after.json()["error"]["reason"] == "token_revoked"


def test_logout_blocks_the_auth_endpoints_too(client, user_token):
    client.post("/auth/logout", headers=auth_headers(user_token))
    assert client.get("/auth/whoami", headers=auth_headers(user_token)).status_code == 401
    assert client.get("/auth/me", headers=auth_headers(user_token)).status_code == 401


def test_logout_does_not_affect_other_sessions(client, fake_upstream):
    """Revocation is per token (per jti), not per user — logging out on your
    phone must not sign you out on your laptop."""
    phone = make_token(jti="jti-phone")
    laptop = make_token(jti="jti-laptop")

    client.post("/auth/logout", headers=auth_headers(phone))

    assert client.get("/api/llm/v1/models", headers=auth_headers(phone)).status_code == 401
    assert client.get("/api/llm/v1/models", headers=auth_headers(laptop)).status_code == 200


def test_logout_succeeds_even_when_auth_service_is_down(client, user_token, fake_auth):
    """The local revocation has already happened, so the token is dead
    everywhere it could still be used through this gateway."""
    fake_auth.fail_with = httpx.ConnectError("refused")

    response = client.post("/auth/logout", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert "unreachable" in response.json()["detail"]

    after = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert after.status_code == 401


def test_logout_is_idempotent(client, user_token):
    first = client.post("/auth/logout", headers=auth_headers(user_token))
    assert first.status_code == 200
    # The second attempt is rejected by the gate itself — the token is already
    # revoked, so it never reaches the controller.
    second = client.post("/auth/logout", headers=auth_headers(user_token))
    assert second.status_code == 401


def test_an_expired_token_is_not_added_to_the_revocation_set(client):
    """Nothing to revoke: the token is already dead by expiry, and an entry
    would only occupy the store until a TTL that has already passed."""
    from features.revocation import get_revocation_store

    expired = make_token(expires_in_minutes=-1, jti="jti-expired")
    client.post("/auth/logout", headers=auth_headers(expired))

    store = get_revocation_store()
    assert len(store) == 0

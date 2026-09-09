"""The core rule: every request needs a JWT except sign-in and sign-up.

This is the requirement the gateway exists to satisfy, so it gets the most
direct tests in the suite.
"""
from __future__ import annotations

import pytest

from .conftest import auth_headers, make_token


# ---------------------------------------------------------------------------
# Public endpoints — reachable with no token at all
# ---------------------------------------------------------------------------

def test_login_needs_no_token(client, fake_auth):
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    assert response.status_code == 200
    assert response.json()["access_token"]
    assert [r.url.path for r in fake_auth.requests] == ["/auth/login"]


def test_register_needs_no_token(client):
    response = client.post(
        "/auth/register",
        json={"email": "new@example.com", "name": "New User", "password": "hunter22"},
    )
    assert response.status_code == 201
    assert response.json()["access_token"]


def test_organization_register_needs_no_token(client):
    response = client.post("/auth/organizations/register", json={"name": "New Org"})
    assert response.status_code == 201
    assert response.json()["org_id"] == "org-new"


@pytest.mark.parametrize("path", ["/health", "/health/live", "/health/ready", "/"])
def test_health_and_banner_need_no_token(client, path):
    assert client.get(path).status_code == 200


# ---------------------------------------------------------------------------
# Everything else requires a valid token
# ---------------------------------------------------------------------------

def test_proxied_request_without_token_is_401(client, fake_upstream):
    response = client.get("/api/llm/v1/models")
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "missing_token"
    # The point of the gate: the upstream was never contacted.
    assert fake_upstream.requests == []


def test_proxied_request_with_valid_token_reaches_upstream(client, user_token, fake_upstream):
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert len(fake_upstream.requests) == 1


def test_auth_endpoints_other_than_login_require_a_token(client):
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/whoami").status_code == 401
    assert client.post("/auth/logout").status_code == 401


def test_401_carries_www_authenticate_header(client):
    response = client.get("/api/llm/v1/models")
    assert response.headers["www-authenticate"] == "Bearer"


# ---------------------------------------------------------------------------
# Token validation — each failure mode is distinguishable by `reason`
# ---------------------------------------------------------------------------

def test_expired_token_is_rejected(client, fake_upstream):
    token = make_token(expires_in_minutes=-5)
    response = client.get("/api/llm/v1/models", headers=auth_headers(token))
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "token_expired"
    assert fake_upstream.requests == []


def test_token_signed_with_the_wrong_secret_is_rejected(client):
    token = make_token(secret="a-different-secret-entirely")
    response = client.get("/api/llm/v1/models", headers=auth_headers(token))
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "invalid_token"


def test_token_from_the_wrong_issuer_is_rejected(client):
    token = make_token(issuer="some-other-service")
    response = client.get("/api/llm/v1/models", headers=auth_headers(token))
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "invalid_issuer"


def test_token_for_another_audience_is_rejected(client):
    token = make_token(audience=["some-other-platform"])
    response = client.get("/api/llm/v1/models", headers=auth_headers(token))
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "invalid_audience"


def test_garbage_token_is_rejected(client):
    response = client.get(
        "/api/llm/v1/models", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert response.status_code == 401


def test_non_bearer_authorization_is_rejected(client):
    response = client.get(
        "/api/llm/v1/models", headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "missing_token"


def test_bearer_scheme_is_case_insensitive(client, user_token):
    response = client.get(
        "/api/llm/v1/models", headers={"Authorization": f"bearer {user_token}"}
    )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# whoami — the claims the gateway acts on
# ---------------------------------------------------------------------------

def test_whoami_returns_the_verified_claims(client, user_token):
    response = client.get("/auth/whoami", headers=auth_headers(user_token))
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "user-1"
    assert body["account_id"] == "acme"
    assert body["org_id"] == "org-1"
    assert body["is_portless"] is False


def test_whoami_makes_no_call_to_auth_service(client, user_token, fake_auth):
    """Verification is local — that is the whole design (features/tokens.py)."""
    client.get("/auth/whoami", headers=auth_headers(user_token))
    assert fake_auth.requests == []


def test_ordinary_proxied_traffic_never_touches_auth_service(
    client, user_token, fake_auth
):
    """The property that keeps auth-service off the critical path."""
    for _ in range(5):
        client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert fake_auth.requests == []

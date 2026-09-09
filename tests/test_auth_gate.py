"""Secured vs non-secured endpoints — the rule the gateway enforces.

Private by default: a path is public only if configured so. These tests pin
down both halves — that the configured public paths get through without a
token, and that everything else does not.
"""
from __future__ import annotations

import pytest

from .conftest import auth_headers, make_token


# ---------------------------------------------------------------------------
# Configured public paths — routed without a token
# ---------------------------------------------------------------------------

def test_login_is_public_and_routed_to_auth_service(client, upstreams):
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    assert response.status_code == 200
    assert response.json()["access_token"]
    # Routed, not implemented: auth-service saw it, at its own path.
    assert upstreams.paths_seen() == ["/auth/login"]
    assert upstreams.requests[0].url.host == "auth.test"


def test_register_is_public_and_routed(client, upstreams):
    response = client.post(
        "/auth/register",
        json={"email": "new@example.com", "name": "New User", "password": "hunter22"},
    )
    assert response.status_code == 201
    assert upstreams.paths_seen() == ["/auth/register"]


def test_a_public_rule_can_be_scoped_to_one_method(client, upstreams):
    """The rule is POST:/auth/login — a GET of the same path is not public."""
    assert client.get("/auth/login").status_code == 401
    assert upstreams.requests == []


def test_gateway_infrastructure_paths_are_always_public(client):
    for path in ("/", "/health", "/health/live", "/health/ready"):
        assert client.get(path).status_code == 200


def test_cors_preflight_is_never_401(client):
    """A preflight never carries an Authorization header, by design — a 401 on
    it breaks every browser client while protecting nothing."""
    response = client.options(
        "/api/llm/v1/models",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code != 401


# ---------------------------------------------------------------------------
# Everything else is private
# ---------------------------------------------------------------------------

def test_a_routed_service_path_requires_a_token(client, upstreams):
    response = client.get("/api/llm/v1/models")
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "missing_token"
    # The point of the gate: nothing reached the service.
    assert upstreams.requests == []


def test_auth_paths_that_are_not_configured_public_require_a_token(client, upstreams):
    """/auth/me and /auth/logout are routed like anything else — being under
    /auth grants nothing."""
    assert client.get("/auth/me").status_code == 401
    assert client.post("/auth/logout").status_code == 401
    assert upstreams.requests == []


def test_auth_service_admin_routes_require_a_token(client, upstreams):
    """The staff endpoints are routed, so they are reachable — but only with a
    token, and auth-service still enforces its own rules on top."""
    assert client.get("/auth/accounts").status_code == 401
    assert client.get("/auth/users").status_code == 401
    assert upstreams.requests == []


def test_a_valid_token_reaches_the_service(client, user_token, upstreams):
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert len(upstreams.requests) == 1


def test_401_carries_www_authenticate(client):
    response = client.get("/api/llm/v1/models")
    assert response.headers["www-authenticate"] == "Bearer"


# ---------------------------------------------------------------------------
# Token validation — each failure mode is distinguishable by `reason`
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"expires_in_minutes": -5}, "token_expired"),
        ({"secret": "a-different-secret-entirely"}, "invalid_token"),
        ({"issuer": "some-other-service"}, "invalid_issuer"),
        ({"audience": ["some-other-platform"]}, "invalid_audience"),
    ],
)
def test_bad_tokens_are_rejected_with_a_specific_reason(client, upstreams, kwargs, reason):
    response = client.get(
        "/api/llm/v1/models", headers=auth_headers(make_token(**kwargs))
    )
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == reason
    assert upstreams.requests == []


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
# Local verification
# ---------------------------------------------------------------------------

def test_verifying_a_token_costs_no_call_to_auth_service(client, user_token, upstreams):
    """The property that keeps auth-service off the critical path: routed
    traffic is verified locally and only touches the service it was for."""
    for _ in range(5):
        client.get("/api/llm/v1/models", headers=auth_headers(user_token))

    assert len(upstreams.requests) == 5
    assert all(r.url.host == "llm.test" for r in upstreams.requests)

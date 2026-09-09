"""The gate: auth-service decides, the gateway enforces.

The gateway holds no signing key and decodes nothing, so these tests are about
*delegation* — that it asks, that it acts on the answer, and that it never
lets a request through without one.
"""
from __future__ import annotations

import httpx

from .conftest import (
    EXPIRED_TOKEN,
    REVOKED_TOKEN,
    VALID_TOKEN,
    auth_headers,
)


# ---------------------------------------------------------------------------
# Public paths — no token, and no call to auth-service
# ---------------------------------------------------------------------------

def test_login_is_public_and_routed(client, upstreams, fake_auth):
    response = client.post(
        "/auth/login", json={"email": "user@example.com", "password": "hunter22"}
    )
    assert response.status_code == 200
    assert upstreams.paths_seen() == ["/auth/login"]
    # Nothing to validate — so auth-service was not asked to validate anything.
    assert fake_auth.calls == []


def test_register_is_public(client, upstreams):
    response = client.post(
        "/auth/register",
        json={"email": "new@example.com", "name": "New", "password": "hunter22"},
    )
    assert response.status_code == 201
    assert upstreams.paths_seen() == ["/auth/register"]


def test_a_public_rule_can_be_scoped_to_one_method(client, upstreams):
    """The rule is POST:/auth/login — a GET of the same path is not public."""
    assert client.get("/auth/login").status_code == 401
    assert upstreams.requests == []


def test_health_and_banner_are_always_public(client):
    for path in ("/", "/health", "/health/live", "/health/ready"):
        assert client.get(path).status_code == 200


def test_cors_preflight_is_never_401(client):
    response = client.options(
        "/api/llm/v1/models",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code != 401


# ---------------------------------------------------------------------------
# Private paths — auth-service is asked, and its verdict is enforced
# ---------------------------------------------------------------------------

def test_a_valid_token_is_validated_by_auth_service_then_routed(
    client, user_token, upstreams, fake_auth
):
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.status_code == 200
    # The gateway asked auth-service about this exact token...
    assert fake_auth.calls == [VALID_TOKEN]
    # ...and only then forwarded it.
    assert len(upstreams.requests) == 1


def test_no_token_is_401_without_asking_auth_service(client, upstreams, fake_auth):
    """A missing header is not something auth-service could rule on, so there
    is nothing to ask about."""
    response = client.get("/api/llm/v1/models")
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "missing_token"
    assert fake_auth.calls == []
    assert upstreams.requests == []


def test_a_token_auth_service_rejects_is_401(client, upstreams, fake_auth):
    response = client.get("/api/llm/v1/models", headers=auth_headers(EXPIRED_TOKEN))
    assert response.status_code == 401
    assert fake_auth.calls == [EXPIRED_TOKEN]
    # Rejected at the edge — nothing reached the service.
    assert upstreams.requests == []


def test_auth_services_own_wording_reaches_the_client(client, fake_auth):
    """"Expired", "revoked" and "invalid" call for different reactions, and
    only auth-service knows which it was."""
    revoked = client.get("/api/llm/v1/models", headers=auth_headers(REVOKED_TOKEN))
    assert "revoked" in revoked.json()["error"]["message"].lower()

    expired = client.get("/api/llm/v1/models", headers=auth_headers(EXPIRED_TOKEN))
    assert "expired" in expired.json()["error"]["message"].lower()


def test_an_unknown_token_is_rejected(client, upstreams):
    response = client.get(
        "/api/llm/v1/models", headers=auth_headers("something-made-up")
    )
    assert response.status_code == 401
    assert upstreams.requests == []


def test_non_bearer_authorization_is_rejected(client, fake_auth):
    response = client.get(
        "/api/llm/v1/models", headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["reason"] == "missing_token"
    assert fake_auth.calls == []


def test_bearer_scheme_is_case_insensitive(client, user_token):
    response = client.get(
        "/api/llm/v1/models", headers={"Authorization": f"bearer {user_token}"}
    )
    assert response.status_code == 200


def test_401_carries_www_authenticate(client):
    assert client.get("/api/llm/v1/models").headers["www-authenticate"] == "Bearer"


def test_auth_paths_that_are_not_public_still_need_a_token(client, upstreams):
    """Being under /auth grants nothing — it is routed like anything else."""
    assert client.get("/auth/me").status_code == 401
    assert client.post("/auth/logout").status_code == 401
    assert client.get("/auth/accounts").status_code == 401
    assert upstreams.requests == []


# ---------------------------------------------------------------------------
# The identity comes from auth-service, not from the token
# ---------------------------------------------------------------------------

def test_the_identity_is_built_from_auth_services_answer(client, user_token):
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    headers = response.json()["seen"]["headers"]
    assert headers["x-user-id"] == "user-1"
    assert headers["x-org-id"] == "org-1"
    assert headers["x-account-id"] == "acme"


def test_a_changed_profile_is_picked_up_without_a_new_token(client, user_token, fake_auth):
    """The advantage of asking: an admin moving a user to another organization
    takes effect on the next validation, not when their token expires."""
    first = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert first.json()["seen"]["headers"]["x-org-id"] == "org-1"

    fake_auth.profiles[user_token] = {**fake_auth.profiles[user_token], "org_id": "org-2"}

    second = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert second.json()["seen"]["headers"]["x-org-id"] == "org-2"


def test_a_200_with_no_user_id_is_not_treated_as_authenticated(client, fake_auth):
    """A malformed answer must not admit a request with no principal to rate
    limit or meter."""
    fake_auth.profiles["odd-token"] = {"email": "nobody@example.com"}
    response = client.get("/api/llm/v1/models", headers=auth_headers("odd-token"))
    assert response.status_code == 502


# ---------------------------------------------------------------------------
# When auth-service cannot be asked — fail closed
# ---------------------------------------------------------------------------

def test_auth_service_unreachable_fails_closed_with_502(client, upstreams, fake_auth):
    """Admitting unvalidated requests when the validator is down would turn an
    outage into an open front door."""
    fake_auth.fail_with = httpx.ConnectError("refused")
    response = client.get("/api/llm/v1/models", headers=auth_headers(VALID_TOKEN))
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "auth_service_unavailable"
    assert upstreams.requests == []


def test_auth_service_timeout_fails_closed_with_504(client, fake_auth):
    fake_auth.fail_with = httpx.ReadTimeout("slow")
    response = client.get("/api/llm/v1/models", headers=auth_headers(VALID_TOKEN))
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "auth_service_timeout"


def test_an_unexpected_status_from_auth_service_is_not_a_verdict(client, fake_auth):
    """A 500 or a proxy error page says nothing about the token, so it must not
    be reported to the caller as "your credentials are bad"."""
    fake_auth.status_override = 500
    response = client.get("/api/llm/v1/models", headers=auth_headers(VALID_TOKEN))
    assert response.status_code == 502


def test_public_paths_still_work_while_auth_service_is_down(client, fake_auth, upstreams):
    """Nothing to validate, so nothing to be blocked by. (The login itself will
    fail — that is routing, not the gate.)"""
    fake_auth.fail_with = httpx.ConnectError("refused")
    response = client.post("/auth/login", json={"email": "x@y.z", "password": "p"})
    assert response.status_code != 401

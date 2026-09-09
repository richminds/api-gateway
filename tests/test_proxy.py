"""Forwarding: path translation, identity injection, and header hygiene.

The header-spoofing tests are the security-critical ones. Downstream services
trust ``X-User-ID`` and ``X-Org-ID``, so the gateway must replace whatever the
caller sent with what the token actually says — not merely fill them in when
absent.
"""
from __future__ import annotations

import httpx
import pytest

from .conftest import VALID_TOKEN, auth_headers, register_token


def seen(response) -> dict:
    """The request the fake upstream received, as it saw it."""
    return response.json()["seen"]


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def test_prefix_is_stripped_before_forwarding(client, user_token):
    """The upstream keeps serving the paths it always did — it has no idea it
    is behind a gateway."""
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert seen(response)["path"] == "/v1/models"


def test_each_prefix_reaches_its_own_service(client, user_token, upstreams):
    client.get("/api/llm/v1/chat", headers=auth_headers(user_token))
    client.get("/api/knowledge/v1/query", headers=auth_headers(user_token))
    hosts = [r.url.host for r in upstreams.requests]
    assert hosts == ["llm.test", "knowledge.test"]


def test_unregistered_path_is_404(client, user_token):
    response = client.get("/api/nonexistent/thing", headers=auth_headers(user_token))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "route_not_found"


def test_query_string_is_preserved(client, user_token):
    response = client.get(
        "/api/llm/v1/models?limit=10&verbose=true", headers=auth_headers(user_token)
    )
    assert seen(response)["query"] == "limit=10&verbose=true"


def test_request_body_is_forwarded(client, user_token):
    response = client.post(
        "/api/llm/v1/chat",
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers=auth_headers(user_token),
    )
    assert "messages" in seen(response)["body"]


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_every_method_is_proxied(client, user_token, method):
    response = client.request(
        method, "/api/llm/v1/thing", headers=auth_headers(user_token)
    )
    assert response.status_code == 200
    assert seen(response)["method"] == method


def test_upstream_status_code_is_passed_through(client, user_token, upstreams):
    upstreams.status = 422
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Identity injection — what the upstream is told about the caller
# ---------------------------------------------------------------------------

def test_verified_identity_is_injected_as_headers(client, user_token):
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    headers = seen(response)["headers"]
    assert headers["x-user-id"] == "user-1"
    assert headers["x-user-email"] == "user@example.com"
    assert headers["x-account-id"] == "acme"
    assert headers["x-org-id"] == "org-1"
    assert headers["x-authenticated-via"] == "api-gateway"


def test_bearer_token_is_forwarded_too(client, user_token):
    """Downstream services validate the JWT themselves and keep working
    unchanged — the injected headers are a convenience on top, not a
    replacement."""
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert seen(response)["headers"]["authorization"] == f"Bearer {user_token}"


def test_portless_flag_is_only_sent_when_true(client, fake_auth):
    register_token(fake_auth, "tok-ordinary", user_id="u1", is_portless=False)
    register_token(fake_auth, "tok-staff", user_id="u2", is_portless=True)

    ordinary = client.get("/api/llm/v1/models", headers=auth_headers("tok-ordinary"))
    assert "x-is-portless" not in seen(ordinary)["headers"]

    staff = client.get("/api/llm/v1/models", headers=auth_headers("tok-staff"))
    assert seen(staff)["headers"]["x-is-portless"] == "true"


def test_correlation_id_is_forwarded(client, user_token):
    response = client.get(
        "/api/llm/v1/models",
        headers={**auth_headers(user_token), "X-Request-ID": "trace-me-123"},
    )
    assert seen(response)["headers"]["x-request-id"] == "trace-me-123"
    assert response.headers["x-request-id"] == "trace-me-123"


def test_a_correlation_id_is_minted_when_absent(client, user_token):
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.headers["x-request-id"]
    assert seen(response)["headers"]["x-request-id"] == response.headers["x-request-id"]


# ---------------------------------------------------------------------------
# Header spoofing — the security-critical case
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "header,spoofed",
    [
        ("X-User-ID", "someone-else"),
        ("X-Org-ID", "another-tenant"),
        ("X-Account-ID", "another-account"),
        ("X-User-Email", "admin@evil.test"),
        ("X-Is-Portless", "true"),
        ("X-Authenticated-Via", "trust-me"),
    ],
)
def test_caller_supplied_identity_headers_are_replaced(client, user_token, header, spoofed):
    """A caller must not be able to become someone else by sending a header."""
    response = client.get(
        "/api/llm/v1/models",
        headers={**auth_headers(user_token), header: spoofed},
    )
    forwarded = seen(response)["headers"].get(header.lower())
    assert forwarded != spoofed


def test_spoofed_identity_is_replaced_with_the_real_one(client, user_token):
    response = client.get(
        "/api/llm/v1/models",
        headers={
            **auth_headers(user_token),
            "X-User-ID": "someone-else",
            "X-Org-ID": "another-tenant",
        },
    )
    headers = seen(response)["headers"]
    assert headers["x-user-id"] == "user-1"
    assert headers["x-org-id"] == "org-1"


def test_forwarded_for_is_not_taken_from_the_caller(client, user_token):
    """The gateway is the trust boundary — a caller cannot forge its own
    origin for the upstream's benefit."""
    response = client.get(
        "/api/llm/v1/models",
        headers={**auth_headers(user_token), "X-Forwarded-For": "1.2.3.4"},
    )
    assert seen(response)["headers"].get("x-forwarded-for") != "1.2.3.4"


def test_hop_by_hop_headers_are_not_forwarded(client, user_token):
    response = client.get(
        "/api/llm/v1/models",
        headers={**auth_headers(user_token), "Connection": "keep-alive", "TE": "trailers"},
    )
    headers = seen(response)["headers"]
    assert "te" not in headers


def test_host_header_names_the_upstream(client, user_token):
    """Not the gateway — otherwise a virtual-hosted upstream routes it wrongly."""
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert seen(response)["host"] == "llm.test"


# ---------------------------------------------------------------------------
# Upstream failures
# ---------------------------------------------------------------------------

def test_unreachable_upstream_is_502(client, user_token, upstreams):
    upstreams.fail_with = httpx.ConnectError("connection refused")
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unavailable"
    # Named, not URL'd — a base URL can carry credentials.
    assert response.json()["error"]["service"] == "llm"


def test_upstream_timeout_is_504(client, user_token, upstreams):
    upstreams.fail_with = httpx.ReadTimeout("too slow")
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "upstream_timeout"


def test_errors_carry_the_request_id(client, user_token, upstreams):
    """What turns "it failed" in a bug report into the exact log line."""
    upstreams.fail_with = httpx.ConnectError("nope")
    response = client.get(
        "/api/llm/v1/models",
        headers={**auth_headers(user_token), "X-Request-ID": "find-me"},
    )
    assert response.json()["error"]["request_id"] == "find-me"

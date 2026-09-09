"""Request counting per user and per account, and the endpoints that report it."""
from __future__ import annotations

import pytest

from features.usage import UsageTracker

from .conftest import VALID_TOKEN, auth_headers, register_token


# ---------------------------------------------------------------------------
# The tracker itself
# ---------------------------------------------------------------------------

def test_requests_are_counted_per_key():
    tracker = UsageTracker()
    tracker.record("u1", "acme", "llm", 200, 10.0)
    tracker.record("u1", "acme", "llm", 200, 30.0)

    rows = tracker.snapshot()
    assert len(rows) == 1
    assert rows[0].counters.requests == 2
    assert rows[0].counters.avg_duration_ms == 20.0


def test_status_codes_are_bucketed():
    tracker = UsageTracker()
    tracker.record("u1", "acme", "llm", 200, 1.0)
    tracker.record("u1", "acme", "llm", 404, 1.0)
    tracker.record("u1", "acme", "llm", 503, 1.0)

    counters = tracker.snapshot()[0].counters
    assert (counters.status_2xx, counters.status_4xx, counters.status_5xx) == (1, 1, 1)
    assert counters.errors == 2  # 4xx and 5xx both count as errors


def test_different_users_are_counted_separately():
    tracker = UsageTracker()
    tracker.record("u1", "acme", "llm", 200, 1.0)
    tracker.record("u2", "acme", "llm", 200, 1.0)
    assert len(tracker.snapshot()) == 2
    assert len(tracker.snapshot(user_id="u1")) == 1


def test_the_same_user_is_counted_separately_per_service():
    tracker = UsageTracker()
    tracker.record("u1", "acme", "llm", 200, 1.0)
    tracker.record("u1", "acme", "knowledge", 200, 1.0)
    assert len(tracker.snapshot()) == 2
    assert len(tracker.snapshot(service="llm")) == 1


def test_rollup_by_account_sums_across_users():
    tracker = UsageTracker()
    tracker.record("u1", "acme", "llm", 200, 1.0)
    tracker.record("u2", "acme", "llm", 200, 1.0)
    tracker.record("u3", "globex", "llm", 200, 1.0)

    by_account = {row["account"]: row["requests"] for row in tracker.aggregate("account")}
    assert by_account == {"acme": 2, "globex": 1}


def test_rollup_by_user_sums_across_services():
    tracker = UsageTracker()
    tracker.record("u1", "acme", "llm", 200, 1.0)
    tracker.record("u1", "acme", "knowledge", 200, 1.0)

    by_user = {row["user"]: row["requests"] for row in tracker.aggregate("user")}
    assert by_user == {"u1": 2}


def test_unknown_rollup_dimension_is_rejected():
    with pytest.raises(ValueError):
        UsageTracker().aggregate("colour")


def test_unauthenticated_traffic_is_counted_under_an_empty_key():
    """A real, queryable category — "how much sign-in traffic did we take" —
    rather than a gap to be filled in with a guess."""
    tracker = UsageTracker()
    tracker.record("", "", "gateway", 401, 1.0)
    assert tracker.snapshot()[0].key.user_id == ""


async def test_flush_without_storage_is_a_no_op():
    tracker = UsageTracker(collection=None)
    tracker.record("u1", "acme", "llm", 200, 1.0)
    assert await tracker.flush() == 1
    # Totals survive a flush; only the pending buffer is cleared.
    assert tracker.snapshot()[0].counters.requests == 1
    assert await tracker.flush() == 0


# ---------------------------------------------------------------------------
# Metering through the gateway
# ---------------------------------------------------------------------------

def test_proxied_requests_are_counted_against_the_user_and_account(client, user_token, staff_token):
    for _ in range(3):
        client.get("/api/llm/v1/models", headers=auth_headers(user_token))

    response = client.get("/v1/usage", headers=auth_headers(staff_token))
    assert response.status_code == 200
    body = response.json()

    llm_rows = [r for r in body["rows"] if r["service"] == "llm"]
    assert llm_rows[0]["user_id"] == "user-1"
    assert llm_rows[0]["account_id"] == "acme"
    assert llm_rows[0]["requests"] == 3


def test_requests_are_attributed_to_the_service_they_targeted(client, user_token, staff_token):
    client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    client.get("/api/knowledge/v1/query", headers=auth_headers(user_token))

    body = client.get("/v1/usage", headers=auth_headers(staff_token)).json()
    services = {row["service"] for row in body["rows"]}
    assert {"llm", "knowledge"} <= services


def test_rejected_requests_are_counted_too(client, staff_token):
    """A client generating nothing but 401s is still using the platform."""
    client.get("/api/llm/v1/models")  # no token → 401

    body = client.get("/v1/usage", headers=auth_headers(staff_token)).json()
    anonymous = [r for r in body["rows"] if r["user_id"] == ""]
    assert anonymous and anonymous[0]["status_4xx"] >= 1


def test_usage_is_rolled_up_by_account(client, staff_token, fake_auth):
    a = register_token(fake_auth, "tok-a", user_id="user-a", account_id="acme")
    b = register_token(fake_auth, "tok-b", user_id="user-b", account_id="acme")
    c = register_token(fake_auth, "tok-c", user_id="user-c", account_id="globex")

    for token in (a, b, c):
        client.get("/api/llm/v1/models", headers=auth_headers(token))

    body = client.get("/v1/usage", headers=auth_headers(staff_token)).json()
    by_account = {row["account"]: row["requests"] for row in body["by_account"]}
    assert by_account["acme"] == 2
    assert by_account["globex"] == 1


def test_usage_can_be_filtered_to_one_account(client, staff_token, fake_auth):
    acme = register_token(fake_auth, "tok-a", user_id="user-a", account_id="acme")
    globex = register_token(fake_auth, "tok-c", user_id="user-c", account_id="globex")
    client.get("/api/llm/v1/models", headers=auth_headers(acme))
    client.get("/api/llm/v1/models", headers=auth_headers(globex))

    body = client.get(
        "/v1/usage", params={"account_id": "acme"}, headers=auth_headers(staff_token)
    ).json()
    assert {row["account_id"] for row in body["rows"]} == {"acme"}


# ---------------------------------------------------------------------------
# Who may read what
# ---------------------------------------------------------------------------

def test_usage_endpoint_is_staff_only(client, user_token):
    response = client.get("/v1/usage", headers=auth_headers(user_token))
    assert response.status_code == 403


def test_usage_endpoint_still_needs_a_token(client):
    assert client.get("/v1/usage").status_code == 401


def test_a_user_can_read_their_own_usage(client, user_token):
    """Not privileged — a client showing "you have made N requests today"
    should not need a platform administrator."""
    client.get("/api/llm/v1/models", headers=auth_headers(user_token))

    response = client.get("/v1/usage/me", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert all(row["user_id"] == "user-1" for row in response.json()["rows"])


def test_own_usage_cannot_be_widened_to_another_user(client, fake_auth):
    """Scoped to the caller's own user_id — there is no parameter to widen it."""
    a = register_token(fake_auth, "tok-a", user_id="user-a")
    b = register_token(fake_auth, "tok-b", user_id="user-b")
    client.get("/api/llm/v1/models", headers=auth_headers(b))

    body = client.get(
        "/v1/usage/me", params={"user_id": "user-b"}, headers=auth_headers(a)
    ).json()
    assert all(row["user_id"] == "user-a" for row in body["rows"])


def test_rate_limit_and_config_endpoints_are_staff_only(client, user_token, staff_token):
    for path in ("/v1/rate-limits", "/v1/config", "/v1/routes"):
        assert client.get(path, headers=auth_headers(user_token)).status_code == 403
        assert client.get(path, headers=auth_headers(staff_token)).status_code == 200


def test_config_never_exposes_secrets(client, staff_token):
    """There is no signing key here to leak any more — the gateway holds none.
    What it does report is where it validates and how long it caches."""
    body = client.get("/v1/config", headers=auth_headers(staff_token)).json()
    assert not any("secret" in key for key in body)
    assert "mongo_uri" not in body
    assert body["mongo_configured"] is False
    assert body["introspection_url"].endswith("/auth/me")

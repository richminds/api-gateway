"""Per-user, per-account and per-IP request budgets.

Both dimensions are tested independently because they exist to stop different
failure modes — one runaway client, versus one tenant crowding out the
platform — and a limiter that enforced only one of them would pass a test that
checked only the other.
"""
from __future__ import annotations

import pytest

from features.rate_limiter import RateLimitExceeded, RateLimiter

from .conftest import VALID_TOKEN, auth_headers, register_token


# ---------------------------------------------------------------------------
# The limiter itself
# ---------------------------------------------------------------------------

def test_requests_are_allowed_up_to_the_limit():
    limiter = RateLimiter(user_rpm=3, account_rpm=0, anonymous_rpm=0)
    for _ in range(3):
        limiter.check(user_id="u1")
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.check(user_id="u1")
    assert exc.value.scope == "user"
    assert exc.value.limit == 3


def test_users_have_separate_budgets():
    limiter = RateLimiter(user_rpm=2, account_rpm=0, anonymous_rpm=0)
    limiter.check(user_id="u1")
    limiter.check(user_id="u1")
    limiter.check(user_id="u2")  # unaffected by u1 exhausting theirs


def test_the_account_budget_is_enforced_independently():
    """A user well under their own ceiling is still stopped by their
    account's."""
    limiter = RateLimiter(user_rpm=100, account_rpm=2, anonymous_rpm=0)
    limiter.check(user_id="u1", account_id="acme")
    limiter.check(user_id="u2", account_id="acme")
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.check(user_id="u3", account_id="acme")
    assert exc.value.scope == "account"


def test_accounts_have_separate_budgets():
    limiter = RateLimiter(user_rpm=0, account_rpm=1, anonymous_rpm=0)
    limiter.check(account_id="acme")
    limiter.check(account_id="globex")


def test_a_zero_limit_disables_that_dimension():
    limiter = RateLimiter(user_rpm=0, account_rpm=0, anonymous_rpm=0)
    for _ in range(500):
        limiter.check(user_id="u1", account_id="acme")


def test_a_user_id_and_an_account_id_that_match_do_not_share_a_window():
    """Windows are keyed by (scope, key) — the same string in two dimensions is
    two budgets, not one."""
    limiter = RateLimiter(user_rpm=2, account_rpm=2, anonymous_rpm=0)
    limiter.check(user_id="same", account_id="same")
    limiter.check(user_id="same", account_id="same")
    with pytest.raises(RateLimitExceeded):
        limiter.check(user_id="same", account_id="same")


def test_overrides_raise_a_specific_principal_ceiling():
    limiter = RateLimiter(
        user_rpm=1, account_rpm=0, anonymous_rpm=0, overrides={"vip": 5}
    )
    for _ in range(5):
        limiter.check(user_id="vip")
    with pytest.raises(RateLimitExceeded):
        limiter.check(user_id="vip")
    # An ordinary user still gets the default ceiling of 1.
    limiter.check(user_id="ordinary")
    with pytest.raises(RateLimitExceeded):
        limiter.check(user_id="ordinary")


def test_ip_is_only_used_when_there_is_no_user():
    """Otherwise an office behind one NAT address would be limited as if it
    were a single user."""
    limiter = RateLimiter(user_rpm=100, account_rpm=0, anonymous_rpm=1)
    limiter.check(user_id="u1", ip="10.0.0.1")
    limiter.check(user_id="u2", ip="10.0.0.1")  # same IP, no anonymous budget used


def test_anonymous_traffic_is_limited_by_ip():
    limiter = RateLimiter(user_rpm=0, account_rpm=0, anonymous_rpm=2)
    limiter.check(ip="10.0.0.1")
    limiter.check(ip="10.0.0.1")
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.check(ip="10.0.0.1")
    assert exc.value.scope == "ip"


def test_retry_after_is_positive_and_within_the_window():
    limiter = RateLimiter(user_rpm=1, account_rpm=0, anonymous_rpm=0)
    limiter.check(user_id="u1")
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.check(user_id="u1")
    assert 0 < exc.value.retry_after_seconds <= 60


def test_usage_snapshot_reports_the_window():
    limiter = RateLimiter(user_rpm=10, account_rpm=0, anonymous_rpm=0)
    limiter.check(user_id="u1")
    limiter.check(user_id="u1")
    usage = limiter.get_usage("user", "u1")
    assert usage.requests_this_minute == 2
    assert usage.limit == 10
    assert usage.remaining == 8


# ---------------------------------------------------------------------------
# Enforcement through the gateway
# ---------------------------------------------------------------------------

def test_over_budget_requests_get_429(client, user_token, upstreams):
    client.app.state.rate_limiter._limits["user"] = 3

    for _ in range(3):
        assert client.get("/api/llm/v1/models", headers=auth_headers(user_token)).status_code == 200

    blocked = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limit_exceeded"
    assert blocked.json()["error"]["scope"] == "user"
    # Rejected at the edge — the upstream was protected, which is the point.
    assert len(upstreams.requests) == 3


def test_429_carries_retry_after_and_limit_headers(client, user_token):
    client.app.state.rate_limiter._limits["user"] = 1
    client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    blocked = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.headers["x-ratelimit-limit"] == "1"
    assert blocked.headers["x-ratelimit-remaining"] == "0"
    assert blocked.headers["x-ratelimit-scope"] == "user"


def test_successful_responses_advertise_the_remaining_budget(client, user_token):
    client.app.state.rate_limiter._limits["user"] = 10
    response = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert response.headers["x-ratelimit-limit"] == "10"
    assert response.headers["x-ratelimit-remaining"] == "9"


def test_one_user_being_throttled_does_not_affect_another(client, fake_auth):
    client.app.state.rate_limiter._limits["user"] = 1
    a = register_token(fake_auth, "tok-a", user_id="user-a")
    b = register_token(fake_auth, "tok-b", user_id="user-b")

    client.get("/api/llm/v1/models", headers=auth_headers(a))
    assert client.get("/api/llm/v1/models", headers=auth_headers(a)).status_code == 429
    assert client.get("/api/llm/v1/models", headers=auth_headers(b)).status_code == 200


def test_health_checks_are_never_rate_limited(client):
    """A gateway that 429s its own health check gets restarted in a loop by the
    system that was checking it."""
    client.app.state.rate_limiter._limits["ip"] = 1
    for _ in range(10):
        assert client.get("/health/live").status_code == 200


def test_sign_in_traffic_is_limited_by_ip(client):
    """The only budget available before a user exists — and what makes
    password guessing expensive."""
    client.app.state.rate_limiter._limits["ip"] = 2
    payload = {"email": "user@example.com", "password": "hunter22"}

    assert client.post("/auth/login", json=payload).status_code == 200
    assert client.post("/auth/login", json=payload).status_code == 200
    assert client.post("/auth/login", json=payload).status_code == 429

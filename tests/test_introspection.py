"""Validation delegated to auth-service: caching, failure policy, logout lag.

The caching tests are the ones that matter operationally. Without a cache the
gateway would put a network round trip in front of every request; with one, the
question becomes "how stale may an answer be", which is exactly the revocation
lag these tests pin down.
"""
from __future__ import annotations

import httpx
import pytest

from features.errors import AuthenticationError, UpstreamError
from features.introspection import TokenIntrospector

from .conftest import PROFILES, REVOKED_TOKEN, VALID_TOKEN, FakeAuthService, auth_headers


def introspector(fake: FakeAuthService, **kwargs) -> TokenIntrospector:
    kwargs.setdefault("url", "http://auth.test/auth/me")
    kwargs.setdefault("cache_ttl", 60.0)
    kwargs.setdefault("stale_grace", 300.0)
    return TokenIntrospector(
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)), **kwargs
    )


# ---------------------------------------------------------------------------
# Asking
# ---------------------------------------------------------------------------

async def test_a_valid_token_returns_the_identity(fake_auth):
    identity = await introspector(fake_auth).validate(VALID_TOKEN)
    assert identity.user_id == "user-1"
    assert identity.org_id == "org-1"
    assert identity.account_id == "acme"
    assert identity.is_portless is False


async def test_a_rejected_token_raises_with_auth_services_wording(fake_auth):
    with pytest.raises(AuthenticationError) as exc:
        await introspector(fake_auth).validate(REVOKED_TOKEN)
    assert "revoked" in str(exc.value).lower()


async def test_an_empty_token_is_not_sent_to_auth_service(fake_auth):
    with pytest.raises(AuthenticationError):
        await introspector(fake_auth).validate("")
    assert fake_auth.calls == []


async def test_nulls_become_empty_strings_not_the_word_none(fake_auth):
    """auth-service returns null for a user with no account or org. A bare
    str() would produce "None", which would then be injected downstream as a
    real-looking tenant."""
    fake_auth.profiles["lonely"] = {
        "user_id": "u9",
        "account_id": None,
        "org_id": None,
    }
    identity = await introspector(fake_auth).validate("lonely")
    assert identity.account_id == ""
    assert identity.org_id == ""


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

async def test_a_repeat_validation_is_served_from_cache(fake_auth):
    intro = introspector(fake_auth)
    for _ in range(5):
        await intro.validate(VALID_TOKEN)
    # One call, not five — the whole point of the cache.
    assert fake_auth.calls == [VALID_TOKEN]


async def test_different_tokens_are_cached_separately(fake_auth):
    intro = introspector(fake_auth)
    fake_auth.profiles["second"] = {"user_id": "u2"}
    await intro.validate(VALID_TOKEN)
    await intro.validate("second")
    assert len(fake_auth.calls) == 2


async def test_an_expired_cache_entry_causes_a_fresh_ask(fake_auth):
    intro = introspector(fake_auth, cache_ttl=0)
    await intro.validate(VALID_TOKEN)
    await intro.validate(VALID_TOKEN)
    assert len(fake_auth.calls) == 2


async def test_rejections_are_cached_too(fake_auth):
    """A 401 is monotonic — a token auth-service rejects never becomes valid —
    so caching it is safe, and it stops a client looping on a dead token from
    hammering auth-service."""
    intro = introspector(fake_auth)
    for _ in range(4):
        with pytest.raises(AuthenticationError):
            await intro.validate(REVOKED_TOKEN)
    assert len(fake_auth.calls) == 1


async def test_invalidate_forces_a_fresh_ask(fake_auth):
    intro = introspector(fake_auth)
    await intro.validate(VALID_TOKEN)
    intro.invalidate(VALID_TOKEN)
    await intro.validate(VALID_TOKEN)
    assert len(fake_auth.calls) == 2


async def test_the_cache_is_not_keyed_on_the_raw_token(fake_auth):
    """A long-lived dict keyed on live credentials would expose every active
    session in a heap dump."""
    intro = introspector(fake_auth)
    await intro.validate(VALID_TOKEN)
    assert VALID_TOKEN not in intro._cache


# ---------------------------------------------------------------------------
# Failure policy
# ---------------------------------------------------------------------------

async def test_unreachable_auth_service_raises_upstream_error(fake_auth):
    fake_auth.fail_with = httpx.ConnectError("refused")
    with pytest.raises(UpstreamError):
        await introspector(fake_auth).validate(VALID_TOKEN)


async def test_a_cached_identity_survives_a_brief_outage(fake_auth):
    """A short auth-service blip must not take the platform down with it."""
    intro = introspector(fake_auth, cache_ttl=0, stale_grace=300)
    await intro.validate(VALID_TOKEN)  # populates the cache

    fake_auth.fail_with = httpx.ConnectError("refused")
    identity = await intro.validate(VALID_TOKEN)  # cache is stale, but usable
    assert identity.user_id == "user-1"


async def test_no_grace_means_fail_closed_immediately(fake_auth):
    intro = introspector(fake_auth, cache_ttl=0, stale_grace=0)
    await intro.validate(VALID_TOKEN)

    fake_auth.fail_with = httpx.ConnectError("refused")
    with pytest.raises(UpstreamError):
        await intro.validate(VALID_TOKEN)


async def test_an_uncached_token_fails_closed_during_an_outage(fake_auth):
    """Nothing to fall back on, so the request must not be admitted."""
    intro = introspector(fake_auth, stale_grace=300)
    fake_auth.fail_with = httpx.ConnectError("refused")
    with pytest.raises(UpstreamError):
        await intro.validate("never-seen-before")


async def test_a_500_is_not_cached_as_a_rejection(fake_auth):
    """It is not a verdict on the token, so the next attempt must ask again."""
    intro = introspector(fake_auth)
    fake_auth.status_override = 500
    with pytest.raises(UpstreamError):
        await intro.validate(VALID_TOKEN)

    fake_auth.status_override = None
    identity = await intro.validate(VALID_TOKEN)
    assert identity.user_id == "user-1"


async def test_no_configured_url_is_an_upstream_error(fake_auth):
    intro = introspector(fake_auth, url="")
    with pytest.raises(UpstreamError):
        await intro.validate(VALID_TOKEN)


# ---------------------------------------------------------------------------
# Logout, end to end — the lag the cache implies
# ---------------------------------------------------------------------------

def test_logout_is_routed_and_the_token_then_stops_working(client, user_token, fake_auth, upstreams):
    """With caching off (the suite default), auth-service's verdict applies to
    the very next request — the gateway holds no revocation state of its own."""
    assert client.get("/api/llm/v1/models", headers=auth_headers(user_token)).status_code == 200

    logout = client.post("/auth/logout", headers=auth_headers(user_token))
    assert logout.status_code == 204
    assert "/auth/logout" in upstreams.paths_seen()

    # auth-service revokes it; the gateway simply asks again and is told no.
    fake_auth.revoke(user_token)
    after = client.get("/api/llm/v1/models", headers=auth_headers(user_token))
    assert after.status_code == 401


async def test_a_cached_validation_delays_logout_by_at_most_the_ttl(fake_auth):
    """The trade the cache makes, stated as a test: within the TTL a revoked
    token still works. Shrink GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS to
    shorten this window."""
    intro = introspector(fake_auth, cache_ttl=60)
    await intro.validate(VALID_TOKEN)

    fake_auth.revoke(VALID_TOKEN)

    # Still accepted — served from cache.
    identity = await intro.validate(VALID_TOKEN)
    assert identity.user_id == "user-1"

    # Once the entry is gone, auth-service's verdict applies.
    intro.invalidate(VALID_TOKEN)
    with pytest.raises(AuthenticationError):
        await intro.validate(VALID_TOKEN)


def test_the_gateway_keeps_no_revocation_state_of_its_own():
    """The module that used to exist is gone — auth-service owns revocation."""
    with pytest.raises(ModuleNotFoundError):
        __import__("features.revocation")

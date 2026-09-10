"""The shared identity cache: what it stores, when it expires, and who it saves.

The cross-replica test is the one that justifies the module existing at all —
a second gateway process serving a token the first one validated, without
auth-service being asked twice. Everything else pins the properties that make
that safe: no raw credential on disk, an expiry that outlives the TTL by
exactly the grace window, and a store whose every failure is a cache miss
rather than a failed request.

No MongoDB here either. ``FakeCollection`` implements the handful of Motor
methods the cache actually calls, so the real code paths run against it.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from features.errors import AuthenticationError
from features.identity import CallerIdentity
from features.identity_cache import IdentityCache
from features.introspection import TokenIntrospector

from .conftest import REVOKED_TOKEN, VALID_TOKEN, FakeAuthService


class FakeCollection:
    """The slice of a Motor collection this cache uses, in a dict.

    ``fail_with`` is the assertion surface for the fail-open tests: set it and
    every operation raises, which must show up as a cache miss and never as an
    error reaching the caller.
    """

    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}
        self.indexes: list[tuple[str, dict]] = []
        self.fail_with: Exception | None = None

    def _check(self) -> None:
        if self.fail_with is not None:
            raise self.fail_with

    async def create_index(self, key, **kwargs):
        self._check()
        self.indexes.append((key, kwargs))

    async def find_one(self, query):
        self._check()
        return self.docs.get(query["_id"])

    async def replace_one(self, query, doc, upsert=False):
        self._check()
        self.docs[query["_id"]] = {"_id": query["_id"], **doc}

    async def delete_many(self, query):
        self._check()
        if not query:
            gone = len(self.docs)
            self.docs.clear()
        else:
            field, value = next(iter(query.items()))
            doomed = [k for k, d in self.docs.items() if d.get(field) == value]
            for k in doomed:
                del self.docs[k]
            gone = len(doomed)
        return type("Result", (), {"deleted_count": gone})()

    async def estimated_document_count(self):
        self._check()
        return len(self.docs)


def cache(**kwargs) -> tuple[IdentityCache, FakeCollection]:
    col = FakeCollection()
    kwargs.setdefault("ttl", 60.0)
    kwargs.setdefault("stale_grace", 300.0)
    return IdentityCache(collection=col, **kwargs), col


def identity(user_id="user-1", account_id="acme") -> CallerIdentity:
    profile = {"user_id": user_id, "account_id": account_id, "email": "u@example.com"}
    return CallerIdentity(
        user_id=user_id, account_id=account_id, email="u@example.com", raw=profile
    )


def key_for(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

async def test_a_stored_identity_comes_back(fake_auth):
    c, _ = cache()
    await c.put("k1", identity=identity())
    answer = await c.get("k1")
    assert answer is not None
    assert answer.identity.user_id == "user-1"
    assert answer.identity.account_id == "acme"
    assert answer.age_seconds < 5


async def test_a_stored_rejection_comes_back_as_a_rejection(fake_auth):
    c, _ = cache()
    await c.put("k1", rejection="Token has been revoked", reason_code="token_rejected")
    answer = await c.get("k1")
    assert answer is not None
    assert answer.identity is None
    assert answer.rejection == "Token has been revoked"
    assert answer.reason_code == "token_rejected"


async def test_a_miss_is_none(fake_auth):
    c, _ = cache()
    assert await c.get("never-stored") is None


# ---------------------------------------------------------------------------
# The credential never lands in the database
# ---------------------------------------------------------------------------

async def test_the_raw_token_is_never_written(fake_auth):
    """A collection of bearer tokens is a collection of working sessions. The
    key is a hash and the document holds no copy of the token."""
    intro = TokenIntrospector(
        url="http://auth.test/auth/me",
        cache_ttl=60.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake_auth.handler)),
        shared=(c := cache()[0]),
    )
    await intro.validate(VALID_TOKEN)

    col = c._collection
    assert key_for(VALID_TOKEN) in col.docs
    assert VALID_TOKEN not in repr(col.docs)


async def test_the_user_and_account_are_stored_for_invalidation(fake_auth):
    c, col = cache()
    await c.put("k1", identity=identity(user_id="u7", account_id="globex"))
    doc = col.docs["k1"]
    assert doc["user_id"] == "u7"
    assert doc["account_id"] == "globex"


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------

async def test_expiry_is_the_ttl_plus_the_grace_window(fake_auth):
    """The TTL index must reap at the OUTER horizon. Set to the inner TTL it
    would delete exactly the entries the grace window exists to serve."""
    c, col = cache(ttl=60.0, stale_grace=300.0)
    await c.put("k1", identity=identity())
    doc = col.docs["k1"]
    lifetime = (doc["expires_at"] - doc["fetched_at"]).total_seconds()
    assert lifetime == pytest.approx(360.0)


async def test_an_expired_document_reads_as_a_miss_before_mongo_reaps_it(fake_auth):
    """MongoDB's TTL monitor runs about once a minute, so a document can
    outlive its own expires_at. Existing is not the same as being fresh."""
    c, col = cache(ttl=60.0, stale_grace=300.0)
    await c.put("k1", identity=identity())
    col.docs["k1"]["fetched_at"] = datetime.now(timezone.utc) - timedelta(seconds=400)
    assert await c.get("k1") is None


async def test_an_entry_inside_the_grace_window_is_still_returned(fake_auth):
    """Past the TTL but not past the horizon: the caller decides whether that
    is usable, so the store must still hand it over with its real age."""
    c, col = cache(ttl=60.0, stale_grace=300.0)
    await c.put("k1", identity=identity())
    col.docs["k1"]["fetched_at"] = datetime.now(timezone.utc) - timedelta(seconds=120)
    answer = await c.get("k1")
    assert answer is not None
    assert answer.age_seconds == pytest.approx(120.0, abs=5)


async def test_a_naive_timestamp_from_mongo_is_read_as_utc(fake_auth):
    """Motor hands back naive datetimes even though BSON stores UTC. Doing the
    arithmetic without converting raises TypeError."""
    c, col = cache()
    await c.put("k1", identity=identity())
    col.docs["k1"]["fetched_at"] = datetime.now(timezone.utc).replace(tzinfo=None)
    answer = await c.get("k1")
    assert answer is not None
    assert answer.age_seconds < 5


async def test_nothing_is_written_when_the_horizon_is_zero(fake_auth):
    """A document already past its own expiry is churn with no cache in return."""
    c, col = cache(ttl=0.0, stale_grace=0.0)
    await c.put("k1", identity=identity())
    assert col.docs == {}


async def test_a_clock_skewed_future_document_is_not_negative_age(fake_auth):
    c, col = cache()
    await c.put("k1", identity=identity())
    col.docs["k1"]["fetched_at"] = datetime.now(timezone.utc) + timedelta(seconds=30)
    answer = await c.get("k1")
    assert answer is not None
    assert answer.age_seconds == 0.0


# ---------------------------------------------------------------------------
# Every failure is a miss
# ---------------------------------------------------------------------------

async def test_a_broken_read_is_a_miss_not_an_error(fake_auth):
    c, col = cache()
    await c.put("k1", identity=identity())
    col.fail_with = RuntimeError("mongo is down")
    assert await c.get("k1") is None


async def test_a_broken_write_does_not_raise(fake_auth):
    c, col = cache()
    col.fail_with = RuntimeError("mongo is down")
    await c.put("k1", identity=identity())  # must not raise


async def test_broken_index_creation_does_not_raise(fake_auth):
    c, col = cache()
    col.fail_with = RuntimeError("no permission")
    await c.ensure_indexes()  # must not raise


async def test_a_disabled_cache_is_inert(fake_auth):
    c = IdentityCache(collection=None)
    assert c.enabled is False
    await c.put("k1", identity=identity())
    assert await c.get("k1") is None
    assert await c.invalidate_user("user-1") == 0


async def test_a_profile_with_no_user_id_is_not_served(fake_auth):
    """The same guard the live path applies to auth-service's answers: a
    principal-less identity would be admitted with nothing to rate limit."""
    c, col = cache()
    await c.put("k1", identity=identity())
    col.docs["k1"]["profile"] = {"email": "u@example.com"}
    assert await c.get("k1") is None


# ---------------------------------------------------------------------------
# Invalidation by user and by account
# ---------------------------------------------------------------------------

async def test_invalidate_user_drops_every_session_for_that_user(fake_auth):
    c, col = cache()
    await c.put("a", identity=identity(user_id="u1", account_id="acme"))
    await c.put("b", identity=identity(user_id="u1", account_id="acme"))
    await c.put("c", identity=identity(user_id="u2", account_id="acme"))

    assert await c.invalidate_user("u1") == 2
    assert set(col.docs) == {"c"}


async def test_invalidate_account_drops_every_session_in_that_account(fake_auth):
    c, col = cache()
    await c.put("a", identity=identity(user_id="u1", account_id="acme"))
    await c.put("b", identity=identity(user_id="u2", account_id="globex"))

    assert await c.invalidate_account("acme") == 1
    assert set(col.docs) == {"b"}


async def test_indexes_cover_the_ttl_and_both_lookup_fields(fake_auth):
    c, col = cache()
    await c.ensure_indexes()
    keys = [k for k, _ in col.indexes]
    assert keys == ["expires_at", "user_id", "account_id"]
    ttl_opts = col.indexes[0][1]
    assert ttl_opts["expireAfterSeconds"] == 0


# ---------------------------------------------------------------------------
# What the whole thing is for: two replicas, one question to auth-service
# ---------------------------------------------------------------------------

def replica(fake: FakeAuthService, shared: IdentityCache) -> TokenIntrospector:
    """One gateway process, with its own empty in-memory cache."""
    return TokenIntrospector(
        url="http://auth.test/auth/me",
        cache_ttl=60.0,
        stale_grace=300.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
        shared=shared,
    )


async def test_a_second_replica_does_not_re_ask_auth_service(fake_auth):
    shared, _ = cache()
    first = replica(fake_auth, shared)
    second = replica(fake_auth, shared)

    assert (await first.validate(VALID_TOKEN)).user_id == "user-1"
    assert (await second.validate(VALID_TOKEN)).user_id == "user-1"

    # One call for two processes. Without the shared tier this is two, and with
    # N replicas it is N — the multiplication this module exists to stop.
    assert len(fake_auth.calls) == 1


async def test_a_second_replica_reuses_a_cached_rejection(fake_auth):
    """Negative answers are shared too, so a client looping on a dead token
    cannot hammer auth-service by spreading across replicas."""
    shared, _ = cache()
    first = replica(fake_auth, shared)
    second = replica(fake_auth, shared)

    for intro in (first, second):
        with pytest.raises(AuthenticationError):
            await intro.validate(REVOKED_TOKEN)

    assert len(fake_auth.calls) == 1


async def test_without_the_shared_tier_each_replica_asks(fake_auth):
    """The control for the test above — this is the behaviour being fixed."""
    disabled = IdentityCache(collection=None)
    first = replica(fake_auth, disabled)
    second = replica(fake_auth, disabled)

    await first.validate(VALID_TOKEN)
    await second.validate(VALID_TOKEN)

    assert len(fake_auth.calls) == 2


async def test_forget_user_clears_the_shared_entry_but_not_other_memories(fake_auth):
    """The exact guarantee, and its limit.

    Invalidation removes the shared document, so no replica can pick the answer
    up again. It cannot reach into another process's dict, so a replica that
    already holds the answer keeps serving it until its own TTL runs out. That
    bounds invalidation at GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS rather than
    making it instant — the same lag logout already has.
    """
    shared, col = cache()
    first = replica(fake_auth, shared)
    second = replica(fake_auth, shared)
    await first.validate(VALID_TOKEN)
    await second.validate(VALID_TOKEN)

    assert await first.forget_user("user-1") == 1
    assert col.docs == {}
    assert first.cache_size() == 0

    # `second` was never told, so its own copy still answers.
    await second.validate(VALID_TOKEN)
    assert len(fake_auth.calls) == 1

    # Once that local copy lapses there is nothing left anywhere, so the next
    # validation genuinely goes back to auth-service.
    second.invalidate(VALID_TOKEN)
    await second.validate(VALID_TOKEN)
    assert len(fake_auth.calls) == 2


async def test_forget_drops_one_token_from_both_tiers(fake_auth):
    shared, col = cache()
    intro = replica(fake_auth, shared)
    await intro.validate(VALID_TOKEN)

    assert await intro.forget(VALID_TOKEN) == 1
    assert col.docs == {}
    assert intro.cache_size() == 0


async def test_a_broken_shared_store_still_authenticates(fake_auth):
    """The cache is an optimisation. If it cannot be reached the gateway keeps
    working by asking auth-service, which is what it would have done anyway."""
    shared, col = cache()
    intro = replica(fake_auth, shared)
    col.fail_with = RuntimeError("mongo is down")

    identity_ = await intro.validate(VALID_TOKEN)
    assert identity_.user_id == "user-1"

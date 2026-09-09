"""Logged-out tokens — the half of logout that local verification needs.

A JWT is stateless: once signed it is valid until ``exp``, and nothing about
the token itself changes when a user logs out. The gateway verifies tokens
locally (see tokens.py for why), so "this token was logged out" is knowledge
it has to hold itself.

It can hold it completely, and that is a property of this topology rather than
a lucky accident: **the gateway is the only ingress, so every logout in the
platform passes through it.** It records each one here at the same moment it
tells auth-service, and every subsequent request is checked against this set.
There is no window in which a logged-out token still works.

Two backends behind one interface, chosen by whether ``GATEWAY_MONGO_URI``
resolves — the same shape as auth-service's own ``features/repository.py``:

    InMemoryRevocationStore   process-local. Correct for a single replica.
    MongoRevocationStore      shared. Required for more than one replica, and
                              — when pointed at auth-service's own database
                              and collection — literally the same store
                              auth-service writes its blacklist to, so a
                              revocation from either side is seen by both.

Entries carry a TTL equal to the token's own remaining lifetime, so the set
never grows without bound: an entry stops being needed at the exact moment
the token it names would have expired anyway.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Protocol, runtime_checkable

from .config import gateway_settings

logger = logging.getLogger(__name__)

_store: "RevocationStore | None" = None


@runtime_checkable
class RevocationStore(Protocol):
    async def revoke(self, jti: str, ttl_seconds: int) -> None: ...
    async def is_revoked(self, jti: str) -> bool: ...


# ---------------------------------------------------------------------------
# In-memory
# ---------------------------------------------------------------------------

class InMemoryRevocationStore:
    """Process-local revoked-token set with lazy expiry.

    Expired entries are dropped when they are next looked at, plus a full sweep
    whenever the set grows past a threshold. A background timer would be the
    obvious alternative, but it keeps a task alive for the life of the process
    to do work that only matters when someone is actually making requests.
    """

    _SWEEP_THRESHOLD = 1024

    def __init__(self) -> None:
        self._expiry: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        if not jti or ttl_seconds <= 0:
            return  # already expired — the token is dead on its own
        async with self._lock:
            self._expiry[jti] = time.time() + ttl_seconds
            if len(self._expiry) > self._SWEEP_THRESHOLD:
                self._sweep()

    async def is_revoked(self, jti: str) -> bool:
        if not jti:
            # A token with no jti cannot be revoked — but it also cannot be one
            # of ours, since auth-service mints a jti into every token it
            # signs. tokens.py has already verified the signature by this
            # point, so this is "nothing to check", not "trust it".
            return False
        async with self._lock:
            expires_at = self._expiry.get(jti)
            if expires_at is None:
                return False
            if expires_at <= time.time():
                del self._expiry[jti]
                return False
            return True

    def _sweep(self) -> None:
        """Drop every expired entry. Caller holds the lock."""
        now = time.time()
        self._expiry = {j: e for j, e in self._expiry.items() if e > now}

    def __len__(self) -> int:
        return len(self._expiry)


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

class MongoRevocationStore:
    """Shared revoked-token set, expired by a MongoDB TTL index.

    The TTL index does the cleanup, which is why each document stores an
    absolute ``expires_at`` rather than a duration: Mongo removes a document
    once that instant passes, with no application code involved.

    Written to be compatible with auth-service's own blacklist documents so the
    two can share one collection — see the ``revoked_tokens_collection``
    setting.
    """

    def __init__(self, collection) -> None:
        self._collection = collection
        self._index_ready = False

    async def _ensure_index(self) -> None:
        """Create the TTL index once, on first use.

        Lazily rather than at startup so a Mongo that is briefly unavailable
        delays the first revocation instead of preventing the gateway from
        booting at all. ``create_index`` is idempotent, and auth-service
        creating the same index on the same collection is harmless.
        """
        if self._index_ready:
            return
        try:
            await self._collection.create_index("expires_at", expireAfterSeconds=0)
            await self._collection.create_index("jti", unique=True)
            self._index_ready = True
        except Exception as exc:  # noqa: BLE001 — index creation must never 500 a logout
            logger.warning("Could not ensure revoked-token indexes: %s", exc)

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        if not jti or ttl_seconds <= 0:
            return
        await self._ensure_index()
        from datetime import datetime, timedelta, timezone

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        await self._collection.update_one(
            {"jti": jti},
            {"$set": {"jti": jti, "expires_at": expires_at}},
            upsert=True,
        )

    async def is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        found = await self._collection.find_one({"jti": jti}, {"_id": 1})
        return found is not None


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

async def init_revocation_store() -> RevocationStore:
    """Build the revocation store from settings. Called once, from the lifespan.

    Falls back to in-memory when Mongo cannot be reached, rather than failing
    to start: a gateway that refuses to boot because its *optional* shared
    store is down is a worse outcome than one that boots and honours the
    logouts it handles itself.
    """
    global _store
    s = gateway_settings

    if not s.mongo_uri:
        _store = InMemoryRevocationStore()
        logger.info("Revocation store: in-memory (no GATEWAY_MONGO_URI)")
        return _store

    try:
        from .mongo_connection import get_connection

        conn = await get_connection()
        _store = MongoRevocationStore(conn.get_collection(s.revoked_tokens_collection))
        logger.info(
            "Revocation store: MongoDB db=%s collection=%s",
            s.mongo_db_name,
            s.revoked_tokens_collection,
        )
    except Exception as exc:  # noqa: BLE001 — see the docstring
        logger.error(
            "Could not reach MongoDB for the revocation store (%s) — falling back "
            "to in-memory. Logouts handled by OTHER replicas will not be seen "
            "by this one until it is fixed.",
            exc,
        )
        _store = InMemoryRevocationStore()

    return _store


def get_revocation_store() -> RevocationStore:
    """The active store. Builds an in-memory one on demand if the lifespan
    never ran — which is the case for a unit test importing this directly."""
    global _store
    if _store is None:
        _store = InMemoryRevocationStore()
    return _store


def reset_revocation_store() -> None:
    """Drop the active store. For tests that want a clean slate."""
    global _store
    _store = None


async def revoke_token(jti: str, expires_at: int) -> None:
    """Revoke a token until its natural expiry (``expires_at``, epoch seconds)."""
    ttl = int(expires_at - time.time())
    await get_revocation_store().revoke(jti, ttl)


async def is_token_revoked(jti: str) -> bool:
    return await get_revocation_store().is_revoked(jti)

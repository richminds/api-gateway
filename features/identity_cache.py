"""The shared identity cache — validated tokens, in MongoDB, expired by TTL.

``features/introspection.py`` caches auth-service's answers in a process-local
dict. That is the right first tier and the wrong *only* tier: this gateway runs
as several replicas, and on a serverless host as a fresh process per cold
start, so a per-process cache is warmed independently by every one of them.
With N replicas auth-service sees roughly N times the traffic the TTL was
supposed to buy, and a user's first request to each replica pays a full round
trip. This is the second tier — one document per validated token, shared by
every replica, reaped by MongoDB itself.

**Keyed by a hash, never by the token.** A bearer token is a live credential,
and a collection of them is a collection of working sessions: one leaked backup
and every signed-in user is impersonable. The SHA-256 of the token is as unique
as the token, is what ``_id`` holds, and reveals nothing. The raw token is
never written here.

**What a document holds.** The ``user_id`` and ``account_id`` the token
resolved to — both indexed, so every entry for one user or one whole account
can be dropped in a single call when an administrator moves them — alongside
the profile needed to rebuild the ``CallerIdentity`` without asking again, or
the rejection when auth-service said no.

**Two expiries, and the difference matters.** ``expires_at`` drives the MongoDB
TTL index and is set to the OUTER horizon, ``ttl + stale_grace``, because an
entry past its TTL is precisely what the grace window exists to serve when
auth-service is unreachable. Pointing the TTL index at the inner TTL instead
would delete those entries just before they became useful. The inner TTL is
enforced in code, on read, by age.

MongoDB's TTL monitor also runs only about once a minute, so a document can
outlive its ``expires_at`` by up to that long. Every read therefore checks the
age itself — a document existing is not evidence that it is fresh.

**Invalidation is bounded, not instant.** Dropping an entry here removes it
for every replica that has not already read it, but no process can reach into
another's in-memory tier. A replica already holding the answer keeps serving it
until its own TTL lapses, so an invalidation lands within
``GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS`` rather than immediately — the same
lag logout already has, and the same knob shortens both.

**Every failure here is a cache miss.** A cache that can break authentication
is worse than no cache, so nothing in this module raises: an unreachable
MongoDB, a malformed document, a failed write — each degrades to "go ask
auth-service", which is exactly what would have happened without this tier.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import gateway_settings
from .identity import CallerIdentity, identity_from_profile

logger = logging.getLogger(__name__)

_cache: "IdentityCache | None" = None


@dataclass
class CachedAnswer:
    """One answer read back from the shared store.

    ``age_seconds`` rather than a timestamp: the caller (``TokenIntrospector``)
    reasons in ``time.monotonic()``, which is not comparable across processes,
    while this store necessarily records wall-clock time. Age is the one form
    that means the same thing on both sides of that boundary.
    """

    age_seconds: float
    identity: CallerIdentity | None = None
    rejection: str = ""
    reason_code: str = "invalid_token"


def _as_utc(value: Any) -> datetime | None:
    """A BSON datetime as an aware UTC one.

    Motor hands back naive datetimes by default even though BSON stores UTC.
    Subtracting a naive datetime from an aware one raises, so the conversion
    has to happen before any arithmetic rather than being assumed away.
    """
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class IdentityCache:
    """MongoDB-backed store of validated identities, keyed by token hash."""

    def __init__(
        self,
        collection: Any = None,
        ttl: float | None = None,
        stale_grace: float | None = None,
    ) -> None:
        s = gateway_settings
        self._collection = collection
        self._ttl = s.introspection_cache_ttl_seconds if ttl is None else ttl
        self._stale_grace = (
            s.introspection_stale_grace_seconds if stale_grace is None else stale_grace
        )

    @property
    def enabled(self) -> bool:
        """False when no collection was wired — the gateway then runs on the
        in-process tier alone, which is a supported configuration and not a
        degraded one."""
        return self._collection is not None

    @property
    def horizon_seconds(self) -> float:
        """How long a document stays worth keeping: the TTL plus the grace
        window it may still be served in."""
        return self._ttl + self._stale_grace

    # -------------------------------------------------------------- lifecycle

    async def ensure_indexes(self) -> None:
        """Create the TTL and lookup indexes. Idempotent; never raises.

        ``expireAfterSeconds=0`` means "expire at the instant named by this
        field", which is what lets each document carry its own deadline rather
        than every document sharing one lifetime measured from insertion.
        """
        if not self.enabled:
            return
        try:
            await self._collection.create_index(
                "expires_at", expireAfterSeconds=0, name="identity_cache_ttl"
            )
            # Both indexed so an administrator moving a user between accounts,
            # or disabling a whole account, can invalidate without waiting out
            # the TTL — see invalidate_user / invalidate_account.
            await self._collection.create_index("user_id", name="identity_cache_user")
            await self._collection.create_index(
                "account_id", name="identity_cache_account"
            )
        except Exception as exc:  # noqa: BLE001 — an index is an optimisation
            logger.warning(
                "Could not create identity-cache indexes (%s). The cache still "
                "works; documents will be pruned on read rather than by MongoDB.",
                exc,
            )

    # ------------------------------------------------------------------ reads

    async def get(self, key: str) -> CachedAnswer | None:
        """The stored answer for this token hash, or None on a miss.

        None covers every reason a caller cannot use this entry — absent,
        expired, unreadable, MongoDB down — because they all lead to the same
        place, and distinguishing them here would only invite a caller to treat
        one of them as something other than a miss.
        """
        if not self.enabled:
            return None
        try:
            doc = await self._collection.find_one({"_id": key})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Identity cache read failed (%s) — treating as a miss", exc)
            return None

        if not doc:
            return None

        fetched_at = _as_utc(doc.get("fetched_at"))
        if fetched_at is None:
            return None

        age = (datetime.now(timezone.utc) - fetched_at).total_seconds()
        # Clocks on two replicas are never exactly equal; a document written
        # moments ago by a slightly fast one must read as new, not as invalid.
        age = max(age, 0.0)
        if age >= self.horizon_seconds:
            # Past even the grace window. MongoDB's TTL monitor will get to it;
            # until it does, this read must not resurrect it.
            return None

        rejection = str(doc.get("rejection") or "")
        if rejection:
            return CachedAnswer(
                age_seconds=age,
                rejection=rejection,
                reason_code=str(doc.get("reason_code") or "invalid_token"),
            )

        profile = doc.get("profile")
        if not isinstance(profile, dict):
            return None
        identity = identity_from_profile(profile)
        if identity.is_anonymous:
            # A stored profile with no user_id would admit a request with no
            # principal to rate limit or meter — the same guard the live path
            # applies to auth-service's own answers.
            return None
        return CachedAnswer(age_seconds=age, identity=identity)

    # ----------------------------------------------------------------- writes

    async def put(
        self,
        key: str,
        *,
        identity: CallerIdentity | None = None,
        rejection: str = "",
        reason_code: str = "invalid_token",
    ) -> None:
        """Store one answer. Never raises — a failed write is just a miss later."""
        if not self.enabled or self.horizon_seconds <= 0:
            # A non-positive horizon would write documents already past their
            # own expiry, which is churn with no cache in return.
            return

        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "user_id": identity.user_id if identity else "",
            "account_id": identity.account_id if identity else "",
            "rejection": rejection,
            "reason_code": reason_code,
            "fetched_at": now,
            "expires_at": now + timedelta(seconds=self.horizon_seconds),
        }
        if identity is not None:
            # auth-service's own response body, so identity_from_profile stays
            # the single place that decides what a profile means.
            doc["profile"] = identity.raw or {
                "user_id": identity.user_id,
                "email": identity.email,
                "name": identity.name,
                "account_id": identity.account_id,
                "account_ids": identity.account_ids,
                "is_admin": identity.is_admin,
            }

        try:
            await self._collection.replace_one({"_id": key}, doc, upsert=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Identity cache write failed (%s) — continuing", exc)

    # ----------------------------------------------------------- invalidation

    async def invalidate_token(self, key: str) -> int:
        """Drop one token's entry. Returns how many documents went."""
        return await self._delete({"_id": key}, "token")

    async def invalidate_user(self, user_id: str) -> int:
        """Drop every cached session for one user.

        What logout and "this user was disabled" want: without it the user's
        tokens stay honoured on every replica until the TTL runs out.
        """
        if not user_id:
            return 0
        return await self._delete({"user_id": user_id}, "user")

    async def invalidate_account(self, account_id: str) -> int:
        """Drop every cached session scoped to one account."""
        if not account_id:
            return 0
        return await self._delete({"account_id": account_id}, "account")

    async def clear(self) -> int:
        """Drop everything. Operational escape hatch, not a hot path."""
        return await self._delete({}, "all")

    async def _delete(self, query: dict[str, Any], what: str) -> int:
        if not self.enabled:
            return 0
        try:
            result = await self._collection.delete_many(query)
            return int(getattr(result, "deleted_count", 0) or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Identity cache invalidation by %s failed: %s", what, exc)
            return 0

    # ---------------------------------------------------------- observability

    async def size(self) -> int:
        """Roughly how many entries are stored. -1 when it cannot be read.

        Estimated rather than counted: an exact count scans the collection, and
        this exists for an admin endpoint and a log line, neither of which is
        worth that.
        """
        if not self.enabled:
            return 0
        try:
            return int(await self._collection.estimated_document_count())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Identity cache size unavailable: %s", exc)
            return -1


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

async def init_identity_cache() -> IdentityCache:
    """Build the cache from settings. Called once, from the lifespan.

    Mirrors ``features/usage.py``'s tracker init, including its posture on
    failure: a MongoDB that cannot be reached at startup is logged and then
    ignored, leaving a disabled cache rather than a gateway that will not boot.
    """
    global _cache
    s = gateway_settings

    collection = None
    if s.mongo_uri and s.identity_cache_enabled:
        try:
            from .mongo_connection import get_connection

            conn = await get_connection()
            collection = conn.get_collection(s.identity_cache_collection)
            logger.info(
                "Identity cache: MongoDB db=%s collection=%s (ttl %.0fs, grace %.0fs)",
                s.mongo_db_name,
                s.identity_cache_collection,
                s.introspection_cache_ttl_seconds,
                s.introspection_stale_grace_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Could not reach MongoDB for the identity cache (%s) — running "
                "on the in-process cache only.",
                exc,
            )
            collection = None
    else:
        logger.info("Identity cache: in-process only")

    _cache = IdentityCache(collection=collection)
    await _cache.ensure_indexes()
    return _cache


def get_identity_cache() -> IdentityCache:
    """The active cache, building a disabled one if the lifespan never ran."""
    global _cache
    if _cache is None:
        _cache = IdentityCache()
    return _cache

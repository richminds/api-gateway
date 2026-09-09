"""Request counters — how many requests, by whom, for which account.

Distinct from the rate limiter, which is often confused with it. The limiter
enforces a rolling 60-second window and then *forgets*; this keeps cumulative
totals that answer "how much has this tenant used this month", which is a
billing and capacity question rather than an enforcement one. They read the
same traffic and are otherwise unrelated.

What is counted, per (user, account, service, day):

    requests        how many calls
    errors          how many came back 4xx/5xx
    duration_ms     total latency, so an average is derivable
    status buckets  2xx/4xx/5xx counts

The day dimension is what makes this useful rather than merely large: totals
that only ever accumulate cannot answer "what changed last Tuesday", and a
per-request audit row would grow without bound for a question nobody asks at
that resolution. One document per key per day is the smallest thing that
answers the questions people actually have.

Writes are buffered in memory and flushed on a timer (``GATEWAY_USAGE_FLUSH_SECONDS``)
because a metering write on the hot path would add a database round trip to
every proxied request — the gateway's whole job is to add as little as
possible. The cost is that a hard crash loses at most one flush interval of
counters, which is the right trade for data used to bill and forecast rather
than to enforce.

With no ``GATEWAY_MONGO_URI`` everything stays in the in-memory aggregate:
GET /v1/usage still works, and the numbers reset when the process does.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import gateway_settings

logger = logging.getLogger(__name__)

_tracker: "UsageTracker | None" = None


@dataclass
class UsageCounters:
    """One key's totals. Mutable — this is the accumulator itself."""

    requests: int = 0
    errors: int = 0
    duration_ms: float = 0.0
    status_2xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0

    def record(self, status_code: int, duration_ms: float) -> None:
        self.requests += 1
        self.duration_ms += duration_ms
        if status_code >= 500:
            self.status_5xx += 1
            self.errors += 1
        elif status_code >= 400:
            self.status_4xx += 1
            self.errors += 1
        else:
            self.status_2xx += 1

    def merge(self, other: "UsageCounters") -> None:
        self.requests += other.requests
        self.errors += other.errors
        self.duration_ms += other.duration_ms
        self.status_2xx += other.status_2xx
        self.status_4xx += other.status_4xx
        self.status_5xx += other.status_5xx

    @property
    def avg_duration_ms(self) -> float:
        return round(self.duration_ms / self.requests, 1) if self.requests else 0.0

    def as_dict(self) -> dict:
        return {
            "requests": self.requests,
            "errors": self.errors,
            "avg_duration_ms": self.avg_duration_ms,
            "status_2xx": self.status_2xx,
            "status_4xx": self.status_4xx,
            "status_5xx": self.status_5xx,
        }


@dataclass(frozen=True)
class UsageKey:
    """What a set of counters is counted against.

    ``user_id`` and ``account_id`` are "" for unauthenticated traffic — which
    is a real, queryable category ("how much sign-in traffic did we take"),
    not a gap to be filled in with a guess.
    """

    user_id: str = ""
    account_id: str = ""
    service: str = ""
    day: str = ""

    def as_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "account_id": self.account_id,
            "service": self.service,
            "day": self.day,
        }


@dataclass
class UsageRecord:
    """A key plus its counters — the shape returned by the reporting API."""

    key: UsageKey
    counters: UsageCounters = field(default_factory=UsageCounters)

    def as_dict(self) -> dict:
        return {**self.key.as_dict(), **self.counters.as_dict()}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class UsageTracker:
    """Buffers per-key counters and flushes them to storage periodically.

    Two levels are kept deliberately:

    ``_totals``   every key this process has ever seen, never cleared. Serves
                  GET /v1/usage instantly with no database round trip, and is
                  the whole story when there is no Mongo.
    ``_pending``  what has changed since the last flush, cleared on each one.
                  Flushed as ``$inc`` updates so several replicas accumulate
                  into the same documents without overwriting each other.
    """

    def __init__(self, collection=None, flush_seconds: float | None = None) -> None:
        self._collection = collection
        self._flush_seconds = flush_seconds or gateway_settings.usage_flush_seconds
        self._totals: dict[UsageKey, UsageCounters] = defaultdict(UsageCounters)
        self._pending: dict[UsageKey, UsageCounters] = defaultdict(UsageCounters)
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    # ------------------------------------------------------------ recording

    def record(
        self,
        user_id: str,
        account_id: str,
        service: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """Count one request.

        Deliberately synchronous and lock-free. It is called from the response
        path of every single request, so it must not await, must not do I/O,
        and must never be the reason a request fails — the actual write happens
        on the flush task. Python dict mutation is atomic under the GIL and the
        flush swaps the buffer out rather than mutating it in place, so no lock
        is needed to keep this consistent.
        """
        key = UsageKey(
            user_id=user_id, account_id=account_id, service=service, day=_today()
        )
        self._totals[key].record(status_code, duration_ms)
        self._pending[key].record(status_code, duration_ms)

    # -------------------------------------------------------------- reading

    def snapshot(
        self, user_id: str = "", account_id: str = "", service: str = ""
    ) -> list[UsageRecord]:
        """Totals seen by this process, optionally filtered.

        Filters are AND-ed, and an empty filter means "don't filter on that
        dimension" — so a caller asking for one account gets every user in it.
        """
        out: list[UsageRecord] = []
        for key, counters in self._totals.items():
            if user_id and key.user_id != user_id:
                continue
            if account_id and key.account_id != account_id:
                continue
            if service and key.service != service:
                continue
            # Copied so a caller iterating the result can't be surprised by
            # counters mutating underneath them as requests continue to arrive.
            copy = UsageCounters()
            copy.merge(counters)
            out.append(UsageRecord(key=key, counters=copy))
        return sorted(out, key=lambda r: r.counters.requests, reverse=True)

    def aggregate(self, dimension: str) -> list[dict]:
        """Roll the per-key totals up to one dimension: "user", "account" or
        "service". This is the shape a dashboard actually wants — nobody asks
        "requests by user by account by service by day" first."""
        attr = {"user": "user_id", "account": "account_id", "service": "service"}.get(
            dimension
        )
        if attr is None:
            raise ValueError(
                f"Unknown usage dimension {dimension!r} — expected user, account or service"
            )

        rolled: dict[str, UsageCounters] = defaultdict(UsageCounters)
        for key, counters in self._totals.items():
            rolled[getattr(key, attr)].merge(counters)

        return sorted(
            [{dimension: name, **c.as_dict()} for name, c in rolled.items()],
            key=lambda row: row["requests"],
            reverse=True,
        )

    # ------------------------------------------------------------- flushing

    async def flush(self) -> int:
        """Write buffered counters to storage. Returns the number of keys written.

        The pending buffer is swapped out under the lock and written outside
        it, so requests arriving mid-flush accumulate into the fresh buffer
        instead of blocking on the database.
        """
        async with self._lock:
            if not self._pending:
                return 0
            batch = self._pending
            self._pending = defaultdict(UsageCounters)

        if self._collection is None:
            return len(batch)  # in-memory only; _totals already has it

        written = 0
        for key, counters in batch.items():
            try:
                await self._collection.update_one(
                    key.as_dict(),
                    {
                        "$inc": {
                            "requests": counters.requests,
                            "errors": counters.errors,
                            "duration_ms": counters.duration_ms,
                            "status_2xx": counters.status_2xx,
                            "status_4xx": counters.status_4xx,
                            "status_5xx": counters.status_5xx,
                        },
                        "$set": {"updated_at": datetime.now(timezone.utc)},
                    },
                    upsert=True,
                )
                written += 1
            except Exception as exc:  # noqa: BLE001
                # Metering must never take the gateway down. The counters for
                # this key are lost; _totals still has them for this process.
                logger.warning("Usage flush failed for %s: %s", key, exc)
        return written

    async def start(self) -> None:
        """Begin the periodic flush loop."""
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._flush_loop())

    async def _flush_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                # Waits on the stop event rather than sleeping, so shutdown is
                # immediate instead of taking up to a full interval.
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._flush_seconds
                )
            except asyncio.TimeoutError:
                pass  # normal path — the interval elapsed
            try:
                await self.flush()
            except Exception as exc:  # noqa: BLE001 — the loop must survive anything
                logger.warning("Usage flush loop error: %s", exc)

    async def stop(self) -> None:
        """Stop the loop and flush what is left.

        The final flush is the point: without it, everything since the last
        interval is lost on every ordinary restart and deploy.
        """
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None
        await self.flush()


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

async def init_usage_tracker() -> UsageTracker:
    """Build and start the tracker. Called once, from the lifespan."""
    global _tracker
    s = gateway_settings

    collection = None
    if s.mongo_uri and s.usage_tracking_enabled:
        try:
            from .mongo_connection import get_connection

            conn = await get_connection()
            collection = conn.get_collection(s.usage_collection)
            logger.info(
                "Usage tracking: MongoDB db=%s collection=%s",
                s.mongo_db_name,
                s.usage_collection,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Could not reach MongoDB for usage tracking (%s) — counting "
                "in-memory only.",
                exc,
            )
    else:
        logger.info("Usage tracking: in-memory")

    _tracker = UsageTracker(collection=collection)
    if s.usage_tracking_enabled:
        await _tracker.start()
    return _tracker


def get_usage_tracker() -> UsageTracker:
    """The active tracker, building an in-memory one on demand if the lifespan
    never ran (a unit test importing this directly)."""
    global _tracker
    if _tracker is None:
        _tracker = UsageTracker()
    return _tracker


async def close_usage_tracker() -> None:
    global _tracker
    if _tracker is not None:
        await _tracker.stop()
        _tracker = None

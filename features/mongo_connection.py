"""MongoDB connection manager for the gateway.

One Motor client for the one thing here that persists anything — the usage
counters (usage.py) — rather than a pool per concern. Same shape as auth-service's
``features/mongo_connection.py``, for the same reason: this service has one
storage dependency, so it should hold one connection to it.

Storage is optional for this service. Everything works with no Mongo at all;
with none configured the counters simply reset on restart and are per-process.

Usage::

    from features.mongo_connection import get_connection

    conn = await get_connection()
    col = conn.get_collection("gateway_usage")
    healthy = await conn.ping()
    # at app shutdown:
    await close_connection()
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

_connection: "MongoConnection | None" = None
_lock = asyncio.Lock()


async def get_connection(uri: str | None = None, db_name: str | None = None) -> "MongoConnection":
    """Return (or create) the shared MongoConnection. Safe to call concurrently."""
    from .config import gateway_settings

    global _connection
    resolved_uri = uri or gateway_settings.mongo_uri
    resolved_db = db_name or gateway_settings.mongo_db_name

    async with _lock:
        if _connection is None:
            _connection = MongoConnection(uri=resolved_uri, db_name=resolved_db)
            await _connection.connect()
            logger.info("MongoDB connection established: db=%s", resolved_db)
        return _connection


async def close_connection() -> None:
    global _connection
    if _connection is not None:
        await _connection.close()
        _connection = None


class MongoConnection:
    """Thin wrapper around a Motor AsyncIOMotorClient."""

    def __init__(self, uri: str, db_name: str) -> None:
        import motor.motor_asyncio

        self._uri = uri
        self._db_name = db_name
        self._client = motor.motor_asyncio.AsyncIOMotorClient(
            uri, serverSelectionTimeoutMS=5_000, connectTimeoutMS=5_000
        )
        self._db = self._client[db_name]

    async def connect(self) -> None:
        """Force the lazy Motor client to actually establish a connection.

        Motor connects on first use, which would otherwise mean the first
        request after startup pays the connection cost and discovers a bad URI.
        Doing it here surfaces a misconfiguration in the startup logs instead.
        """
        await self._client.admin.command("ping")

    async def ping(self) -> bool:
        try:
            await self._client.admin.command("ping")
            return True
        except Exception as exc:  # noqa: BLE001 — readiness reports, never raises
            logger.warning("MongoDB ping failed: %s", exc)
            return False

    def get_collection(self, name: str) -> Any:
        return self._db[name]

    @property
    def db_name(self) -> str:
        return self._db_name

    async def close(self) -> None:
        self._client.close()
        logger.info("MongoDB connection closed")

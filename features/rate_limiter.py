"""Per-user and per-account request budgets.

This is the feature that makes a shared front door safe. Every application on
the platform enters through one deployment, so without per-caller budgets a
single runaway client — a retry loop, a stuck cron, a script someone left
running — consumes the capacity of the services behind it and every other
tenant starts seeing failures from a system they never misused.

**Two dimensions are checked, not one**, and the distinction matters:

    per user      stops one client from hurting the rest of their own
                  organization
    per account   stops one tenant from hurting the rest of the platform

A request must pass both. Checking only the user lets a thousand users of one
account swamp everyone else; checking only the account lets one user inside a
big account burn its whole allowance. They are separate failure modes and each
needs its own ceiling.

Unauthenticated traffic — sign-in and sign-up, the only endpoints that reach
this without a token — is limited per client IP instead. It is the only key
available before a user exists, and it is what makes password guessing
expensive.

**That budget is deliberately small, so it needs a per-path escape hatch.**
Some upstreams are routed as public at the gateway not because their traffic is
unauthenticated, but because they validate their own tokens and the gateway
cannot check them (makemerich-backend today). All of their traffic therefore
lands in the anonymous dimension, where a budget sized to make password
guessing expensive — 30/min — throttles an ordinary application within a page
or two. Raising it globally is the wrong fix: auth-service has no lockout of
its own, so this budget is the only barrier in front of POST /auth/login.
``GATEWAY_ANONYMOUS_RPM_OVERRIDES`` therefore sets the anonymous ceiling per
PATH, letting one subtree be generous while sign-in stays tight.

Algorithm: sliding window over the last 60 seconds, per key. Scope is one
process: with several replicas each enforces its own window, so divide the
intended global budget by the replica count. A cross-replica limiter would put
a shared-store round trip in front of every request, which is a poor trade for
a component whose entire job is to add as little latency as possible — the
same call llm-gateway's own limiter makes, for the same reason.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60.0

# The three budgets a key can be counted against. "user" and "account" are
# checked together on an authenticated request; "ip" is used on its own for
# unauthenticated sign-in/sign-up traffic.
SCOPE_USER = "user"
SCOPE_ACCOUNT = "account"
SCOPE_IP = "ip"


class RateLimitExceeded(Exception):
    """Raised when a caller is over one of their budgets.

    ``scope`` says *which* budget was hit, and it reaches the client in the
    error body: "you personally are going too fast" and "your organization is
    going too fast" call for completely different reactions, and a caller who
    cannot tell them apart will retry a limit that no amount of backing off on
    their side will clear.
    """

    def __init__(
        self,
        key: str,
        scope: str,
        limit: int,
        current: int,
        retry_after_seconds: float,
    ) -> None:
        self.key = key
        self.scope = scope
        self.limit = limit
        self.current = current
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Rate limit exceeded for {scope}='{key}': {current}/{limit} requests "
            f"in the last {int(WINDOW_SECONDS)}s. Retry in {retry_after_seconds:.0f}s."
        )


@dataclass
class RateLimitUsage:
    """Snapshot of one key's current window, for dashboards and headers."""

    key: str
    scope: str
    requests_this_minute: int = 0
    limit: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.requests_this_minute)


@dataclass
class _Window:
    """Request timestamps for one key, pruned to the last WINDOW_SECONDS."""

    requests: Deque[float] = field(default_factory=deque)

    def prune(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while self.requests and self.requests[0] <= cutoff:
            self.requests.popleft()


@dataclass(frozen=True)
class AnonymousBudget:
    """One ``GATEWAY_ANONYMOUS_RPM_OVERRIDES`` entry: a path and its ceiling."""

    path: str
    rpm: int
    prefix: bool = False
    """True when the entry ended in "*"."""

    def matches(self, path: str) -> bool:
        if self.prefix:
            # "/x/*" covers "/x/anything" and "/x" itself, but not "/xy" —
            # the same boundary rule the route table and access policy use.
            return path == self.path or path.startswith(self.path + "/")
        return path == self.path


class AnonymousBudgets:
    """The parsed per-path anonymous ceilings. Immutable once built."""

    def __init__(self, rules: list[AnonymousBudget]) -> None:
        # Longest path first, so a specific rule can be layered over a general
        # one without the order of the env var mattering.
        self._rules = sorted(rules, key=lambda r: len(r.path), reverse=True)

    def __len__(self) -> int:
        return len(self._rules)

    def rpm_for(self, path: str) -> int | None:
        """The ceiling for this path, or None to use the global default."""
        normalised = path.rstrip("/") or "/"
        for rule in self._rules:
            if rule.matches(normalised):
                return rule.rpm
        return None

    def describe(self) -> list[str]:
        return [f"{r.path}{'/*' if r.prefix else ''}={r.rpm}" for r in self._rules]


def parse_anonymous_rpm_overrides(raw: str) -> list[AnonymousBudget]:
    """Parse ``GATEWAY_ANONYMOUS_RPM_OVERRIDES`` — ``path=rpm``, comma-separated.

    Malformed entries are logged and skipped rather than raising, matching
    GATEWAY_RATE_LIMIT_OVERRIDES: a typo in one budget should not stop the
    gateway booting. That is the opposite of the route table and the public-path
    list, where a dropped entry silently breaks routing or auth and a hard
    failure at startup is the kinder outcome. Here the fallback is the global
    anonymous budget, which is safe — merely stricter.
    """
    rules: list[AnonymousBudget] = []

    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue

        path, sep, value = entry.rpartition("=")
        if not sep:
            logger.warning(
                "Ignoring malformed GATEWAY_ANONYMOUS_RPM_OVERRIDES entry %r — "
                "expected 'path=rpm'",
                entry,
            )
            continue

        path = path.strip()
        prefix = path.endswith("*")
        if prefix:
            path = path[:-1].rstrip("/")

        if not path.startswith("/"):
            logger.warning(
                "Ignoring GATEWAY_ANONYMOUS_RPM_OVERRIDES entry %r — a path must "
                "start with '/' (e.g. '/api/makemerich/*=600')",
                entry,
            )
            continue

        try:
            rpm = int(value.strip())
        except ValueError:
            logger.warning("Ignoring non-numeric anonymous-rpm override %r", entry)
            continue

        rules.append(AnonymousBudget(path=path, rpm=rpm, prefix=prefix))

    return rules


class RateLimiter:
    """Sliding-window limiter over the user / account / IP dimensions.

    Thread-safe: FastAPI serves many event-loop tasks concurrently and runs
    sync work in a threadpool, so the window store is lock-guarded.
    """

    def __init__(
        self,
        user_rpm: int | None = None,
        account_rpm: int | None = None,
        anonymous_rpm: int | None = None,
        overrides: dict[str, int] | None = None,
    ) -> None:
        from .config import gateway_settings as s

        self._limits = {
            SCOPE_USER: s.user_rpm if user_rpm is None else user_rpm,
            SCOPE_ACCOUNT: s.account_rpm if account_rpm is None else account_rpm,
            SCOPE_IP: s.anonymous_rpm if anonymous_rpm is None else anonymous_rpm,
        }
        self._overrides = (
            s.parsed_rate_limit_overrides() if overrides is None else overrides
        )
        # Keyed by (scope, key) so a user_id and an account_id that happen to
        # be the same string never share a window.
        self._windows: dict[tuple[str, str], _Window] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------- limits

    def limit_for(self, scope: str, key: str) -> int:
        """The RPM ceiling for one key. Per-principal overrides win."""
        if key in self._overrides:
            return self._overrides[key]
        return self._limits.get(scope, 0)

    # -------------------------------------------------------------- checks

    def check(
        self,
        user_id: str = "",
        account_id: str = "",
        ip: str = "",
        anonymous_rpm: int | None = None,
    ) -> None:
        """Raise RateLimitExceeded if any supplied dimension is over budget.

        ``anonymous_rpm`` overrides the IP ceiling for THIS request only — the
        per-path budget resolved by the middleware. A per-principal override
        naming this exact IP still wins over it, since that one was configured
        against the caller rather than the path.

        Empty dimensions are skipped rather than collapsed into a shared
        bucket: lumping every accountless user under one "" key would let any
        one of them exhaust the budget for all of them.

        This is not a read-only probe — a passing check *reserves* a slot in
        every dimension it checked. Note the consequence: a request rejected on
        the account budget has already been counted against the user budget,
        since the dimensions are recorded as they pass. That slightly
        over-counts a user whose account is saturated, which is the right way
        round — the alternative is checking everything before recording
        anything, and then two concurrent requests can both pass a check that
        only one of them should have.
        """
        dimensions: list[tuple[str, str]] = []
        if user_id:
            dimensions.append((SCOPE_USER, user_id))
        if account_id:
            dimensions.append((SCOPE_ACCOUNT, account_id))
        if ip and not user_id:
            # IP is the fallback identity, not an extra ceiling on top of a
            # real one: an office behind one NAT address would otherwise be
            # limited as if it were a single user.
            dimensions.append((SCOPE_IP, ip))

        now = time.monotonic()
        with self._lock:
            for scope, key in dimensions:
                limit = self.limit_for(scope, key)
                if (
                    scope == SCOPE_IP
                    and anonymous_rpm is not None
                    and key not in self._overrides
                ):
                    limit = anonymous_rpm
                if limit <= 0:
                    continue  # this dimension is disabled

                window = self._windows.setdefault((scope, key), _Window())
                window.prune(now)

                if len(window.requests) >= limit:
                    # The oldest request in the window is the one whose expiry
                    # frees a slot, so that is the honest retry time — not a
                    # fixed guess the client would either over- or under-wait.
                    retry_after = max(0.0, window.requests[0] + WINDOW_SECONDS - now)
                    raise RateLimitExceeded(
                        key, scope, limit, len(window.requests), retry_after
                    )

                window.requests.append(now)

    # --------------------------------------------------------- observability

    def get_usage(self, scope: str, key: str) -> RateLimitUsage:
        limit = self.limit_for(scope, key)
        now = time.monotonic()
        with self._lock:
            window = self._windows.get((scope, key))
            if window is None:
                return RateLimitUsage(key=key, scope=scope, limit=limit)
            window.prune(now)
            return RateLimitUsage(
                key=key,
                scope=scope,
                requests_this_minute=len(window.requests),
                limit=limit,
            )

    def get_all_usage(self) -> list[RateLimitUsage]:
        with self._lock:
            keys = list(self._windows)
        return [self.get_usage(scope, key) for scope, key in keys]

    def reset(self, scope: str = "", key: str = "") -> None:
        """Clear counters. With no arguments, clears everything."""
        with self._lock:
            if not scope and not key:
                self._windows.clear()
            else:
                self._windows.pop((scope, key), None)

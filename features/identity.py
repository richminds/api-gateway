"""Who is calling — the gateway's view of an authenticated caller.

The gateway does not decode, verify or otherwise understand tokens. A token is
an **opaque string** it forwards to auth-service, which answers with the user
it belongs to (see ``features/introspection.py``). Everything below describes
that answer.

That is the whole point of the split: auth-service owns identity — the signing
key, the algorithm, expiry, and the revocation list — and it is the only place
that has to be right about them. The gateway asks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CallerIdentity:
    """Who is making this request, as auth-service reported them.

    Every field comes from auth-service's answer, never from something the
    caller sent in a header — that distinction is the security model of this
    gateway. See ``features/proxy.py`` for how caller-supplied copies of these
    headers are stripped before the verified values are injected.
    """

    user_id: str
    """auth-service's ``user_id``. Stable, and the key for per-user rate
    limiting and usage metering."""

    email: str = ""
    name: str = ""

    account_id: str = ""
    """The application (app account) this session is scoped to. The key for
    per-account rate limiting and usage. Empty when the user belongs to no app
    account, which is normal."""

    org_id: str = ""
    """The tenant the user belongs to. Downstream services filter their data on
    this, so it must come from auth-service and nowhere else."""

    is_portless: bool = False
    """Platform staff. knowledge-service reads this to bypass per-org
    filtering, and the gateway's own /v1 admin routes gate on it."""

    is_admin: bool = False
    """Member of the configured admin app account, per auth-service."""

    raw: dict[str, Any] = field(default_factory=dict, repr=False)
    """auth-service's full response, for anything not promoted to a field
    above. Kept out of ``repr`` so an identity can be logged without dumping
    the user's whole profile into the log."""

    @property
    def is_anonymous(self) -> bool:
        return not self.user_id

    def rate_limit_keys(self) -> tuple[str, str]:
        """``(user_key, account_key)`` for the two rate-limit dimensions.

        The account key is empty when the session names no account, and
        ``rate_limiter.check`` skips an empty dimension — a user with no app
        account is limited as a user only, rather than being lumped together
        with every other accountless user into one shared bucket (which would
        let any one of them exhaust the budget for all of them).
        """
        return self.user_id, self.account_id


ANONYMOUS = CallerIdentity(user_id="")
"""The identity for a request that carries no token — health probes and the
configured public paths. A sentinel rather than None so call sites can read
``identity.account_id`` unconditionally."""


def identity_from_profile(profile: dict[str, Any]) -> CallerIdentity:
    """Build a CallerIdentity from auth-service's ``GET /auth/me`` body.

    Tolerant of fields it does not know about, and of nulls: auth-service
    returns ``account_id``/``org_id`` as ``null`` for a user who has neither,
    and JSON null must become "" rather than the string "None" — which is what
    a bare ``str()`` would produce, and which would then be injected downstream
    as a real-looking tenant.
    """
    return CallerIdentity(
        user_id=str(profile.get("user_id") or ""),
        email=str(profile.get("email") or ""),
        name=str(profile.get("name") or ""),
        account_id=str(profile.get("account_id") or ""),
        org_id=str(profile.get("org_id") or ""),
        is_portless=bool(profile.get("is_portless", False)),
        is_admin=bool(profile.get("is_admin", False)),
        raw=profile,
    )


def extract_bearer(authorization_header: str) -> str:
    """Pull the token out of an Authorization header, or return "".

    Case-insensitive on the scheme because "Bearer", "bearer" and "BEARER" all
    appear in real clients and RFC 7235 makes the scheme case-insensitive.
    This is the only thing the gateway does to a token before handing it
    straight to auth-service.
    """
    header = (authorization_header or "").strip()
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return token.strip()

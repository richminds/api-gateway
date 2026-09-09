"""JWT verification and the caller identity it produces.

auth-service signs; the gateway verifies. Verification is done **locally**
(HS256 against the shared secret) rather than by asking auth-service about
every request, because a network round trip in front of every single call
would make auth-service a hard dependency of every request the platform
serves — one slow auth-service would take the whole platform down, and the
gateway would add a hop's latency to traffic that has nothing to do with
identity. Local verification is a signature check on bytes we already have.

The cost of local verification is that a stateless JWT stays valid until it
expires, so "log out" has to be modelled explicitly. That is what
``features/revocation.py`` is for, and it works here specifically *because*
this gateway is the only ingress: every logout the platform will ever see
comes through it, so its revoked-token set is complete by construction.

What comes out of a valid token is a ``CallerIdentity`` — the gateway's view
of who is calling. Its fields mirror the claims auth-service mints (see that
service's ``features/security.py::create_access_token`` and
``features/service.py``), and they are what gets injected as trusted headers
for the upstream service (``features/proxy.py``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import jwt  # PyJWT

from .config import gateway_settings
from .errors import AuthenticationError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CallerIdentity:
    """Who is making this request, as established by their token.

    Every field is a *claim auth-service asserted*, never something the caller
    sent in a header — that distinction is the whole security model of this
    gateway. See ``features/proxy.py`` for how caller-supplied copies of these
    headers are stripped before the identity below is injected.
    """

    user_id: str
    """The ``sub`` claim. Stable, and the key for per-user rate limiting and
    usage metering."""

    email: str = ""
    name: str = ""

    account_id: str = ""
    """The application (app account) this token is scoped to. The key for
    per-account rate limiting and usage. Empty when the token names none,
    which is normal for a user who belongs to no app account yet."""

    org_id: str = ""
    """The tenant the user belongs to. Downstream services filter their data
    on this, so it must come from the token and nowhere else."""

    is_portless: bool = False
    """Platform staff. knowledge-service reads this to bypass per-org
    filtering, so — like org_id — it is only ever taken from a verified
    token."""

    jti: str = ""
    """The token's unique ID. What logout revokes (see revocation.py); there
    is nothing else to key a revocation entry on, since the token itself is
    stateless."""

    expires_at: int = 0
    """``exp``, epoch seconds. Used to set the revocation entry's TTL so it
    expires exactly when the token would have stopped working anyway."""

    claims: dict[str, Any] = field(default_factory=dict, repr=False)
    """The full decoded payload, for anything not promoted to a field above.
    Kept out of ``repr`` so an identity can be logged without dumping a token's
    entire contents into the log."""

    @property
    def is_anonymous(self) -> bool:
        return not self.user_id

    def rate_limit_keys(self) -> tuple[str, str]:
        """``(user_key, account_key)`` for the two rate-limit dimensions.

        The account key is empty when the token names no account, and
        ``rate_limiter.check`` skips an empty dimension — a user with no app
        account is limited as a user only, rather than being lumped together
        with every other accountless user into one shared bucket (which would
        let any one of them exhaust the budget for all of them).
        """
        return self.user_id, self.account_id


ANONYMOUS = CallerIdentity(user_id="")
"""The identity for a request that carries no token — health probes, sign-in
and sign-up. A sentinel rather than None so call sites can read
``identity.account_id`` unconditionally."""


def identity_from_claims(claims: dict[str, Any]) -> CallerIdentity:
    """Build a CallerIdentity from a *verified* payload.

    Split out from ``verify_token`` so the mapping can be unit tested, and so
    a caller that has already verified a token (the login path, which just
    minted it via auth-service) can reuse it without a second decode.
    """
    return CallerIdentity(
        user_id=str(claims.get("sub") or ""),
        email=str(claims.get("email") or ""),
        name=str(claims.get("name") or ""),
        account_id=str(claims.get("account_id") or ""),
        org_id=str(claims.get("org_id") or ""),
        is_portless=bool(claims.get("is_portless", False)),
        jti=str(claims.get("jti") or ""),
        expires_at=int(claims.get("exp") or 0),
        claims=claims,
    )


class TokenVerifier:
    """Verifies tokens minted by auth-service.

    Reads settings on each call rather than binding them at construction: a
    deployment that enables auth, or rotates the secret, after the app object
    exists would otherwise keep using the values frozen at import time and
    401 every request with no obvious cause. This mirrors the same decision in
    llm-gateway's ``app/middleware/auth.py``.
    """

    def verify(self, token: str) -> CallerIdentity:
        """Decode and validate a bearer token, or raise AuthenticationError.

        Checks signature, expiry, issuer and audience. Revocation is
        deliberately NOT checked here — it needs I/O, and keeping this method
        pure makes it usable anywhere. ``revocation.py`` is the second half,
        called by the auth middleware right after this.
        """
        if not token:
            raise AuthenticationError("No bearer token supplied", reason="missing_token")

        s = gateway_settings
        try:
            claims = jwt.decode(
                token,
                s.jwt_secret,
                algorithms=[s.jwt_algorithm],
                issuer=s.jwt_issuer,
                audience=s.jwt_audience if s.verify_audience else None,
                options={"verify_aud": s.verify_audience},
            )
        except jwt.ExpiredSignatureError as exc:
            # Its own reason code: a client that sees "expired" should log in
            # again (there are no refresh tokens), whereas "invalid" usually
            # means a configuration mismatch worth surfacing differently.
            raise AuthenticationError(
                "Token has expired — please log in again", reason="token_expired"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError(
                "Token was not issued for this platform", reason="invalid_audience"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthenticationError(
                "Token was not issued by the configured auth service",
                reason="invalid_issuer",
            ) from exc
        except jwt.PyJWTError as exc:
            # Deliberately vague to the caller (an attacker probing signatures
            # learns nothing) but logged in full for an operator: a sudden wave
            # of these almost always means GATEWAY_JWT_SECRET has drifted from
            # AUTH_JWT_SECRET, not an attack.
            logger.warning("Rejected a token: %s", exc)
            raise AuthenticationError("Invalid token", reason="invalid_token") from exc

        if not claims.get("sub"):
            # Signed by us, but unusable: every downstream decision keys on the
            # user, so an anonymous-but-valid token is a bug upstream, not a
            # caller to be trusted.
            raise AuthenticationError(
                "Token carries no subject claim", reason="invalid_token"
            )

        return identity_from_claims(claims)


def extract_bearer(authorization_header: str) -> str:
    """Pull the token out of an Authorization header, or return "".

    Case-insensitive on the scheme because "Bearer", "bearer" and "BEARER" all
    appear in real clients and RFC 7235 makes the scheme case-insensitive.
    """
    header = (authorization_header or "").strip()
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return token.strip()

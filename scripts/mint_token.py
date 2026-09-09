"""Mint a gateway-valid JWT without running auth-service.

For local development and for testing the gateway in isolation: it produces a
token with exactly the claims auth-service would mint, signed with the same
secret the gateway verifies against.

    python scripts/mint_token.py --user-id dev-1 --account-id acme
    python scripts/mint_token.py --portless          # a platform-staff token
    python scripts/mint_token.py --expires-in -1     # an already-expired one

    TOKEN=$(python scripts/mint_token.py)
    curl -H "Authorization: Bearer $TOKEN" localhost:8000/auth/whoami

This is a development tool, and it only works where the gateway's secret is
also yours to hold. That is the point: if you can mint a token for any user,
so can anyone else with that secret — which is exactly why
``GATEWAY_JWT_SECRET`` must be set to a real value before a deployment is
exposed, and why the gateway logs an error at startup when it has not been.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import jwt  # noqa: E402

from features.config import gateway_settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--user-id", default="dev-user", help="the 'sub' claim")
    parser.add_argument("--email", default="dev@example.com")
    parser.add_argument("--name", default="Dev User")
    parser.add_argument("--account-id", default="dev-account", help="the app account")
    parser.add_argument("--org-id", default="dev-org", help="the tenant")
    parser.add_argument(
        "--portless",
        action="store_true",
        help="platform staff — unlocks the gateway's /v1 admin endpoints",
    )
    parser.add_argument("--jti", default="", help="token ID (defaults to a random one)")
    parser.add_argument(
        "--expires-in",
        type=int,
        default=60,
        metavar="MINUTES",
        help="lifetime in minutes; negative mints an already-expired token",
    )
    args = parser.parse_args()

    s = gateway_settings
    if s.jwt_secret_is_default:
        # stderr, so the token on stdout stays pipeable into $(...).
        print(
            "warning: signing with the built-in development secret — this token "
            "is only valid against a gateway that is also unconfigured.",
            file=sys.stderr,
        )

    import secrets

    now = datetime.now(timezone.utc)
    payload = {
        "sub": args.user_id,
        "email": args.email,
        "name": args.name,
        "account_id": args.account_id,
        "org_id": args.org_id,
        "is_portless": args.portless,
        "iss": s.jwt_issuer,
        # A list, matching what auth-service mints: PyJWT accepts the token when
        # the verifier's configured audience appears anywhere in it.
        "aud": [s.jwt_audience],
        "jti": args.jti or secrets.token_hex(16),
        "iat": now,
        "exp": now + timedelta(minutes=args.expires_in),
    }

    print(jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

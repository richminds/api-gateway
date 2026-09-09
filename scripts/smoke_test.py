"""End-to-end smoke test against a running gateway.

    python run.py &
    python scripts/smoke_test.py

Checks the things a deployment can get wrong that unit tests cannot see: that
the process actually serves, that the JWT gate is on, that an unauthenticated
call to a routed path is refused, and that a valid token gets through. Exits
non-zero on the first failure so it can gate a deploy.

It mints its own token (see mint_token.py), so it needs the gateway's signing
secret but no running auth-service. Point ``--base-url`` at a real deployment
and it will exercise that instead.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402
import jwt  # noqa: E402

from features.config import gateway_settings  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
_failures = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _failures
    if not condition:
        _failures += 1
    print(f"[{PASS if condition else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def mint(is_portless: bool = False) -> str:
    import secrets

    s = gateway_settings
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": "smoke-test-user",
            "email": "smoke@example.com",
            "name": "Smoke Test",
            "account_id": "smoke-account",
            "org_id": "smoke-org",
            "is_portless": is_portless,
            "iss": s.jwt_issuer,
            "aud": [s.jwt_audience],
            "jti": secrets.token_hex(16),
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        s.jwt_secret,
        algorithm=s.jwt_algorithm,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument(
        "--secured-path",
        default="/api/llm/v1/models",
        help="a routed path that should require a token",
    )
    parser.add_argument(
        "--public-path",
        default="/auth/login",
        help="a routed path configured as public (GATEWAY_PUBLIC_PATHS)",
    )
    parser.add_argument(
        "--logout-path",
        default="/auth/logout",
        help="the routed path that ends a session (GATEWAY_LOGOUT_PATHS)",
    )
    args = parser.parse_args()

    client = httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0)

    # ── the service is up ───────────────────────────────────────────────────
    try:
        live = client.get("/health/live")
    except httpx.HTTPError as exc:
        print(f"[{FAIL}] gateway is not reachable at {args.base_url} — {exc}")
        return 1
    check("liveness responds", live.status_code == 200, f"HTTP {live.status_code}")

    ready = client.get("/health/ready")
    check(
        "readiness responds",
        ready.status_code in (200, 503),
        f"HTTP {ready.status_code}",
    )
    if ready.status_code == 200:
        for dep in ready.json().get("dependencies", []):
            print(f"       · {dep['name']}: {dep['status']} — {dep.get('detail', '')}")

    # ── the gate is on ──────────────────────────────────────────────────────
    anonymous = client.get(args.secured_path)
    check(
        "a secured path rejects an unauthenticated request",
        anonymous.status_code == 401,
        f"HTTP {anonymous.status_code} (expected 401 — is GATEWAY_AUTH_ENABLED false, "
        "or is this path in GATEWAY_PUBLIC_PATHS?)",
    )

    check(
        "401 names a machine-readable reason",
        anonymous.status_code != 401 or "reason" in anonymous.json().get("error", {}),
    )

    # ── the configured public path is reachable ─────────────────────────────
    public = client.post(args.public_path, json={"email": "nobody@example.test", "password": "x"})
    check(
        f"{args.public_path} is reachable without a token",
        public.status_code != 401,
        f"HTTP {public.status_code} (a 4xx from the service behind it is fine here; "
        "401 from the gateway itself means it is not in GATEWAY_PUBLIC_PATHS)",
    )

    # ── a valid token works ─────────────────────────────────────────────────
    token = mint()
    headers = {"Authorization": f"Bearer {token}"}

    routed = client.get(args.secured_path, headers=headers)
    check(
        "a valid token gets through the gate",
        routed.status_code not in (401, 403),
        f"HTTP {routed.status_code}"
        + (" — 502/504 means the service behind it is down, not that the gate failed"
           if routed.status_code in (502, 504) else ""),
    )

    check(
        "responses carry a correlation ID",
        bool(routed.headers.get("x-request-id")),
    )

    # ── logout is routed, and noticed ───────────────────────────────────────
    # The gateway does not implement logout; it forwards it and records the
    # revocation when the upstream accepts it. If auth-service is not running,
    # this half cannot be exercised — the token is only revoked on success.
    logout = client.post(args.logout_path, headers=headers)
    if 200 <= logout.status_code < 300:
        after = client.get(args.secured_path, headers=headers)
        check(
            "a token stops working once logout succeeds",
            after.status_code == 401,
            f"HTTP {after.status_code}",
        )
    else:
        print(
            f"[SKIP] logout revocation — {args.logout_path} returned "
            f"HTTP {logout.status_code}; nothing was revoked because the session "
            "did not end upstream (is auth-service running?)"
        )

    client.close()

    print()
    if _failures:
        print(f"{_failures} check(s) failed.")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""End-to-end smoke test against a running gateway.

    python run.py &
    python scripts/smoke_test.py

Checks the things a deployment can get wrong that unit tests cannot see: that
the process actually serves, that the JWT gate is on, that an unauthenticated
call to a proxied path is refused, and that a valid token gets through. Exits
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
        "--proxied-path",
        default="/api/llm/v1/models",
        help="a path behind the gateway, to prove the gate applies to it",
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
    anonymous = client.get(args.proxied_path)
    check(
        "proxied path rejects an unauthenticated request",
        anonymous.status_code == 401,
        f"HTTP {anonymous.status_code} (expected 401 — is GATEWAY_AUTH_ENABLED false?)",
    )

    check(
        "401 names a machine-readable reason",
        anonymous.status_code != 401 or "reason" in anonymous.json().get("error", {}),
    )

    # ── sign-in is public ───────────────────────────────────────────────────
    login = client.post("/auth/login", json={"email": "nobody@example.test", "password": "x"})
    check(
        "sign-in is reachable without a token",
        login.status_code != 401,
        f"HTTP {login.status_code} (a 4xx from auth-service is fine here; 401 from "
        "the gateway itself is not)",
    )

    # ── a valid token works ─────────────────────────────────────────────────
    token = mint()
    headers = {"Authorization": f"Bearer {token}"}

    whoami = client.get("/auth/whoami", headers=headers)
    check("a valid token is accepted", whoami.status_code == 200, f"HTTP {whoami.status_code}")
    if whoami.status_code == 200:
        check(
            "the gateway reads the expected claims",
            whoami.json().get("user_id") == "smoke-test-user",
        )

    proxied = client.get(args.proxied_path, headers=headers)
    check(
        "an authenticated request reaches the upstream",
        proxied.status_code not in (401, 403),
        f"HTTP {proxied.status_code}"
        + (" — 502/504 means the upstream is down, not that the gate failed"
           if proxied.status_code in (502, 504) else ""),
    )

    check(
        "responses carry a correlation ID",
        bool(proxied.headers.get("x-request-id")),
    )

    # ── logout revokes immediately ──────────────────────────────────────────
    logout = client.post("/auth/logout", headers=headers)
    check("logout succeeds", logout.status_code == 200, f"HTTP {logout.status_code}")

    after = client.get("/auth/whoami", headers=headers)
    check(
        "the token stops working the moment it is logged out",
        after.status_code == 401,
        f"HTTP {after.status_code}",
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

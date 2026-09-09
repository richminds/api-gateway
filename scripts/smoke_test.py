"""End-to-end smoke test against a running gateway.

    python run.py &
    python scripts/smoke_test.py

Checks the things a deployment can get wrong that unit tests cannot see: that
the process serves, that the gate is on, that a configured public path is
reachable without a token, and that a real token gets through. Exits non-zero
on the first failure so it can gate a deploy.

The gateway holds no signing key, so this script cannot mint a token — that is
the point of the architecture. Give it real credentials and it signs in through
the gateway to get one, or pass ``--token`` if you already have one. With
neither, the authenticated half is skipped and the public half still runs.

    python scripts/smoke_test.py --email you@example.com --password ...
    python scripts/smoke_test.py --token "$TOKEN"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"
_failures = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _failures
    if not condition:
        _failures += 1
    print(f"[{PASS if condition else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def skip(name: str, why: str) -> None:
    print(f"[{SKIP}] {name} — {why}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument(
        "--secured-path",
        default="/api/llm/v1/models",
        help="a routed path that should require a token",
    )
    parser.add_argument(
        "--login-path",
        default="/auth/login",
        help="the routed sign-in path (must be in GATEWAY_PUBLIC_PATHS)",
    )
    parser.add_argument("--email", default="", help="sign in through the gateway")
    parser.add_argument("--password", default="")
    parser.add_argument("--account-id", default="", help="optional account for login")
    parser.add_argument("--token", default="", help="use an existing token instead")
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
    check("readiness responds", ready.status_code in (200, 503), f"HTTP {ready.status_code}")
    if ready.status_code in (200, 503):
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

    # A token the gateway has never seen must be refused, not admitted. This is
    # the check that fails loudly if validation is misconfigured — a gateway
    # that cannot reach auth-service answers 502 here, never 200.
    bogus = client.get(
        args.secured_path, headers={"Authorization": "Bearer not-a-real-token"}
    )
    check(
        "a bogus token is refused",
        bogus.status_code in (401, 502, 504),
        f"HTTP {bogus.status_code}"
        + (
            " — 502/504 means auth-service could not be asked; check "
            "GATEWAY_INTROSPECTION_URL"
            if bogus.status_code in (502, 504)
            else ""
        ),
    )
    if bogus.status_code in (502, 504):
        check(
            "validation reaches auth-service",
            False,
            "the gateway could not validate anything — every authenticated "
            "request will fail until GATEWAY_INTROSPECTION_URL is correct",
        )

    # ── a configured public path is reachable ───────────────────────────────
    login_payload: dict[str, str] = {
        "email": args.email or "nobody@example.test",
        "password": args.password or "not-a-real-password",
    }
    if args.account_id:
        login_payload["account_id"] = args.account_id

    public = client.post(args.login_path, json=login_payload)
    check(
        f"{args.login_path} is reachable without a token",
        public.status_code != 401 or bool(args.email),
        f"HTTP {public.status_code} (a 4xx from auth-service is fine here; a 401 "
        "from the gateway itself means it is not in GATEWAY_PUBLIC_PATHS)",
    )

    # ── a real token gets through ───────────────────────────────────────────
    token = args.token
    if not token and args.email and public.status_code == 200:
        token = public.json().get("access_token", "")
        check("sign-in returned a token", bool(token))

    if not token:
        skip(
            "authenticated routing",
            "no token — pass --token, or --email/--password to sign in",
        )
    else:
        headers = {"Authorization": f"Bearer {token}"}
        routed = client.get(args.secured_path, headers=headers)
        check(
            "a valid token gets through the gate",
            routed.status_code not in (401, 403),
            f"HTTP {routed.status_code}"
            + (
                " — 502/504 here means the service behind it is down, not that "
                "the gate failed"
                if routed.status_code in (502, 504)
                else ""
            ),
        )
        check("responses carry a correlation ID", bool(routed.headers.get("x-request-id")))

    client.close()

    print()
    if _failures:
        print(f"{_failures} check(s) failed.")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

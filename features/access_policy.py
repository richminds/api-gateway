"""Which paths are public and which require a token.

The gateway routes rather than implements, so it cannot know from a path alone
whether it is a sign-in endpoint or a private one — that is a fact about the
service behind it. So it is configuration:

    GATEWAY_PUBLIC_PATHS=POST:/auth/login,POST:/auth/register

Everything not listed requires a valid JWT. That default is the important
half: a new endpoint appearing on any upstream is protected automatically, and
opening it up takes a deliberate edit. The opposite default — public unless
listed — fails silently and in the dangerous direction.

Entry forms, in increasing order of how much they give away:

    /auth/login             this exact path, any method
    POST:/auth/login        this exact path, only via POST
    /auth/public/*          this path and everything beneath it, any method

The wildcard exists because some services genuinely have a whole public
subtree, but it is an explicit opt-in: a bare path never matches by prefix.
That is deliberate — a prefix rule like "/auth/* is public" is one new
endpoint away from exposing /auth/users, and nothing errors when it happens,
the endpoint just stops being protected.

Two categories are public no matter what is configured:

  * the gateway's own infrastructure paths (health, docs, banner) — an
    orchestrator has to probe before any credential exists;
  * CORS preflight (OPTIONS) — a preflight never carries an Authorization
    header, by design, so a 401 on it breaks every browser client while
    protecting nothing.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
)

# The gateway's own endpoints, always reachable without a credential. These are
# served by this service, not routed anywhere, so they are not a matter of
# deployment configuration.
INFRASTRUCTURE_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/health",
        "/health/live",
        "/health/ready",
        "/health/upstreams",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/openapi.json",
    }
)


@dataclass(frozen=True)
class PublicRule:
    """One entry from GATEWAY_PUBLIC_PATHS."""

    path: str
    method: str = ""
    """Empty means any method."""
    prefix: bool = False
    """True when the entry ended in "*"."""

    def matches(self, method: str, path: str) -> bool:
        if self.method and self.method != method.upper():
            return False
        if self.prefix:
            # "/x/*" covers "/x/anything" and "/x" itself, but not "/xy".
            return path == self.path or path.startswith(self.path + "/")
        return path == self.path


class AccessPolicy:
    """Decides whether a request needs a token. Immutable once built."""

    def __init__(self, rules: list[PublicRule]) -> None:
        self._rules = rules

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> list[PublicRule]:
        return list(self._rules)

    def is_public(self, method: str, path: str) -> bool:
        """True when this request may proceed without a valid token."""
        # A trailing slash is normalised away first: FastAPI treats
        # "/auth/login/" as a redirect to "/auth/login", and a caller who sends
        # the former should not get a 401 the latter would not produce.
        normalised = path.rstrip("/") or "/"

        if normalised in INFRASTRUCTURE_PATHS:
            return True
        if method.upper() == "OPTIONS":
            return True  # CORS preflight — see the module docstring

        return any(rule.matches(method, normalised) for rule in self._rules)

    def describe(self) -> list[str]:
        """Human-readable rules, for the startup log and GET /v1/config."""
        return [
            f"{r.method or 'ANY'} {r.path}{'/*' if r.prefix else ''}" for r in self._rules
        ]


def parse_public_paths(raw: str) -> list[PublicRule]:
    """Parse GATEWAY_PUBLIC_PATHS. Raises ValueError on a malformed entry.

    Fatal rather than skip-and-warn, unlike the rate-limit overrides. A dropped
    public path takes down sign-in — loudly, at startup, is far better than
    discovering it when nobody can log in.
    """
    rules: list[PublicRule] = []

    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue

        method = ""
        path = entry
        head, sep, tail = entry.partition(":")
        if sep and head.upper() in HTTP_METHODS:
            method = head.upper()
            path = tail.strip()

        prefix = path.endswith("*")
        if prefix:
            # "/x/*" and "/x*" both mean the subtree at /x; the rstrip makes
            # them equivalent rather than making the second one match "/xy".
            path = path[:-1].rstrip("/")

        if not path.startswith("/"):
            raise ValueError(
                f"Malformed GATEWAY_PUBLIC_PATHS entry {entry!r} — a path must "
                "start with '/' (e.g. 'POST:/auth/login' or '/auth/public/*')"
            )

        rules.append(PublicRule(path=path, method=method, prefix=prefix))

    return rules


def build_access_policy(raw: str | None = None) -> AccessPolicy:
    """Build the policy from settings (or an explicit string, for tests)."""
    from .config import gateway_settings

    policy = AccessPolicy(
        parse_public_paths(raw if raw is not None else gateway_settings.public_paths)
    )

    if len(policy):
        logger.info("Public (no token required): %s", ", ".join(policy.describe()))
    else:
        # Legitimate for a gateway fronting only private services, but if the
        # auth routes are behind it too then nobody can obtain a token, so it
        # is worth saying out loud.
        logger.warning(
            "GATEWAY_PUBLIC_PATHS is empty — every routed path requires a token. "
            "If sign-in is routed through this gateway, no one can obtain one."
        )
    return policy

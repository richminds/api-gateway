"""The route table — which public path prefix belongs to which upstream service.

A gateway is only useful if adding a service behind it is configuration rather
than code, so the table is parsed from ``GATEWAY_ROUTES`` at startup:

    GATEWAY_ROUTES=llm:/api/llm:http://localhost:8080,knowledge:/api/knowledge:http://localhost:8090

Each comma-separated entry is ``name:prefix:base_url``.

    name        the service's identity in logs, usage rows, health output and
                error bodies. Never its URL — a base URL can carry credentials
                in some deployments and error bodies reach the caller.
    prefix      the public path this service owns, e.g. /api/llm
    base_url    where to forward to, e.g. http://llm-gateway:8080

Parsing splits on the first two colons only (``split(":", 2)``), because the
third field is a URL that contains colons of its own — "http://host:8080" must
survive intact. That is the entire reason this is not a naive ``split(":")``.

Prefix matching is longest-first, so a more specific route can be layered over
a general one (``/api/llm/embeddings`` -> a dedicated service,
``/api/llm`` -> the rest) without the order of the env var mattering. Getting
this wrong is a class of bug where a route works or doesn't depending on
dictionary insertion order, which is exactly the kind of thing that survives
code review and fails in staging.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .errors import ConfigurationError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Route:
    """One upstream service and the public path prefix it owns."""

    name: str
    prefix: str
    base_url: str

    def upstream_path(self, request_path: str) -> str:
        """Translate a public path into the path to request upstream.

        The prefix is *stripped*, so ``/api/llm/v1/chat`` reaches llm-gateway
        as ``/v1/chat`` — the upstream keeps serving the same paths it always
        did and has no idea it is behind a gateway. That is what lets these
        services stay independently runnable and independently testable.

        A request for exactly the prefix (``/api/llm``) maps to ``/``, not to
        the empty string, since an empty path is not a valid request target.
        """
        remainder = request_path[len(self.prefix) :]
        if not remainder:
            return "/"
        return remainder if remainder.startswith("/") else "/" + remainder

    def target_url(self, request_path: str) -> str:
        return self.base_url + self.upstream_path(request_path)


class ServiceRegistry:
    """The parsed route table. Immutable once built."""

    def __init__(self, routes: list[Route]) -> None:
        # Longest prefix first — see the module docstring. Sorted once here so
        # every lookup is a straight scan with no ordering surprises.
        self._routes = sorted(routes, key=lambda r: len(r.prefix), reverse=True)
        self._by_name = {r.name: r for r in self._routes}

    def __len__(self) -> int:
        return len(self._routes)

    def __iter__(self):
        return iter(self._routes)

    @property
    def routes(self) -> list[Route]:
        return list(self._routes)

    def get(self, name: str) -> Route | None:
        return self._by_name.get(name)

    def resolve(self, path: str) -> Route | None:
        """The route owning this path, or None.

        A prefix matches when the path is the prefix exactly, or continues with
        a "/". The boundary check is what stops ``/api/llmstore`` from being
        swallowed by the ``/api/llm`` route — a plain ``startswith`` would
        route a different service's traffic to the wrong place.
        """
        for route in self._routes:
            if path == route.prefix or path.startswith(route.prefix + "/"):
                return route
        return None


def parse_routes(raw: str) -> list[Route]:
    """Parse ``GATEWAY_ROUTES``. Raises ConfigurationError on a malformed entry.

    Unlike the rate-limit overrides — where a bad entry is skipped so one typo
    can't stop the service booting — a bad route is fatal. Silently dropping it
    would leave the gateway up and healthy while returning 404 for a service
    everyone believes is wired in, and that is a much worse failure than not
    starting.
    """
    routes: list[Route] = []
    seen_prefixes: dict[str, str] = {}

    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue

        parts = entry.split(":", 2)
        if len(parts) != 3:
            raise ConfigurationError(
                f"Malformed GATEWAY_ROUTES entry {entry!r} — expected "
                "'name:prefix:base_url' (e.g. 'llm:/api/llm:http://localhost:8080')"
            )

        name, prefix, base_url = (p.strip() for p in parts)

        if not name or not prefix or not base_url:
            raise ConfigurationError(
                f"Malformed GATEWAY_ROUTES entry {entry!r} — name, prefix and "
                "base_url must all be non-empty"
            )
        if not prefix.startswith("/"):
            raise ConfigurationError(
                f"Route prefix {prefix!r} must start with '/' (service {name!r})"
            )
        if not base_url.startswith(("http://", "https://")):
            raise ConfigurationError(
                f"Route base_url {base_url!r} must start with http:// or https:// "
                f"(service {name!r})"
            )

        # A trailing slash here would produce "//v1/chat" upstream. Harmless on
        # most servers, but it shows up in their access logs and route matching
        # and is trivial to normalise once, here.
        prefix = prefix.rstrip("/") or "/"
        base_url = base_url.rstrip("/")

        if prefix in seen_prefixes:
            raise ConfigurationError(
                f"Route prefix {prefix!r} is claimed by both "
                f"{seen_prefixes[prefix]!r} and {name!r} — prefixes must be unique"
            )
        seen_prefixes[prefix] = name

        routes.append(Route(name=name, prefix=prefix, base_url=base_url))

    return routes


def build_registry(raw: str | None = None) -> ServiceRegistry:
    """Build the registry from settings (or an explicit string, for tests)."""
    from .config import gateway_settings

    routes = parse_routes(raw if raw is not None else gateway_settings.routes)
    if not routes:
        # Not fatal: a gateway with no upstreams still serves login/logout and
        # is a legitimate intermediate state while a deployment is being wired
        # up. It is not a normal steady state, so it is worth a warning.
        logger.warning(
            "GATEWAY_ROUTES is empty — no services are reachable through this "
            "gateway. Auth endpoints still work."
        )
    else:
        logger.info(
            "Route table: %s",
            ", ".join(f"{r.prefix} -> {r.name}" for r in routes),
        )
    return ServiceRegistry(routes)

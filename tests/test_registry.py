"""Route-table parsing and prefix matching.

Pure unit tests — no app, no network. The prefix-boundary and longest-match
cases are the ones that would otherwise fail as "a route works in dev and
sends traffic to the wrong service in staging".
"""
from __future__ import annotations

import pytest

from features.errors import ConfigurationError
from features.registry import ServiceRegistry, build_registry, parse_routes


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parses_a_single_route():
    routes = parse_routes("llm:/api/llm:http://localhost:8080")
    assert len(routes) == 1
    assert routes[0].name == "llm"
    assert routes[0].prefix == "/api/llm"
    assert routes[0].base_url == "http://localhost:8080"


def test_the_urls_own_colons_are_not_separators():
    """The reason this is not a naive split(":") — "http://host:8080" has to
    survive intact."""
    routes = parse_routes("svc:/api/svc:https://example.com:9443/base")
    assert routes[0].base_url == "https://example.com:9443/base"


def test_parses_several_routes():
    routes = parse_routes(
        "llm:/api/llm:http://localhost:8080,knowledge:/api/knowledge:http://localhost:8090"
    )
    assert [r.name for r in routes] == ["llm", "knowledge"]


def test_whitespace_and_empty_entries_are_tolerated():
    routes = parse_routes(" llm:/api/llm:http://a.test , , knowledge:/api/k:http://b.test ")
    assert len(routes) == 2


def test_trailing_slashes_are_normalised():
    """A trailing slash would produce "//v1/chat" upstream."""
    routes = parse_routes("llm:/api/llm/:http://localhost:8080/")
    assert routes[0].prefix == "/api/llm"
    assert routes[0].base_url == "http://localhost:8080"


@pytest.mark.parametrize(
    "raw",
    [
        "missing-fields",
        "name:/prefix",                      # no base_url
        "name:/prefix:",                     # empty base_url
        ":/prefix:http://a.test",            # empty name
        "name:prefix-without-slash:http://a.test",
        "name:/prefix:ftp://a.test",         # not http(s)
    ],
)
def test_malformed_entries_are_fatal(raw):
    """Deliberately fatal, unlike the rate-limit overrides: silently dropping a
    route leaves the gateway up and healthy while 404ing a service everyone
    believes is wired in."""
    with pytest.raises(ConfigurationError):
        parse_routes(raw)


def test_duplicate_prefixes_are_rejected():
    with pytest.raises(ConfigurationError, match="unique"):
        parse_routes("a:/api/x:http://a.test,b:/api/x:http://b.test")


def test_an_empty_route_table_is_allowed():
    """A legitimate intermediate state while a deployment is being wired up —
    auth endpoints still work."""
    assert parse_routes("") == []


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def registry(raw: str) -> ServiceRegistry:
    return ServiceRegistry(parse_routes(raw))


def test_resolves_a_path_to_its_service():
    reg = registry("llm:/api/llm:http://a.test")
    assert reg.resolve("/api/llm/v1/chat").name == "llm"


def test_the_bare_prefix_resolves():
    reg = registry("llm:/api/llm:http://a.test")
    assert reg.resolve("/api/llm").name == "llm"


def test_an_unregistered_path_resolves_to_nothing():
    reg = registry("llm:/api/llm:http://a.test")
    assert reg.resolve("/api/other") is None


def test_a_prefix_only_matches_on_a_path_boundary():
    """The check that stops /api/llmstore being swallowed by the /api/llm
    route — a plain startswith would send another service's traffic to the
    wrong place."""
    reg = registry("llm:/api/llm:http://a.test")
    assert reg.resolve("/api/llmstore/thing") is None


def test_the_longest_matching_prefix_wins_regardless_of_order():
    """So a specific route can be layered over a general one without the order
    of the env var mattering."""
    general_first = registry(
        "llm:/api/llm:http://a.test,embed:/api/llm/embeddings:http://b.test"
    )
    specific_first = registry(
        "embed:/api/llm/embeddings:http://b.test,llm:/api/llm:http://a.test"
    )
    for reg in (general_first, specific_first):
        assert reg.resolve("/api/llm/embeddings/v1").name == "embed"
        assert reg.resolve("/api/llm/v1/chat").name == "llm"


# ---------------------------------------------------------------------------
# Path translation
# ---------------------------------------------------------------------------

def test_the_prefix_is_stripped_for_the_upstream():
    """The upstream keeps serving the paths it always did."""
    route = parse_routes("llm:/api/llm:http://a.test")[0]
    assert route.upstream_path("/api/llm/v1/chat") == "/v1/chat"
    assert route.target_url("/api/llm/v1/chat") == "http://a.test/v1/chat"


def test_the_bare_prefix_maps_to_root():
    """Not the empty string — that is not a valid request target."""
    route = parse_routes("llm:/api/llm:http://a.test")[0]
    assert route.upstream_path("/api/llm") == "/"


def test_build_registry_reads_the_configured_routes():
    reg = build_registry("a:/x:http://a.test")
    assert len(reg) == 1
    assert reg.get("a") is not None
    assert reg.get("nope") is None

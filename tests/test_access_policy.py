"""The public/private policy — parsing and matching.

Pure unit tests. The "private by default" and prefix-boundary cases are the
ones that would otherwise fail as "an endpoint nobody meant to expose was
reachable in production".
"""
from __future__ import annotations

import pytest

from features.access_policy import AccessPolicy, build_access_policy, parse_public_paths


def policy(raw: str) -> AccessPolicy:
    return AccessPolicy(parse_public_paths(raw))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_a_bare_path_is_public_for_any_method():
    rules = parse_public_paths("/auth/login")
    assert rules[0].path == "/auth/login"
    assert rules[0].method == ""
    assert rules[0].prefix is False


def test_a_method_can_be_required():
    rules = parse_public_paths("POST:/auth/login")
    assert rules[0].method == "POST"
    assert rules[0].path == "/auth/login"


def test_the_method_is_normalised_to_upper_case():
    assert parse_public_paths("post:/auth/login")[0].method == "POST"


def test_a_wildcard_marks_a_subtree():
    rules = parse_public_paths("/public/*")
    assert rules[0].prefix is True
    assert rules[0].path == "/public"


def test_several_entries_and_whitespace():
    rules = parse_public_paths(" POST:/auth/login , /health/x , ")
    assert len(rules) == 2


def test_a_path_must_start_with_a_slash():
    with pytest.raises(ValueError):
        parse_public_paths("auth/login")


def test_an_empty_policy_parses():
    assert parse_public_paths("") == []


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def test_anything_not_listed_is_private():
    """The default that matters: a new upstream endpoint is protected the
    moment it exists."""
    p = policy("POST:/auth/login")
    assert p.is_public("POST", "/auth/login")
    assert not p.is_public("GET", "/auth/me")
    assert not p.is_public("POST", "/auth/logout")
    assert not p.is_public("GET", "/api/llm/v1/models")


def test_a_method_scoped_rule_does_not_open_other_methods():
    p = policy("POST:/auth/login")
    assert p.is_public("POST", "/auth/login")
    assert not p.is_public("GET", "/auth/login")
    assert not p.is_public("DELETE", "/auth/login")


def test_a_bare_rule_opens_every_method():
    p = policy("/auth/login")
    assert p.is_public("POST", "/auth/login")
    assert p.is_public("GET", "/auth/login")


def test_an_exact_rule_never_matches_by_prefix():
    """A bare path is exact — this is what stops '/auth/login' from also
    opening '/auth/login-as-someone-else'."""
    p = policy("/auth/login")
    assert not p.is_public("POST", "/auth/login/extra")
    assert not p.is_public("POST", "/auth/loginx")


def test_a_wildcard_covers_the_subtree_and_the_root():
    p = policy("/public/*")
    assert p.is_public("GET", "/public")
    assert p.is_public("GET", "/public/thing")
    assert p.is_public("GET", "/public/a/b/c")


def test_a_wildcard_respects_the_path_boundary():
    """'/public/*' must not open '/publicity'."""
    p = policy("/public/*")
    assert not p.is_public("GET", "/publicity")
    assert not p.is_public("GET", "/publicthings")


def test_a_trailing_slash_does_not_change_the_answer():
    p = policy("POST:/auth/login")
    assert p.is_public("POST", "/auth/login/")


def test_infrastructure_paths_are_public_with_an_empty_policy():
    p = policy("")
    assert p.is_public("GET", "/health/live")
    assert p.is_public("GET", "/docs")
    assert p.is_public("GET", "/")
    assert not p.is_public("GET", "/api/llm/v1/models")


def test_options_is_always_public():
    p = policy("")
    assert p.is_public("OPTIONS", "/api/llm/v1/models")


def test_describe_is_readable():
    p = policy("POST:/auth/login,/public/*")
    assert p.describe() == ["POST /auth/login", "ANY /public/*"]


def test_build_reads_the_configured_value():
    p = build_access_policy("POST:/x")
    assert p.is_public("POST", "/x")
    assert not p.is_public("POST", "/y")

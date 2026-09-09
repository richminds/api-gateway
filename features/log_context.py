"""Ambient correlation IDs for the current request.

Three values live here — the correlation ID (``request_id``) that ties every
artefact of one call together, the ``account_id`` the call was made on behalf
of, and the ``user_id`` who made it. All three are bound once at the top of
the request and read ambiently everywhere else, because threading them
through every function in ``features/`` would touch code that has no business
knowing about HTTP.

This is the same mechanism as llm-gateway's ``features/log_context.py``, with
``user_id`` added. The gateway is the only service that knows *who* the caller
is before anyone downstream does — it is where the token is opened — so it is
the only place that can put a real user on a log line. Everything it emits
while handling a request therefore carries all three fields with no call site
passing anything down (see ``app/logging_config.py``).

Usage::

    from features.log_context import bind_request_id, get_request_id

    token = bind_request_id("a1b2c3d4")
    try:
        ...  # everything in here, and everything it awaits, sees this ID
    finally:
        reset_request_id(token)

``request_id`` is the only one of the three that is ever minted. An account or
a user is an identity someone else asserts and we verify; inventing one would
put a fabricated principal on log lines and usage rows, which is worse than
the honest "" that says "this request named nobody".
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Iterator
from uuid import uuid4

_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "api_gateway_request_id", default=""
)
_account_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "api_gateway_account_id", default=""
)
_user_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "api_gateway_user_id", default=""
)


# ────────────────────────────────────────────────────────────────── request ID

def get_request_id() -> str:
    """The correlation ID for whatever is currently running, or "" if none was
    ever bound (e.g. a script importing features/ with no HTTP request)."""
    return _request_id_var.get()


def bind_request_id(request_id: str) -> contextvars.Token:
    """Bind a correlation ID. Returns a token for ``reset_request_id`` —
    prefer ``request_id_scope`` unless you need the raw token (e.g. crossing
    an ``await`` boundary a ``with`` block can't span, which is exactly the
    HTTP middleware's situation)."""
    return _request_id_var.set(request_id)


def reset_request_id(token: contextvars.Token) -> None:
    _request_id_var.reset(token)


def new_request_id() -> str:
    """Mint a correlation ID in the shape the whole platform uses.

    16 hex chars — same as llm-gateway and knowledge-service mint, so an ID
    that starts here stays recognisable when it appears in their logs after
    being forwarded as ``X-Request-ID``.
    """
    return uuid4().hex[:16]


@contextmanager
def request_id_scope(request_id: str | None = None) -> Iterator[str]:
    """Bind a correlation ID for the duration of the ``with`` block, minting
    one when none is given."""
    resolved = request_id or new_request_id()
    token = _request_id_var.set(resolved)
    try:
        yield resolved
    finally:
        _request_id_var.reset(token)


# ────────────────────────────────────────────────────────────────── account ID

def get_account_id() -> str:
    """The account (tenant) the current work is being done for, or "" when the
    caller's token named none.

    Empty is a normal, expected value — health probes and unauthenticated
    sign-in traffic both produce it. It is emitted as "" rather than omitted so
    ``account_id`` is always present to query on, including the query "which
    traffic arrived with no account at all".
    """
    return _account_id_var.get()


def bind_account_id(account_id: str) -> contextvars.Token:
    return _account_id_var.set(account_id)


def reset_account_id(token: contextvars.Token) -> None:
    _account_id_var.reset(token)


@contextmanager
def account_id_scope(account_id: str) -> Iterator[str]:
    """Bind an account ID for the duration of the ``with`` block. Never mints
    one — see the module docstring."""
    token = _account_id_var.set(account_id or "")
    try:
        yield account_id or ""
    finally:
        _account_id_var.reset(token)


# ───────────────────────────────────────────────────────────────────── user ID

def get_user_id() -> str:
    """The authenticated user for the current request, or "" when there isn't
    one (a health probe, or a sign-in that hasn't succeeded yet)."""
    return _user_id_var.get()


def bind_user_id(user_id: str) -> contextvars.Token:
    return _user_id_var.set(user_id)


def reset_user_id(token: contextvars.Token) -> None:
    _user_id_var.reset(token)


@contextmanager
def user_id_scope(user_id: str) -> Iterator[str]:
    """Bind a user ID for the duration of the ``with`` block. Never mints
    one — see the module docstring."""
    token = _user_id_var.set(user_id or "")
    try:
        yield user_id or ""
    finally:
        _user_id_var.reset(token)

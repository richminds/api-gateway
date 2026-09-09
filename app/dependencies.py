"""Shared FastAPI dependencies — access to the singletons and the caller.

The long-lived objects (the proxy connection pool, the service registry, the
access policy) are built once in the lifespan and stashed on ``app.state``.
Reaching them through a dependency rather than a module-level global is what
lets a test build the app with fake upstreams and a fake transport, with no
monkeypatching and no network.
"""
from __future__ import annotations

from fastapi import Depends, Request

from features.errors import AuthorizationError
from features.proxy import ProxyClient
from features.registry import ServiceRegistry
from features.identity import ANONYMOUS, CallerIdentity


def get_proxy_client(request: Request) -> ProxyClient:
    return request.app.state.proxy_client


def get_registry(request: Request) -> ServiceRegistry:
    return request.app.state.registry


def get_identity(request: Request) -> CallerIdentity:
    """The verified caller.

    Set by ``AuthMiddleware``, which has already rejected anything invalid — so
    on a protected route this is always a real identity, and on a public one it
    may be ``ANONYMOUS``.
    """
    return getattr(request.state, "identity", ANONYMOUS)


def get_token(request: Request) -> str:
    """The raw bearer token, forwarded upstream alongside the decoded claims.

    Downstream services validate the JWT themselves, so they need the token
    itself and not only the headers derived from it. Nothing else should reach
    for this — re-parsing a token that has already been verified invites the
    two paths to disagree about who the caller is.
    """
    return getattr(request.state, "token", "")


def require_admin(identity: CallerIdentity = Depends(get_identity)) -> CallerIdentity:
    """403s unless the caller is an administrator.

    The gateway's own administrative routes (usage, rate-limit windows,
    resolved config) expose every account's traffic volumes, so they are gated
    on membership of the admin app account. The flag comes from auth-service —
    the gateway has no user store of its own to consult.
    """
    if not identity.is_admin:
        raise AuthorizationError(
            "This endpoint is restricted to administrators."
        )
    return identity

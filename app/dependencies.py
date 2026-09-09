"""Shared FastAPI dependencies — access to the singletons and the caller.

The long-lived objects (the auth-service client, the proxy connection pool,
the service registry) are built once in the lifespan and stashed on
``app.state``. Reaching them through a dependency rather than a module-level
global is what lets a test build the app with a fake auth-service and a fake
transport, with no monkeypatching and no network.
"""
from __future__ import annotations

from fastapi import Depends, Request

from features.auth_client import AuthServiceClient
from features.errors import AuthorizationError
from features.proxy import ProxyClient
from features.registry import ServiceRegistry
from features.tokens import ANONYMOUS, CallerIdentity


def get_auth_client(request: Request) -> AuthServiceClient:
    return request.app.state.auth_client


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
    """The raw bearer token, for the endpoints that forward it to auth-service.

    Only the auth controller needs this. Everything else should work from the
    decoded identity above — re-parsing a token that has already been verified
    invites the two paths to disagree about who the caller is.
    """
    return getattr(request.state, "token", "")


def require_admin(identity: CallerIdentity = Depends(get_identity)) -> CallerIdentity:
    """403s unless the caller is platform staff.

    The gateway's own administrative routes (usage, rate-limit windows,
    resolved config) expose every tenant's traffic volumes, so they are gated
    on the same platform-staff flag knowledge-service uses to bypass per-org
    filtering. The claim comes from the token and therefore from auth-service —
    the gateway has no user store of its own to consult.
    """
    if not identity.is_portless:
        raise AuthorizationError(
            "This endpoint is restricted to platform staff."
        )
    return identity

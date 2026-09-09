"""Domain exceptions raised by the gateway core.

Framework-free on purpose: these say what went wrong, and ``app/errors.py``
is the single place that decides what each one means over HTTP. That split is
what lets this package be imported and tested without FastAPI.
"""
from __future__ import annotations


class GatewayError(Exception):
    """Base for every error this gateway raises itself."""


class ConfigurationError(GatewayError):
    """The deployment is misconfigured — an operator has to fix it.

    Raised for an empty/malformed route table or a missing JWT secret when
    auth enforcement is on. Never the caller's fault, so it surfaces as 500.
    """


class AuthenticationError(GatewayError):
    """The caller presented no credential, or an invalid/expired/revoked one.

    Carries ``reason`` as a stable machine-readable code so a client can tell
    "your token expired, refresh it" apart from "that token was revoked, log
    in again" without parsing prose.
    """

    def __init__(self, message: str, reason: str = "invalid_token") -> None:
        self.reason = reason
        super().__init__(message)


class AuthorizationError(GatewayError):
    """The caller is authenticated but not allowed to do this."""


class UpstreamError(GatewayError):
    """A downstream service could not be reached or did not answer in time.

    ``service`` is the registry name of the upstream (not its URL — the URL
    can carry credentials in some deployments and this message reaches the
    caller). ``timeout`` distinguishes "took too long" (504) from "refused
    the connection" (502).
    """

    def __init__(self, service: str, detail: str, timeout: bool = False) -> None:
        self.service = service
        self.detail = detail
        self.timeout = timeout
        super().__init__(f"Upstream '{service}' failed: {detail}")


class RouteNotFound(GatewayError):
    """No registered service claims this path prefix."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"No service is registered for path '{path}'")

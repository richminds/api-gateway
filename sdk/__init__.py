"""Client SDK for the API Gateway.

Copy this package (or pip-install this repo) into any application that should
reach the platform through its front door. One base URL, one credential, and
the session handling — sign in, hold the token, re-authenticate on expiry — is
done for you.
"""
from .client import GatewayClient, GatewayError, Session

__all__ = ["GatewayClient", "GatewayError", "Session"]

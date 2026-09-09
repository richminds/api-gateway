"""Request/response models for the gateway's auth endpoints.

These mirror auth-service's own schemas rather than importing them, because
the two services share no code — that is the price of them being independently
deployable, and duplicating four small models is cheaper than a shared package
both must upgrade in lockstep.

The response models are deliberately loose (``TokenResponse`` carries the user
as a nested model with optional fields) because the gateway's job on these
routes is to pass auth-service's answer through, not to re-validate it. A
strict model here would turn "auth-service added a field" into "the gateway
strips it", which is a debugging session nobody enjoys.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    """Sign up. One of the two endpoints reachable without a token."""

    email: str = Field(min_length=3, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=6, max_length=200)
    account_id: str | None = Field(default=None, max_length=64)
    """The application this user belongs to. Must reference an app account
    registered with auth-service when given."""
    org_id: str | None = Field(default=None, max_length=200)
    """Optional at signup — omit to sign up as a guest and join an
    organization later via POST /auth/me/organization."""


class LoginRequest(BaseModel):
    """Sign in. The other endpoint reachable without a token."""

    email: str
    password: str
    account_id: str | None = Field(default=None, max_length=200)
    """Which application this login is for. When the user belongs to more than
    one, the response lists them all and the client should let the user pick,
    then call POST /auth/me/account."""


class SelectAccountRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)


class JoinOrganizationRequest(BaseModel):
    org_id: str


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class UserPublic(BaseModel):
    """The user as auth-service describes them."""

    user_id: str
    email: str = ""
    name: str = ""
    account_id: str | None = None
    account_ids: list[str] = Field(default_factory=list)
    org_id: str | None = None
    is_admin: bool = False
    is_portless: bool = False
    created_at: str | None = None


class LoginAccount(BaseModel):
    account_id: str
    name: str


class TokenResponse(BaseModel):
    """What a successful sign-in, sign-up or token re-issue returns.

    The token is minted by auth-service and signed with the secret this
    gateway verifies against — the gateway never mints one itself. It has no
    signing key of its own, on purpose: one service issues identity, one place
    to audit.
    """

    access_token: str
    token_type: str = "bearer"
    user: UserPublic
    account_id: str | None = None
    accounts: list[LoginAccount] = Field(default_factory=list)


class LogoutResponse(BaseModel):
    """Logout is idempotent and always reports success — see the controller."""

    status: str = "logged_out"
    detail: str = ""


class GatewayIdentity(BaseModel):
    """Who the gateway thinks you are, from your token alone.

    Served by GET /auth/whoami. Deliberately distinct from GET /auth/me, which
    asks auth-service for the *stored* profile: this one is free (no network
    call) and shows exactly the claims the gateway will act on and forward
    downstream, which is what you want when debugging an authorization problem.
    """

    user_id: str
    email: str = ""
    name: str = ""
    account_id: str = ""
    org_id: str = ""
    is_portless: bool = False
    expires_at: int = 0

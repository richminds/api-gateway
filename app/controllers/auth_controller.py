"""Auth endpoints — the gateway's front for auth-service.

Every route here goes through ``features/auth_client.py``, which is the only
thing in the platform that talks to auth-service. Clients never see that
service; they see these paths.

The surface is deliberately smaller than auth-service's own. Only what an
end-user client needs to sign in and manage its own session is exposed:

    POST /auth/register              sign up          (public)
    POST /auth/login                 sign in          (public)
    POST /auth/logout                sign out
    GET  /auth/me                    stored profile
    GET  /auth/whoami                token claims, no network call
    POST /auth/me/account            switch app account (re-issues the token)
    POST /auth/me/organization       join an org       (re-issues the token)
    POST /auth/organizations/register  self-serve org creation (public)

auth-service's staff-only administration routes (user lists, org management,
app-account CRUD) are **not** proxied. They are operator tooling, reached
directly on the private network by whoever runs the platform; publishing them
through the public front door would put the platform's entire user and tenant
administration one authorization bug away from the internet, in exchange for
convenience nobody has asked for. Adding one is a deliberate act, not an
oversight to be corrected.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse

from features.auth_client import AuthServiceClient, AuthServiceResponse
from features.revocation import revoke_token
from features.tokens import CallerIdentity

from ..dependencies import get_auth_client, get_identity, get_token
from ..models.auth_model import (
    CreateOrganizationRequest,
    GatewayIdentity,
    JoinOrganizationRequest,
    LoginRequest,
    RegisterRequest,
    SelectAccountRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _passthrough(result: AuthServiceResponse) -> Response:
    """Return auth-service's answer as-is.

    Status and body are preserved exactly — see AuthServiceResponse for why the
    gateway does not reinterpret them. Only auth-service's *headers* are
    dropped: they describe its connection, not this one, and its CORS headers
    would conflict with the ones this gateway's own middleware sets.
    """
    if result.status_code == status.HTTP_204_NO_CONTENT or result.body is None:
        return Response(status_code=result.status_code)
    return JSONResponse(status_code=result.status_code, content=result.body)


@router.post("/register", summary="Sign up")
async def register(
    payload: RegisterRequest,
    request: Request,
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """Create an account and return a token. **Public** — no JWT required.

    One of exactly two endpoints that can be reached without a token (see
    app/middleware/auth.py). Rate limited by client IP like any other
    unauthenticated traffic, which is what stops this being used to enumerate
    or spam-create accounts.
    """
    result = await auth.register(
        payload.model_dump(exclude_none=True), request_id=request.state.request_id
    )
    if result.ok:
        # No user_id yet on request.state — this is the request that creates
        # them — so it is logged explicitly rather than left to the ambient
        # context, which would show "" for the most interesting line in the
        # signup flow.
        logger.info(
            "Registered a new user",
            extra={"email": payload.email, "account_id": payload.account_id or ""},
        )
    return _passthrough(result)


@router.post("/login", summary="Sign in")
async def login(
    payload: LoginRequest,
    request: Request,
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """Exchange credentials for a token. **Public** — no JWT required.

    The token comes back signed by auth-service; the gateway verifies it on
    every subsequent request without calling auth-service again.

    A failed sign-in is passed through with auth-service's own 401. It is
    logged here at warning level because this gateway is the only place that
    sees every sign-in attempt for the whole platform — which makes it the only
    place that can spot a credential-stuffing run.
    """
    result = await auth.login(
        payload.model_dump(exclude_none=True), request_id=request.state.request_id
    )
    if not result.ok:
        logger.warning(
            "Failed sign-in attempt",
            extra={"email": payload.email, "status": result.status_code},
        )
    return _passthrough(result)


@router.post(
    "/organizations/register",
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization",
)
async def register_organization(
    payload: CreateOrganizationRequest,
    request: Request,
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """Self-serve organization creation. **Public** — no JWT required.

    Returns an org_id to hand to teammates in a signup form, or to pass
    straight to POST /auth/register. Public because a brand-new organization
    has no members yet, so there is nobody who could hold a token for it —
    requiring one would make the first signup impossible.
    """
    return _passthrough(
        await auth.register_organization(
            payload.model_dump(), request_id=request.state.request_id
        )
    )


@router.post("/logout", summary="Sign out")
async def logout(
    request: Request,
    identity: CallerIdentity = Depends(get_identity),
    token: str = Depends(get_token),
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """Revoke this token, here and at auth-service.

    **Both, and the local one first**, because the two stores answer different
    questions. auth-service's blacklist is what *it* checks on its own
    endpoints; the gateway's is what stops the token at the front door — and
    since the gateway verifies tokens locally rather than asking auth-service
    per request, a logout recorded only there would leave the token working
    for every proxied call until it expired. That is the entire failure mode
    this ordering exists to prevent.

    If auth-service is unreachable the logout still succeeds: the local
    revocation has already happened, so the token is dead everywhere it can
    still be used through this gateway — which, since the gateway is the only
    ingress, is everywhere that matters. Reporting a failure would invite the
    client to retry a logout that has, in every sense the user cares about,
    already worked.
    """
    await revoke_token(identity.jti, identity.expires_at)

    detail = ""
    try:
        result = await auth.logout(token, request_id=request.state.request_id)
        if not result.ok:
            # e.g. auth-service considers the token already revoked. Not an
            # error worth failing on — the desired end state holds either way.
            logger.info(
                "auth-service returned %d on logout; the token is revoked at "
                "the gateway regardless.",
                result.status_code,
            )
    except Exception as exc:  # noqa: BLE001 — see the docstring
        detail = "Session ended at the gateway; auth-service was unreachable."
        logger.warning("Could not propagate logout to auth-service: %s", exc)

    logger.info("User logged out")
    return JSONResponse(
        status_code=200, content={"status": "logged_out", "detail": detail}
    )


@router.get("/whoami", response_model=GatewayIdentity, summary="Token claims")
async def whoami(identity: CallerIdentity = Depends(get_identity)) -> GatewayIdentity:
    """What this gateway reads from your token — no network call.

    Distinct from GET /auth/me below, which asks auth-service for the stored
    profile. Use this one to debug an authorization problem: it shows exactly
    the claims the gateway acts on and forwards downstream, which is what a 403
    from a downstream service is actually about. If it disagrees with /auth/me,
    the token predates a change to the user and they need a fresh one.
    """
    return GatewayIdentity(
        user_id=identity.user_id,
        email=identity.email,
        name=identity.name,
        account_id=identity.account_id,
        org_id=identity.org_id,
        is_portless=identity.is_portless,
        expires_at=identity.expires_at,
    )


@router.get("/me", summary="Stored profile")
async def me(
    request: Request,
    token: str = Depends(get_token),
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """The caller's profile as auth-service currently holds it.

    Costs a round trip, unlike /auth/whoami — which is the point: this reflects
    changes made since the token was issued (a new organization, a changed
    name), where the token's own claims are a snapshot from sign-in time.
    """
    return _passthrough(await auth.me(token, request_id=request.state.request_id))


@router.post("/me/account", summary="Switch app account")
async def select_account(
    payload: SelectAccountRequest,
    request: Request,
    token: str = Depends(get_token),
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """Re-issue this caller's token scoped to another of their app accounts.

    The second half of a multi-account sign-in: POST /auth/login lists the
    accounts a user may use, this exchanges a choice for a new token. It has to
    be a new token because the account is a signed claim that downstream
    services scope their data on — a client-side flag would let anyone read
    another account's data by flipping it.

    The old token is NOT revoked here. It remains valid for its remaining
    lifetime, scoped to the previous account, which is what makes it safe for a
    client to hold two sessions open — an admin console showing two
    applications side by side is a real use, and revoking on switch would break
    it. Use POST /auth/logout to end a session deliberately.
    """
    return _passthrough(
        await auth.select_account(
            payload.model_dump(), token, request_id=request.state.request_id
        )
    )


@router.post("/me/organization", summary="Join an organization")
async def join_organization(
    payload: JoinOrganizationRequest,
    request: Request,
    token: str = Depends(get_token),
    auth: AuthServiceClient = Depends(get_auth_client),
) -> Response:
    """Attach a guest account to an organization; returns a re-issued token.

    Only works while the account has no organization — moving a user between
    organizations is staff-only at auth-service, so a user cannot walk into
    another tenant's data. The gateway does not second-guess that rule; it
    forwards the request and auth-service enforces it.
    """
    return _passthrough(
        await auth.join_organization(
            payload.model_dump(), token, request_id=request.state.request_id
        )
    )

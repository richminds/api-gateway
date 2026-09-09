"""API Gateway core — the portable half of the service.

Everything in here is framework-free (no FastAPI import) so it can be unit
tested without an HTTP server and, if the gateway is ever embedded in another
process, imported directly. ``app/`` is the HTTP shell around it, exactly as
in the sibling llm-gateway (``features/`` + ``app/``), knowledge-service
(``rag/`` + ``app/``) and auth-service (``features/`` + ``app/``).

What lives here:

    config.py         GATEWAY_* domain settings — upstreams, JWT, limits
    registry.py       the route table: which path prefix goes to which service
    access_policy.py  which routed paths are public; everything else needs a token
    tokens.py         local JWT verification (HS256) + the caller identity
    revocation.py     logged-out token IDs, so logout takes effect at once
    rate_limiter.py   sliding-window request budgets per user and per account
    usage.py          request counters per user and per account
    proxy.py          the forwarding engine + identity injection
    log_context.py    ambient request/user/account IDs for correlated logs
    errors.py         domain exceptions (app/errors.py maps them to HTTP)

Nothing here implements an application capability. auth-service, llm-gateway
and knowledge-service are all reached the same way: as entries in the route
table.
"""

__version__ = "1.0.0"

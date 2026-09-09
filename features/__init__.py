"""API Gateway core — the portable half of the service.

Everything in here is framework-free (no FastAPI import) so it can be unit
tested without an HTTP server and, if the gateway is ever embedded in another
process, imported directly. ``app/`` is the HTTP shell around it, exactly as
in the sibling llm-gateway (``features/`` + ``app/``), knowledge-service
(``rag/`` + ``app/``) and auth-service (``features/`` + ``app/``).

What lives here:

    config.py         GATEWAY_* domain settings — upstreams, validation, limits
    registry.py       the route table: which path prefix goes to which service
    access_policy.py  which routed paths are public; everything else needs a token
    introspection.py  token validation, delegated to auth-service (cached)
    identity.py       the caller, as auth-service reported them
    rate_limiter.py   sliding-window request budgets per user and per account
    usage.py          request counters per user and per account
    proxy.py          the forwarding engine + identity injection
    log_context.py    ambient request/user/account IDs for correlated logs
    errors.py         domain exceptions (app/errors.py maps them to HTTP)

Nothing here implements an application capability, and nothing here decodes a
token: auth-service owns identity and answers "who is this?", while
llm-gateway, knowledge-service and auth-service itself are all reached the
same way — as entries in the route table.
"""

__version__ = "1.0.0"

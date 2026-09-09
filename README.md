# API Gateway

The single ingress for the platform. Every client request enters here and
nowhere else.

It authenticates every request against a JWT minted by auth-service — except
sign-in and sign-up, which cannot have a token yet — logs every request in one
place with a verified user on it, meters requests per user and per account,
enforces per-user and per-account budgets, and reverse-proxies what survives
all of that to the services behind it.

**It is the only service that talks to auth-service.**

```
                        ┌──────────────────────────────────────┐
   browser / client     │            api-gateway  :8000        │
   ───────────────────► │                                      │
        JWT             │  authenticate → budget → log → route │
                        └───┬──────────────┬───────────────┬───┘
                            │              │               │
              ┌─────────────┘              │               └──────────────┐
              ▼                            ▼                              ▼
      auth-service :8100          llm-gateway :8080         knowledge-service :8090
      (private — gateway           /api/llm/*                /api/knowledge/*
       is its only caller)
```

---

## Why the gateway is the only caller of auth-service

Identity is established in one place, so there is one place to audit, one place
to rate limit sign-in attempts, and one place that can be certain it has seen
every logout. auth-service binds to the private network; in a correct
deployment nothing else can reach it.

That property is enforced in code by a single module —
[`features/auth_client.py`](features/auth_client.py). Every call to
auth-service in the entire system goes through it. If a second caller ever
appears, that is the thing to push back on in review, because the guarantee
only holds while that file is the sole client.

---

## Quick start

```bash
cp .env.example .env
# set GATEWAY_JWT_SECRET to the same value as auth-service's AUTH_JWT_SECRET

make install
make dev            # http://localhost:8000/docs
```

Without a running auth-service you can still exercise the gate, because tokens
are verified locally:

```bash
TOKEN=$(python scripts/mint_token.py --user-id dev-1 --account-id acme)

curl -H "Authorization: Bearer $TOKEN" localhost:8000/auth/whoami
curl localhost:8000/api/llm/v1/models                     # 401 — no token
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/llm/v1/models

python scripts/smoke_test.py                              # end-to-end checks
```

---

## The rule

**Every request needs a valid, unrevoked JWT, except:**

| Public path | Why |
|---|---|
| `POST /auth/register` | signing up — there is no token yet, that is the point |
| `POST /auth/login` | signing in — likewise |
| `POST /auth/organizations/register` | a new organization has no members who could hold a token |
| `GET /health`, `/health/*` | an orchestrator must probe before any credential exists |
| `GET /docs`, `/redoc`, `/openapi.json`, `/` | documentation and the service banner |

The list is an explicit allowlist of **exact paths**
([`app/middleware/auth.py`](app/middleware/auth.py)), never a pattern. A prefix
rule like "`/auth/*` is public" is one new endpoint away from silently exposing
`/auth/users` — nothing errors, the endpoint just stops being protected. Adding
a public path should require someone to type it.

Everything else — every proxied service call, every other auth endpoint — is
401 without a token.

---

## Endpoints

### Session

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | public | Sign up; returns a token |
| `POST` | `/auth/login` | public | Sign in; returns a token |
| `POST` | `/auth/organizations/register` | public | Self-serve organization creation |
| `POST` | `/auth/logout` | JWT | Revoke this token here **and** at auth-service |
| `GET` | `/auth/whoami` | JWT | The claims the gateway reads — no network call |
| `GET` | `/auth/me` | JWT | The stored profile, from auth-service |
| `POST` | `/auth/me/account` | JWT | Switch app account (re-issues the token) |
| `POST` | `/auth/me/organization` | JWT | Join an organization (re-issues the token) |

auth-service's staff-only administration routes (user lists, org management,
app-account CRUD) are deliberately **not** proxied. They are operator tooling,
reached directly on the private network; publishing them through the public
front door would put the platform's entire user and tenant administration one
authorization bug away from the internet.

### Observability

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/usage/me` | JWT | The caller's own request counts |
| `GET` | `/v1/usage` | staff | Counts per user / account / service, with rollups |
| `GET` | `/v1/rate-limits` | staff | Live sliding windows |
| `GET` | `/v1/routes` | staff | The route table |
| `GET` | `/v1/config` | staff | Resolved, non-secret configuration |
| `GET` | `/health/live` | public | Liveness — touches no dependency |
| `GET` | `/health/ready` | public | Readiness — auth-service and storage |
| `GET` | `/health/upstreams` | public | Live probe of every registered service |

"staff" means the token's `is_portless` claim — set by auth-service, never by
the gateway, which has no user store of its own.

### Everything else

Any path matching a registered prefix is proxied. `GATEWAY_ROUTES` maps
`name:prefix:base_url`, and the prefix is **stripped** before forwarding:

```
GET /api/llm/v1/chat        →  llm-gateway        GET /v1/chat
GET /api/knowledge/v1/query →  knowledge-service  GET /v1/query
```

The upstreams keep serving the paths they always did and stay independently
runnable and testable. Adding a service is a configuration change, not a code
change.

---

## Token lifecycle

auth-service **signs**; the gateway **verifies**. The gateway has no signing
key of its own — one service issues identity.

```
  POST /auth/login  ──►  gateway  ──►  auth-service   (bcrypt check, mints JWT)
                                            │
  ◄──────────────── access_token ───────────┘

  GET /api/llm/...  ──►  gateway   verifies the signature LOCALLY
                                   (no call to auth-service)
                            │
                            └──►  llm-gateway, with identity headers attached
```

Verification is local and deliberately so: a network round trip in front of
every request would make auth-service a hard dependency of *all* platform
traffic — one slow auth-service would take everything down — and would add a
hop's latency to requests that have nothing to do with identity.

Configuration must line up, because HS256 is symmetric:

| Gateway | must equal | auth-service |
|---|---|---|
| `GATEWAY_JWT_SECRET` | = | `AUTH_JWT_SECRET` |
| `GATEWAY_JWT_ISSUER` | = | `AUTH_JWT_ISSUER` |
| `GATEWAY_JWT_AUDIENCE` | ∈ | `AUTH_JWT_AUDIENCE` (a list) |

A mismatch shows up as every request 401ing — check the `reason` field:
`invalid_token` (secret), `invalid_issuer`, `invalid_audience`,
`token_expired`, `token_revoked`, `missing_token`.

### Logout, and why it works

A JWT is stateless: once signed it is valid until `exp`, and nothing about the
token changes when a user logs out. Since the gateway verifies locally, a
logout recorded only at auth-service would leave the token working for every
proxied call until it expired.

So `POST /auth/logout` records the revocation **locally first**, then tells
auth-service. The local set is complete by construction — the gateway is the
only ingress, so every logout in the platform passes through it. If
auth-service is unreachable the logout still succeeds, because the token is
already dead everywhere it could still be used.

Entries carry a TTL equal to the token's own remaining lifetime, so the set
never grows without bound. Point `GATEWAY_MONGO_URI` and
`GATEWAY_REVOKED_TOKENS_COLLECTION` at auth-service's own database and the two
blacklists become one store.

---

## What downstream services receive

The gateway **replaces** the caller's identity headers with verified ones. This
is the security-critical part: downstream services trust `X-User-ID` and
`X-Org-ID`, so if a caller could send them, they could read any tenant's data
by typing a different value. Stripping is unconditional — remove whatever was
there, then set ours ([`features/proxy.py`](features/proxy.py)).

| Header | From |
|---|---|
| `X-User-ID` | the `sub` claim |
| `X-User-Email`, `X-User-Name` | token claims |
| `X-Account-ID` | the app account the token is scoped to |
| `X-Org-ID` | the tenant — what downstream services filter data on |
| `X-Is-Portless` | platform staff; sent **only** when true |
| `X-Authenticated-Via` | `api-gateway` |
| `X-Request-ID` | the correlation ID |
| `Authorization` | the original bearer token, forwarded |

The token is forwarded *as well as* the decomposed claims, deliberately:
llm-gateway and knowledge-service already validate JWTs themselves and keep
doing so unchanged. The headers are a convenience layer, not a replacement.

`X-Forwarded-For` is **set**, not appended — the gateway is the trust boundary,
so a caller cannot forge its own origin.

---

## Rate limiting

Two dimensions, both enforced, because they stop different failure modes:

| Scope | Default | Stops |
|---|---|---|
| per user | `GATEWAY_USER_RPM=120` | one runaway client hurting their own colleagues |
| per account | `GATEWAY_ACCOUNT_RPM=1200` | one tenant crowding out the platform |
| per IP | `GATEWAY_ANONYMOUS_RPM=30` | password guessing at sign-in |

A request must pass both applicable budgets. Checking only the user lets a
thousand users of one account swamp everyone else; checking only the account
lets one user inside a big account burn its whole allowance.

A 429 says which budget was hit, in the body's `scope` and in
`X-RateLimit-Scope` — "you are going too fast" and "your organization is going
too fast" call for completely different reactions. `Retry-After` is the real
window expiry, not a fixed guess.

Budgets are **per process**. With N replicas, each enforces its own window, so
divide the intended global budget by N.

---

## Usage metering

Separate from rate limiting, and often confused with it: the limiter enforces a
rolling 60-second window and then forgets; metering keeps cumulative totals per
`(user, account, service, day)` — requests, errors, latency, status buckets.

Writes are buffered and flushed on a timer rather than written per request,
which would add a database round trip to every proxied call. A hard crash loses
at most `GATEWAY_USAGE_FLUSH_SECONDS` of counters — the right trade for data
used to bill and forecast rather than to enforce.

Requests rejected before reaching an upstream are counted too: a client
generating nothing but 401s is using the platform, and the numbers should say
so.

With no `GATEWAY_MONGO_URI` everything stays in-process and `GET /v1/usage`
still works; the numbers reset when the process does.

---

## Logging

One JSON object per line, the same format as the sibling services, so one query
spans the whole platform. Every line carries `request_id`, `account_id` and
`user_id` from ambient context — no call site threads them through.

```json
{"timestamp":"2026-09-09T17:03:35.104Z","level":"INFO","logger":"gateway.access",
 "message":"GET /api/llm/v1/models → 502 (2301ms)","request_id":"bc0935f29f574f4b",
 "account_id":"smoke-account","user_id":"smoke-test-user","method":"GET",
 "path":"/api/llm/v1/models","status":502,"latency_ms":2301.1,"service":"llm"}
```

The `user_id` is what makes this gateway's logs different from every other
service's: it is the only place that opens the token, so it is the only place
that can put a real user on a log line. "Show me everything user X did today,
across every service" is a field filter here and a guess anywhere else.

The correlation ID is echoed from the caller when present, minted otherwise,
returned on the response, and forwarded upstream — so one ID ties the gateway's
log, auth-service's log and the upstream's log together for a single call.

`APIGW_LOG_FORMAT=text` reverts to a plain format for a local terminal.

---

## Errors

One envelope for the whole platform:

```json
{"error": {"code": "rate_limit_exceeded", "message": "...",
           "request_id": "bc0935f29f574f4b", "scope": "user", "limit": 120}}
```

| Status | Code | Meaning |
|---|---|---|
| 401 | `unauthorized` | no credential, or an invalid/expired/revoked one (see `reason`) |
| 403 | `forbidden` | authenticated, but not allowed |
| 404 | `route_not_found` | no service is registered for this path |
| 429 | `rate_limit_exceeded` | over the user, account or IP budget |
| 502 | `upstream_unavailable` | a downstream service could not be reached |
| 504 | `upstream_timeout` | a downstream service did not answer in time |
| 500 | `gateway_misconfigured` | bad route table or configuration |

`request_id` is on every error — it is what turns "it failed" in a bug report
into the exact log line.

---

## Layout

```
app/                     HTTP layer (FastAPI)
  main.py                app factory, lifespan, middleware order
  config.py              APIGW_* — how the service is exposed
  errors.py              domain exception → HTTP status
  logging_config.py      JSON formatter
  dependencies.py        singletons + the caller identity
  middleware/
    request_context.py   correlation ID, access log, usage metering
    auth.py              the JWT gate
    rate_limit.py        per-user / per-account / per-IP budgets
  controllers/
    auth_controller.py   login, logout, session
    proxy_controller.py  the catch-all
    health_controller.py probes
    admin_controller.py  usage, limits, config
features/                portable core — no FastAPI import
  config.py              GATEWAY_* — what it fronts and trusts
  auth_client.py         THE ONLY client for auth-service
  tokens.py              local JWT verification
  revocation.py          logged-out tokens
  registry.py            the route table
  proxy.py               forwarding + identity injection
  rate_limiter.py        sliding windows
  usage.py               request counters
  log_context.py         ambient request/user/account IDs
sdk/                     GatewayClient — session handling for callers
scripts/                 mint_token.py, smoke_test.py
tests/                   130 tests, no network, no MongoDB
```

Middleware order is load-bearing and documented in
[`app/main.py`](app/main.py): Starlette runs middleware in **reverse**
registration order, and registering the rate limiter outside the auth
middleware is a silent failure — the limiter still runs, sees no identity yet,
and quietly budgets every authenticated caller by IP.

---

## Development

```bash
make install-dev
make test           # 130 tests
make test-cov
make lint
make docker-up
```

The suite never touches a network, a MongoDB or a real auth-service: fake
upstreams are injected as httpx `MockTransport` handlers through the same
`client=` constructor argument the production classes already expose, so the
real client code paths — header building, error translation, streaming,
connection release — are the ones under test. Only the socket is fake.

---

## Deployment notes

- **Set `GATEWAY_JWT_SECRET`.** Unset, it falls back to the same development
  default auth-service uses, and anyone who has read either repository can forge
  a token for any user. The gateway logs an error at startup in production.
- **Set `GATEWAY_MONGO_URI` for more than one replica.** Otherwise each replica
  meters only its own traffic and honours only the logouts it personally
  handled.
- **Only this service should be publicly reachable.** The whole model assumes
  auth-service, llm-gateway and knowledge-service are on a private network.
- **`APIGW_TRUST_FORWARDED_FOR` stays false** unless a load balancer you control
  overwrites the header. Exposed directly, anyone can rotate a fake IP per
  request and the sign-in rate limit becomes no rate limit at all.
- **CORS is configured here and only here** — the gateway is the only origin a
  browser app talks to.

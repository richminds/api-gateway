# API Gateway

The single ingress for the platform. **A router** — it implements no business
capability of its own. Every request is forwarded to the service that owns it,
auth-service included.

What it adds is the cross-cutting work that would otherwise be reimplemented in
every service, inconsistently: authenticating the caller, logging the request
with a verified identity on it, metering it per user and per account, and
enforcing request budgets.

```
                        ┌──────────────────────────────────────┐
   browser / client     │            api-gateway  :8000        │
   ───────────────────► │                                      │
   service-to-service   │  authenticate → budget → log → route │
                        └───┬──────────────┬───────────────┬───┘
                            │              │               │
              ┌─────────────┘              │               └──────────────┐
              ▼                            ▼                              ▼
      auth-service :8100          llm-gateway :8080         knowledge-service :8090
        /auth/*                     /api/llm/*                /api/knowledge/*
```

Every service behind it is private. The gateway is the only thing that reaches
them, which is what makes it the only caller of auth-service — a property of
being the sole ingress, not of implementing anything.

---

## What it does not do

It does not implement sign-in, sign-up, logout, or any other auth endpoint.
Those belong to auth-service, which is routed like every other upstream:

```
POST /auth/login   →  gateway  →  auth-service  POST /auth/login
GET  /auth/me      →  gateway  →  auth-service  GET  /auth/me
GET  /auth/accounts→  gateway  →  auth-service  GET  /auth/accounts
```

The gateway does not parse those request bodies, re-declare those models, or
reshape those responses. A field auth-service adds tomorrow arrives at the
client without a gateway change, because there is nothing here to update.

---

## Quick start

```bash
cp .env.example .env
# set GATEWAY_JWT_SECRET to the same value as auth-service's AUTH_JWT_SECRET

make install
make dev            # http://localhost:8000/docs
```

Tokens are verified locally, so you can exercise the gate with no auth-service
running:

```bash
TOKEN=$(python scripts/mint_token.py --user-id dev-1 --account-id acme)

curl localhost:8000/api/llm/v1/models                       # 401 — no token
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/llm/v1/models
curl -X POST localhost:8000/auth/login -d '{}'              # public — routed

python scripts/smoke_test.py                                # end-to-end checks
```

---

## Secured and non-secured endpoints

**Private by default.** A routed path requires a valid JWT unless it is listed
in `GATEWAY_PUBLIC_PATHS`:

```bash
GATEWAY_PUBLIC_PATHS=POST:/auth/login,POST:/auth/register,POST:/auth/organizations/register
```

That default direction is the important part — a new endpoint appearing on any
upstream is protected the moment it exists, and opening it up takes a
deliberate edit. The opposite default fails silently and in the dangerous
direction.

| Entry form | Meaning |
|---|---|
| `/auth/login` | this exact path, any method |
| `POST:/auth/login` | this exact path, only via POST |
| `/public/*` | this path and everything beneath it |

A bare path is **exact** and never matches by prefix. The wildcard is an
explicit opt-in, because a rule like "`/auth/*` is public" is one new endpoint
away from exposing `/auth/users`, and nothing errors when that happens — the
endpoint just stops being protected.

Always public regardless of configuration: the gateway's own `/health*`,
`/docs`, `/redoc`, `/openapi.json` and `/` (an orchestrator must probe before
any credential exists), and `OPTIONS` preflight (which never carries an
`Authorization` header by design, so a 401 on it breaks every browser client
while protecting nothing).

So with the default configuration:

| Path | Token required |
|---|---|
| `POST /auth/login`, `POST /auth/register` | no |
| `GET /auth/me`, `POST /auth/logout` | **yes** |
| `GET /auth/accounts`, `GET /auth/users` | **yes** (auth-service also enforces staff rights) |
| `GET /api/llm/*`, `GET /api/knowledge/*` | **yes** |

---

## Routing

`GATEWAY_ROUTES` maps `name:prefix:base_url`. The prefix is **stripped** before
forwarding, so upstreams keep serving the paths they always did and stay
independently runnable:

```
GET /api/llm/v1/chat        →  llm-gateway        GET /v1/chat
GET /api/knowledge/v1/query →  knowledge-service  GET /v1/query
POST /auth/login            →  auth-service       POST /auth/login
```

The auth entry's `base_url` carries a **path**
(`http://localhost:8100/auth`): auth-service serves under `/auth`, the matched
prefix is stripped, and the base URL's path puts it back. That keeps the public
path identical to what the UIs already call, so pointing them at the gateway is
a base-URL change and nothing else.

Prefix matching is longest-first, so a specific route can be layered over a
general one regardless of the order of the env var. Adding a service is a
configuration change, not a code change.

---

## Token lifecycle

auth-service **signs**; the gateway **verifies**. The gateway has no signing key
of its own.

```
  POST /auth/login  ──►  gateway ──routes──►  auth-service   (mints the JWT)
  ◄──────────────── access_token ─────────────────┘

  GET /api/llm/...  ──►  gateway   verifies the signature LOCALLY
                            │      (no call to auth-service)
                            └──routes──►  llm-gateway, identity headers attached
```

Verification is local and deliberately so: a network round trip in front of
every request would make auth-service a hard dependency of *all* platform
traffic, and would add a hop's latency to requests that have nothing to do with
identity.

Configuration must line up, because HS256 is symmetric:

| Gateway | must equal | auth-service |
|---|---|---|
| `GATEWAY_JWT_SECRET` | = | `AUTH_JWT_SECRET` |
| `GATEWAY_JWT_ISSUER` | = | `AUTH_JWT_ISSUER` |
| `GATEWAY_JWT_AUDIENCE` | ∈ | `AUTH_JWT_AUDIENCE` (a list) |

A mismatch shows up as every request 401ing — check the `reason` field:
`invalid_token` (secret), `invalid_issuer`, `invalid_audience`, `token_expired`,
`token_revoked`, `missing_token`.

### Logout

A JWT is stateless: once signed it is valid until `exp`. Since the gateway
verifies locally, a logout recorded only at auth-service would leave the token
working here until it expired.

The gateway still does not implement logout — it routes the request and **takes
note of the result**. When a request to a path in `GATEWAY_LOGOUT_PATHS`
succeeds, the token's `jti` is recorded as revoked, so it stops being accepted
at the front door immediately. A *failed* logout revokes nothing: the session
did not end, and revoking would sign the user out of something still live.

Two mechanisms, either sufficient:

- **Observed logouts** (above) — works with no shared storage, correct for a
  single replica.
- **Shared revocation store** — point `GATEWAY_MONGO_URI` and
  `GATEWAY_REVOKED_TOKENS_COLLECTION` at auth-service's own database and the
  two blacklists become one, so a token revoked by either side is dead to both.
  Required for more than one replica.

---

## What downstream services receive

The gateway **replaces** the caller's identity headers with verified ones. This
is the security-critical part: downstream services trust `X-User-ID` and
`X-Org-ID`, so if a caller could send them, they could read any tenant's data by
typing a different value. Stripping is unconditional.

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
doing so unchanged. `X-Forwarded-For` is **set**, not appended — the gateway is
the trust boundary, so a caller cannot forge its own origin.

---

## Rate limiting

| Scope | Default | Stops |
|---|---|---|
| per user | `GATEWAY_USER_RPM=120` | one runaway client hurting their own colleagues |
| per account | `GATEWAY_ACCOUNT_RPM=1200` | one tenant crowding out the platform |
| per IP | `GATEWAY_ANONYMOUS_RPM=30` | password guessing on the public paths |

A request must pass both applicable budgets. Checking only the user lets a
thousand users of one account swamp everyone else; checking only the account
lets one user inside a big account burn its whole allowance.

A 429 says which budget was hit, in the body's `scope` and in
`X-RateLimit-Scope`. `Retry-After` is the real window expiry, not a fixed guess.
Budgets are **per process** — with N replicas, divide the intended global budget
by N.

---

## Usage metering

Separate from rate limiting: the limiter enforces a rolling 60-second window and
forgets; metering keeps cumulative totals per `(user, account, service, day)` —
requests, errors, latency, status buckets.

Writes are buffered and flushed on a timer rather than written per request,
which would add a database round trip to every routed call. Requests rejected
before reaching a service are counted too: a client generating nothing but 401s
is using the platform.

---

## Logging

One JSON object per line, the same format as the sibling services, so one query
spans the whole platform. Every line carries `request_id`, `account_id` and
`user_id` from ambient context.

```json
{"timestamp":"2026-09-09T17:03:35.104Z","level":"INFO","logger":"gateway.access",
 "message":"GET /api/llm/v1/models → 200 (231ms)","request_id":"bc0935f29f574f4b",
 "account_id":"acme","user_id":"user-1","method":"GET",
 "path":"/api/llm/v1/models","status":200,"latency_ms":231.1,"service":"llm"}
```

The `user_id` is what makes this gateway's logs different: it is the only place
that opens the token, so it is the only place that can put a real user on a log
line. The correlation ID is echoed from the caller when present, minted
otherwise, returned on the response, and forwarded upstream — so one ID ties the
gateway's log and the upstream's log together for a single call.

---

## The gateway's own endpoints

Only health and its own observability. Everything else is routed.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health/live` | public | Liveness — touches no dependency |
| `GET` | `/health/ready` | public | Readiness — route table and storage |
| `GET` | `/health/upstreams` | public | Live probe of every registered service |
| `GET` | `/v1/usage/me` | JWT | The caller's own request counts |
| `GET` | `/v1/usage` | staff | Counts per user / account / service |
| `GET` | `/v1/rate-limits` | staff | Live sliding windows |
| `GET` | `/v1/routes` | staff | The route table |
| `GET` | `/v1/config` | staff | Resolved, non-secret configuration |

"staff" means the token's `is_portless` claim — set by auth-service, never by
the gateway, which has no user store of its own.

A **down upstream is not an unready gateway**: if llm-gateway is unreachable,
this service stays in the load balancer, keeps serving knowledge-service
traffic, and returns an honest 502 for the rest. That applies to auth-service
too — traffic carrying a valid token is unaffected by it being down, because
verification is local.

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
| 502 | `upstream_unavailable` | a service could not be reached |
| 504 | `upstream_timeout` | a service did not answer in time |
| 500 | `gateway_misconfigured` | bad route table or configuration |

A service's own status codes pass through untouched — a 409 from auth-service
reaches the client as a 409, worded as auth-service worded it.

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
    proxy_controller.py  the catch-all router
    health_controller.py probes
    admin_controller.py  usage, limits, config
features/                portable core — no FastAPI import
  config.py              GATEWAY_* — what it fronts and trusts
  registry.py            the route table
  access_policy.py       which paths are public
  tokens.py              local JWT verification
  revocation.py          logged-out tokens
  proxy.py               forwarding + identity injection
  rate_limiter.py        sliding windows
  usage.py               request counters
  log_context.py         ambient request/user/account IDs
sdk/                     GatewayClient — session handling for callers
scripts/                 mint_token.py, smoke_test.py
tests/                   145 tests, no network, no MongoDB
```

Middleware order is load-bearing and documented in [`app/main.py`](app/main.py):
Starlette runs middleware in **reverse** registration order, and registering the
rate limiter outside the auth middleware is a silent failure — the limiter still
runs, sees no identity yet, and quietly budgets every authenticated caller by IP.

---

## Development

```bash
make install-dev
make test           # 145 tests
make lint
make docker-up
```

The suite never touches a network or a MongoDB: every upstream is one httpx
`MockTransport` handler injected through the `client=` argument `ProxyClient`
already exposes, so the real proxy code paths — header building, error
translation, streaming, connection release — are the ones under test.

---

## Deployment notes

- **Set `GATEWAY_JWT_SECRET`.** Unset, it falls back to the same development
  default auth-service uses, and anyone who has read either repository can forge
  a token for any user.
- **Set `GATEWAY_MONGO_URI` for more than one replica.** Otherwise each replica
  meters only its own traffic and honours only the logouts it personally routed.
  On serverless (Vercel), where instances are ephemeral and independent, treat
  this as required rather than optional.
- **Only this service should be publicly reachable.** The whole model assumes
  auth-service, llm-gateway and knowledge-service are on a private network.
- **`APIGW_TRUST_FORWARDED_FOR` stays false** unless a load balancer you control
  overwrites the header. Exposed directly, anyone can rotate a fake IP per
  request and the public-path rate limit becomes no rate limit at all.
- **CORS is configured here and only here** — the gateway is the only origin a
  browser app talks to.

### Pointing the UIs at the gateway

Both UIs call `/auth/*` already, so with the default route table only their base
URL changes:

```bash
VITE_AUTH_BASE_URL=https://api.example.com     # was auth-service directly
VITE_API_BASE_URL=https://api.example.com/api/knowledge
```

### A Git Bash gotcha (Windows)

Git Bash rewrites environment values that look like Unix paths, so

```bash
export GATEWAY_LOGOUT_PATHS=/auth/logout      # becomes C:/Program Files/Git/auth/logout
```

silently mangles any setting whose value starts with `/` — `GATEWAY_PUBLIC_PATHS`
entries without a `METHOD:` prefix included. It fails quietly: the gateway
starts, routes fine, and simply never matches the path. Set these in `.env`
(which is read directly and unaffected), or export `MSYS_NO_PATHCONV=1` first.

# API Gateway

The single ingress for the platform. **A router** — it implements no business
capability of its own. Every request is forwarded to the service that owns it,
auth-service included.

What it adds is the cross-cutting work that would otherwise be reimplemented in
every service, inconsistently: authenticating the caller, logging the request
with a verified identity on it, metering it per user and per account, and
enforcing request budgets.

It holds **no signing key** and decodes nothing. A token is an opaque string it
hands to auth-service, which answers "who is this?" — having checked the
signature, the expiry and its own revocation list.

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

It also does not **validate** tokens itself. There is no JWT library in this
service, no signing key, and no revocation store — auth-service owns all three,
and the gateway asks it.

---

## Quick start

```bash
cp .env.example .env
# set GATEWAY_INTROSPECTION_URL to auth-service's /auth/me

make install
make dev            # http://localhost:8000/docs
```

Validation is delegated, so a running auth-service is required for anything
authenticated. Sign in through the gateway to get a token:

```bash
curl localhost:8000/api/llm/v1/models                       # 401 — no token

TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/llm/v1/models

python scripts/smoke_test.py --email you@example.com --password ...
```

---

## Secured and non-secured endpoints

**Private by default.** A routed path requires a token auth-service accepts,
unless it is listed in `GATEWAY_PUBLIC_PATHS`:

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

## How a request is authenticated

auth-service **owns identity**; the gateway asks. There is no shared secret and
no second implementation of the rules.

```
  POST /auth/login  ──►  gateway ──routes──►  auth-service   (issues the token)
  ◄──────────────── access_token ─────────────────┘

  GET /api/llm/...  ──►  gateway ──GET /auth/me──►  auth-service
                            │      "who is this?"        │
                            │   ◄── user_id, org_id, ... ─┘
                            └──routes──►  llm-gateway, identity headers attached
```

The endpoint is auth-service's own `GET /auth/me`, which already checks the
signature, the expiry **and its revocation list** — no new endpoint was needed
there. One setting points at it:

```bash
GATEWAY_INTROSPECTION_URL=https://auth-service.example.com/auth/me
```

Point it **directly** at auth-service, not back through this gateway's `/auth`
route — that would make validating a request require validating a request.

### Caching, and the revocation lag it buys

Asking on every request would put a round trip in front of all platform traffic
and make auth-service a hard dependency of every call. Answers are cached
against the token for `GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS` (default 60),
collapsing that to one call per token per TTL.

The cost is stated plainly: **a logged-out token keeps working for at most that
long.** It is the one knob to turn if you want logout to bite faster, and the
trade is linear — halve the TTL, double the calls. Set it to 0 to ask every
time.

Rejections are cached too. A 401 is monotonic — a token auth-service rejects
never becomes valid again — so caching it is safe, and it stops a client looping
on a dead token from hammering auth-service.

### Two tiers, so replicas do not multiply the load

The cache above is process-local, which on its own is only half a cache: every
replica warms its own, so with N of them auth-service sees roughly N times the
traffic the TTL was meant to buy, and a user's first request to each replica
pays a full round trip. On a serverless host, where a cold start is a fresh
process, that is most requests.

The second tier is MongoDB — one document per validated token, shared by every
replica, in `GATEWAY_IDENTITY_CACHE_COLLECTION` (default
`gateway_identity_cache`). A request checks the local dict, then the shared
store, then auth-service, populating both on the way back. It needs no TTL of
its own: it reuses the two settings above, because a second expiry for the same
answer is a bug waiting to be written.

| Property | How |
|---|---|
| Key | SHA-256 of the token. **The raw token is never written** — a collection of bearer tokens is a collection of working sessions |
| Stored | `user_id` and `account_id` (both indexed), the profile needed to rebuild the identity, or the rejection |
| Expiry | a MongoDB TTL index on `expires_at`, set to TTL **+** grace — the outer horizon, since an entry past its TTL is exactly what the grace window serves |
| Freshness | re-checked in code on every read: MongoDB's TTL monitor runs about once a minute, so a document outliving its own expiry is normal |
| Failure | every error is a cache miss. An unreachable MongoDB means "ask auth-service", which is what would have happened anyway |

Because `user_id` and `account_id` are indexed, every cached session for a user
or a whole account can be dropped in one call —
`TokenIntrospector.forget_user()` / `forget_account()` — instead of waiting out
the TTL when an administrator disables a user or moves them between accounts.
That is bounded rather than instant: it clears the shared store and the calling
replica, but a replica already holding the answer keeps serving it until its own
TTL lapses.

It is inactive without `GATEWAY_MONGO_URI`, and the gateway runs on the local
tier alone — a supported configuration, not a degraded one. `GET /v1/config`
reports `identity_cache_enabled` and `identity_cache_entries`.

### When auth-service cannot be reached

| Situation | Result |
|---|---|
| Token was validated recently | served from cache, within `GATEWAY_INTROSPECTION_STALE_GRACE_SECONDS` (default 300), with a warning logged |
| Token is unknown to this instance | **502 / 504 — the request is refused** |

Failing closed is deliberate: admitting unvalidated traffic because the
validator is down turns an outage into an open front door. Set the grace to 0
to fail closed immediately in both cases.

Note the status codes — a validation outage is reported as 502/504, never 401.
The caller's credentials were never the problem, and telling them to log in
again would be both wrong and useless.

### Logout

Nothing special happens here. Logout is a routed request to auth-service like
any other; auth-service revokes the token, and the gateway stops accepting it as
soon as the cached answer expires. There is no revocation store in this service.

## What downstream services receive

The gateway **replaces** the caller's identity headers with verified ones. This
is the security-critical part: downstream services trust `X-User-ID` and
`X-Account-ID`, so if a caller could send them, they could read any tenant's
data by typing a different value. Stripping is unconditional.

| Header | From |
|---|---|
| `X-User-ID` | the `sub` claim |
| `X-User-Email`, `X-User-Name` | token claims |
| `X-Account-ID` | the app account the token is scoped to |
| `X-Is-Admin` | `true` — and sent only when true |
| `X-Authenticated-Via` | `api-gateway` |
| `X-Request-ID` | the correlation ID |
| `Authorization` | the original bearer token, forwarded |

The token is forwarded *as well as* the decomposed claims, deliberately:
llm-gateway and knowledge-service already validate JWTs themselves and keep
doing so unchanged. `X-Forwarded-For` is **set**, not appended — the gateway is
the trust boundary, so a caller cannot forge its own origin.

**auth-service is the one exception**: it is sent `Authorization` and none of
the claim headers. It is the identity authority — it derives the caller from a
token it signed itself, and a second, weaker source of truth alongside that can
only disagree with it. It is still stripped like every other upstream, which is
the half that matters: a service that is not told who the caller is must also
not be told a lie by the caller.

Which services are exempt is `GATEWAY_IDENTITY_EXEMPT_SERVICES` (default
`auth`, naming `GATEWAY_ROUTES` entries — not path prefixes). Anything not on
that list receives the full set, so a service added to the route table is
served identity headers by default rather than silently going without them.

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

"staff" means the token's `is_admin` claim — set by auth-service, never by
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
| 502 | `auth_service_unavailable` | the token could not be validated — auth-service is down |
| 504 | `upstream_timeout` | a service did not answer in time |
| 504 | `auth_service_timeout` | auth-service did not answer in time |
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
  introspection.py       validation, delegated to auth-service (cached)
  identity_cache.py      the cross-replica tier of that cache, in MongoDB
  identity.py            the caller, as auth-service reported them
  proxy.py               forwarding + identity injection
  rate_limiter.py        sliding windows
  usage.py               request counters
  log_context.py         ambient request/user/account IDs
sdk/                     GatewayClient — session handling for callers
scripts/                 smoke_test.py
tests/                   154 tests, no network, no MongoDB
```

Middleware order is load-bearing and documented in [`app/main.py`](app/main.py):
Starlette runs middleware in **reverse** registration order, and registering the
rate limiter outside the auth middleware is a silent failure — the limiter still
runs, sees no identity yet, and quietly budgets every authenticated caller by IP.

---

## Development

```bash
make install-dev
make test           # 154 tests
make lint
make docker-up
```

The suite never touches a network or a MongoDB: auth-service and the upstreams
are httpx `MockTransport` handlers injected through the `client=` arguments
`TokenIntrospector` and `ProxyClient` already expose, so the real code paths —
header building, error translation, streaming, caching, connection release — are
the ones under test.

Tokens in the suite are **opaque strings**, because that is what they are to the
gateway. There is no JWT minting: a test that needs an invalid token uses a
string the fake auth-service rejects.

---

## Deployment notes

- **Set `GATEWAY_INTROSPECTION_URL`.** Without it nothing can be validated and
  every authenticated request fails with 502. The gateway logs an error at
  startup when it is empty.
- **auth-service is now on the critical path.** Every authenticated request
  needs it (modulo the cache), so its availability is the platform's
  availability. Size the TTL and stale grace accordingly.
- **Set `GATEWAY_MONGO_URI` for more than one replica** if you want usage
  counters merged across instances. Revocation no longer depends on it.
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
export GATEWAY_INTROSPECTION_URL=/auth/me   # becomes C:/Program Files/Git/auth/me
```

silently mangles any setting whose value starts with `/` — `GATEWAY_PUBLIC_PATHS`
entries without a `METHOD:` prefix included. It fails quietly: the gateway
starts, routes fine, and simply never matches the path. Set these in `.env`
(which is read directly and unaffected), or export `MSYS_NO_PATHCONV=1` first.

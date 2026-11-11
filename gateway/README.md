# APIShield Gateway (M1: Gateway and Protection)

An async reverse proxy that sits in front of any HTTP/JSON API and protects it.

```
Client --> [ APIShield Gateway ] --> Upstream API
             request pipeline:   normalize > auth > rate limit > validate > rules
             response pipeline:  secret-leak + error-leak inspection
             every request:      one traffic event --> Redis Stream (non-blocking)
```

## Run it

All commands are run from the **repo root**. Python 3.10 or newer.

```bash
pip install -r gateway/requirements.txt

# 1. the API being protected (the vulnerable demo API)
uvicorn demo_api.main:app --port 8001

# 2. Redis (rate limits + event stream). Without it the gateway still starts and
#    falls back to in-memory limits and events, with a warning.
docker run --rm -p 6379:6379 redis:7

# 3. the gateway, on port 8080
APISHIELD_ADMIN_TOKEN=demo-admin python -m gateway.apishield_gateway
```

Then send traffic to `http://localhost:8080` instead of `:8001`.

```bash
curl localhost:8080/_apishield/health
curl "localhost:8080/search?q=%27%20OR%20%271%27%3D%271"      # 403, SQL injection blocked
curl localhost:8080/admin/stats                                # 401, spec says auth is required
curl localhost:8080/debug                                      # stack trace masked
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8080/login \
  -H 'content-type: application/json' -d '{"username":"alice","password":"guess"}'; done   # 6th is 429
```

Tests: `pytest gateway/tests` (116 tests, no Redis or network needed).

## What each stage does

| Order | Stage | File | Behaviour |
|---|---|---|---|
| 1 | Normalize | `normalize.py` | Decodes the path and query (including double encoding), collapses `//` and `..`, matches the route to its OpenAPI `path_template`, computes `shape_hash` (field names and types, never values). |
| 2 | Auth | `auth.py` | API key lookup (`X-API-Key`, stored as SHA-256). JWT verification: rejects `alg=none`, expired, bad signature, wrong issuer or audience. Routes the spec marks as protected get `401` without credentials. |
| 3 | Rate limit | `ratelimit.py` | Redis token bucket (atomic Lua script) per caller, per IP, or per caller + endpoint. Returns `429` with `Retry-After`. |
| 4 | Validate | `validation.py` | Path, query and JSON body against the OpenAPI schema: types, required fields, content type (`415`), max body size (`413`). Error messages name the field, never the value. |
| 5 | Rules | `rules.py` | YAML/JSON rules, signature and condition based. Hot reload. |
| resp | Inspector | `inspector.py` | Finds API keys, JWTs, private keys, stack traces and SQL errors in responses, then masks them or only alerts. |
| always | Event emitter | `events.py` | One event per request onto a bounded queue; a background task writes batches to Redis. A slow or dead Redis drops events, it never slows requests. |

Gateway-generated errors all look like
`{"error": {"code": "...", "message": "..."}, "request_id": "..."}`.
Every response carries `X-Request-ID` (the same ID is sent upstream and written to the
event) and `Server-Timing: apishield;dur=<gateway ms>, upstream;dur=<upstream ms>`.

## Configuration

`gateway/gateway.yaml` holds the structure (limits, API keys, inspector settings).
Environment variables override it:

| Variable | Meaning |
|---|---|
| `APISHIELD_UPSTREAM_URL` | API to protect, e.g. `http://demo-api:8001` |
| `APISHIELD_REDIS_URL` | e.g. `redis://redis:6379/0`. Empty = in-memory fallback |
| `APISHIELD_MODE` | `enforce` (block) or `monitor` (log only) |
| `APISHIELD_ADMIN_TOKEN` | Enables the control endpoints below |
| `APISHIELD_JWT_SECRET`, `APISHIELD_JWT_ISSUER`, `APISHIELD_JWT_AUDIENCE` | JWT verification |
| `APISHIELD_API_KEYS` | `name:key,name2:key2` |
| `APISHIELD_OPENAPI_SPEC`, `APISHIELD_RULES_DIR` | Paths. With no spec the gateway fetches `<upstream>/openapi.json` |
| `APISHIELD_FAIL_OPEN` | `true`: if a check itself crashes, let traffic through and record it |
| `APISHIELD_HOST`, `APISHIELD_PORT`, `APISHIELD_CONFIG` | Listen address, config file path |

`gateway.yaml` ships with demo_api's hardcoded JWT secret (`dev-secret`) so the demo
works out of the box. It is not a real secret; set `APISHIELD_JWT_SECRET` anywhere else.

## Rules

Files in `gateway/rules/` (`.yaml`, `.yml`, `.json`) are loaded at start and re-read
within about 2 seconds of any change. A file that fails to parse keeps its last good
rules; a single bad rule is skipped and reported in `/_apishield/health`.

```yaml
- id: block-sqli-on-search          # required
  name: SQL injection on /search    # shown in the dashboard
  enabled: true
  match:                            # every field given must hold
    path: /search                   # exact, /users/{id}, or /admin/*
    method: GET                     # or [GET, POST]
    ip: [203.0.113.0/24]
    header: {user-agent: "curl"}    # header name -> regex
    signature: sqli                 # sqli | nosqli | xss | path_traversal | bad_user_agent | regex:<pattern>
    condition: "req_size > 10000 and not authenticated"
  action: block                     # allow | log | block | throttle | challenge
  source: scanner                   # builtin | scanner | analyst | learner
  expires_at: 2026-12-01T00:00:00Z  # optional
  priority: 100                     # optional, lower runs first
  throttle: {limit: 5, per: 60}     # only for action: throttle
```

| Action | Effect |
|---|---|
| `allow` | Allow-list entry: stop evaluating further rules |
| `log` | Record the hit, keep going |
| `block` | `403` |
| `throttle` | Token bucket per caller for this rule; `429` + `Retry-After` when exceeded |
| `challenge` | Caller must be authenticated, otherwise `401`. `require_auth` is accepted as an alias |

Conditions are a small expression language parsed with `ast`, never `eval`. Names:
`method, path, path_template, ip, caller, authenticated, req_size, content_type,
user_agent, query, header, body, claims, payload`. Functions: `len, contains, matches,
startswith, endswith, lower`.

## Control endpoints

For the Admin API and the scanner, not for API clients. All except `health` need the
header `X-APIShield-Admin-Token` and return `404` until `APISHIELD_ADMIN_TOKEN` is set.

| Endpoint | Purpose |
|---|---|
| `GET /_apishield/health` | Mode, Redis status, rule count, rule load errors, dropped events |
| `GET /_apishield/rules` | Active rules with hit counts since start |
| `POST /_apishield/rules` | Add or replace rules by id (one rule, a list, or `{"rules": [...]}`). Saved to `rules/dynamic.json` |
| `DELETE /_apishield/rules/{id}` | Remove a runtime rule |
| `POST /_apishield/reload` | Re-read the rules folder now |
| `PUT /_apishield/mode` | `{"mode": "monitor"}` or `{"mode": "enforce"}` |

Demo flow: start in `monitor` (attacks pass but are recorded), run the scan, push the
suggested rules, switch to `enforce`, and the same attacks are blocked.

## Contracts with the other parts

**Traffic event (to M3 and M4).** Stream `apishield:traffic`, one entry per request,
one field `data` holding this JSON (exactly the plan's shape):

```json
{"ts":"2026-11-11T11:51:23.623Z","req_id":"fc73...","caller":"ip_127.0.0.1","ip":"127.0.0.1",
 "method":"GET","path_template":"/search","status":403,"latency_ms":2.17,"req_size":0,
 "resp_size":131,"shape_hash":"ff417be79483e4e3","rule_hits":["builtin-sqli"],"action":"block"}
```

- Read it with `XREAD` / `XREADGROUP`, then `json.loads(fields["data"])`.
- `caller` is `key_<8 hex>` (hash of the API key), `user_<sub>` (JWT subject) or `ip_<address>`.
- `action` is the strongest thing that happened: `allow < log < throttle < challenge < block`.
- `rule_hits` holds rule ids plus built-in check names: `auth.*`, `ratelimit.<limit id>`,
  `validation.*`, `resp.secret.*`, `resp.error.*`, `gateway.*`.
- The stream is capped at about 100,000 entries.

**Rules (from M2, M4 and M3).** Either drop a file into `gateway/rules/` or
`POST /_apishield/rules`. The scanner's current draft
(`{"id", "match": {"path", "method"}, "action": "require_auth", "source": "scanner"}`)
already loads as-is.

**Answers to `frontend/CONTRACT_QUESTIONS.md`, items 6 to 10 (M1's proposal):**

6. The gateway does not serve `/metrics/summary`. It emits raw events; `requests`,
   `blocked`, `allowed`, `p95_latency_ms`, `top_endpoints` and `top_callers` are
   aggregations over the stream for the Admin API. Count `blocked` as
   `action in (block, throttle, challenge)`.
7. Same source: bucket the events by `ts`.
8. The gateway does not serve SSE. Events arrive one at a time on the Redis stream;
   the Admin API relays them.
9. One field. `Rule.action` covers it (`log` vs `block`). The global
   monitor / enforce switch is separate (`PUT /_apishield/mode`).
10. The gateway only needs the fields shown under Rules and ignores the rest, so
    `created_at` / `created_by` can live in the Admin API's database.

## Not in v1

- Swagger 2.0 specs (OpenAPI 3.x only), XML and form-body schema validation.
- `hits` is counted since the gateway started; `hits_24h` should come from the event stream.
- The `ip` field in events is the raw address. Masking for display is left to the Admin API.
